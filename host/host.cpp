#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <cstdlib>

#include <openenclave/host.h>

#include "../enclave/prog_mpc.h"
#include "config.hpp"
#include "control_protocol.hpp"
#include "network.hpp"
#include "noise_u.h"

namespace
{
void check_oe(oe_result_t result, const char* message)
{
    if (result != OE_OK)
    {
        throw std::runtime_error(std::string(message) + ": " + oe_result_str(result));
    }
}

void check_status(int status, const char* message)
{
    if (status != noise::kOk)
    {
        throw std::runtime_error(std::string(message) + ": protocol status=" + std::to_string(status));
    }
}

uint64_t batch_round_from_subround(uint64_t subround_id)
{
    return subround_id >> 32U;
}

uint64_t batch_index_from_subround(uint64_t subround_id)
{
    return (subround_id & 0xffffffffULL) - 1ULL;
}

class PartyNode
{
public:
    PartyNode(
        std::string enclave_path,
        uint64_t party_id,
        uint64_t party_count,
        uint64_t threshold,
        uint16_t listen_port,
        std::vector<host::Endpoint> peers)
        : enclave_path_(std::move(enclave_path)),
          party_id_(party_id),
          party_count_(party_count),
          threshold_(threshold),
          listen_port_(listen_port),
          peers_(std::move(peers))
    {
    }

    ~PartyNode()
    {
        stop();
    }

    void initialize()
    {
        uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

        const char* sim = std::getenv("OE_SIMULATION");
        if (sim && std::string(sim) == "1")
        {
            flags |= OE_ENCLAVE_FLAG_SIMULATE;
        }

        check_oe(
            oe_create_noise_enclave(
                enclave_path_.c_str(),
                OE_ENCLAVE_TYPE_SGX,
                flags,
                nullptr,
                0,
                &enclave_),
            "oe_create_noise_enclave failed");

        int status = noise::kOk;
        check_oe(
            ecall_init_party(enclave_, &status, party_id_, party_count_, threshold_),
            "ecall_init_party transport failed");
        check_status(status, "ecall_init_party rejected");

        listen_fd_ = host::create_listen_socket(listen_port_);
        log("listening on port " + std::to_string(listen_port_));
    }

    void serve_forever()
    {
        while (true)
        {
            const int client_fd = host::accept_client(listen_fd_);
            std::thread([this, client_fd]() {
                try
                {
                    handle_client(client_fd);
                }
                catch (const std::exception& ex)
                {
                    log(std::string("client handling failed: ") + ex.what());
                }

                host::close_socket(client_fd);
            }).detach();
        }
    }

private:
    struct RoundState
    {
        uint64_t batch_round_id = 0;
        uint64_t batch_size = 0;
        std::string state = "IDLE";
        uint64_t completed_items = 0;
        uint64_t current_item = 0;
        uint64_t current_chunk_start = 0;
        uint64_t current_chunk_size = 0;
        std::vector<uint64_t> current_chunk_round_ids;
        std::vector<uint64_t> current_chunk_received_counts;
        std::vector<uint64_t> current_chunk_ack_counts;
        bool current_chunk_done = false;
        std::vector<uint64_t> local_secrets;
        std::vector<noise::SharePoint> aggregates;
    };

    struct GeneratedChunk
    {
        std::vector<uint64_t> round_ids;
        std::vector<noise::SharePackage> packages;
        std::vector<uint64_t> local_secrets;
    };

    std::string enclave_path_;
    uint64_t party_id_;
    uint64_t party_count_;
    uint64_t threshold_;
    uint16_t listen_port_;
    std::vector<host::Endpoint> peers_;
    oe_enclave_t* enclave_ = nullptr;
    int listen_fd_ = -1;

    std::mutex mutex_;
    std::condition_variable round_cv_;
    std::mutex output_mutex_;
    RoundState round_;
    std::array<std::array<bool, noise::kMaxParties>, noise::kMaxParallelBatch> chunk_received_from_{};
    std::array<std::array<bool, noise::kMaxParties>, noise::kMaxParallelBatch> chunk_acked_by_{};

    void stop()
    {
        if (enclave_ != nullptr)
        {
            oe_terminate_enclave(enclave_);
            enclave_ = nullptr;
        }

        if (listen_fd_ >= 0)
        {
            host::close_socket(listen_fd_);
            listen_fd_ = -1;
        }
    }

    void handle_client(int client_fd)
    {
        const std::string request = host::recv_line(client_fd);
        if (request.empty())
        {
            host::send_line(client_fd, "ERR empty request");
            return;
        }

        uint64_t round_id = 0;
        uint64_t batch_size = 0;
        host::BatchShareMessage batch_share;

        if (host::parse_start_message(request, &round_id, &batch_size))
        {
            start_round(round_id, batch_size);
            host::send_line(client_fd, "OK STARTED " + std::to_string(round_id) + " " + std::to_string(batch_size));
            return;
        }

        if (host::parse_batch_share_message(request, &batch_share))
        {
            const host::BatchAckMessage batch_ack = handle_batch_share_request(batch_share);
            host::send_line(client_fd, host::build_batch_ack_message(batch_ack));
            return;
        }

        if (host::is_status_request(request))
        {
            host::send_line(client_fd, host::build_status_response(snapshot()));
            return;
        }

        host::send_line(client_fd, "ERR unknown request");
    }

    void start_round(uint64_t round_id, uint64_t batch_size)
    {
        bool should_launch = false;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            prepare_batch_locked(round_id, batch_size);
            if (round_.state == "WAITING")
            {
                round_.state = "RUNNING";
                should_launch = true;
            }
        }

        if (should_launch)
        {
            std::thread([this, round_id, batch_size]() {
                try
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                    run_batch(round_id, batch_size);
                }
                catch (const std::exception& ex)
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (round_.batch_round_id == round_id)
                    {
                        round_.state = "ERROR";
                    }
                    round_cv_.notify_all();
                    log(std::string("batch ") + std::to_string(round_id) + ": failed: " + ex.what());
                }
            }).detach();
        }
    }

    void run_batch(uint64_t round_id, uint64_t batch_size)
    {
        log("batch " + std::to_string(round_id) + ": started with batch_size = " + std::to_string(batch_size));

        for (uint64_t chunk_start = 0; chunk_start < batch_size; chunk_start += noise::kMaxParallelBatch)
        {
            const uint64_t chunk_size = std::min<uint64_t>(noise::kMaxParallelBatch, batch_size - chunk_start);
            GeneratedChunk chunk = generate_chunk(round_id, chunk_start, chunk_size);
            send_chunk(chunk_start, chunk);
            wait_for_chunk(round_id, chunk_start);
            finalize_chunk(round_id, chunk_start);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (round_.batch_round_id == round_id && round_.completed_items == round_.batch_size)
            {
                round_.state = "DONE";
            }
        }
        round_cv_.notify_all();
        log("batch " + std::to_string(round_id) + ": all items completed");
    }

    GeneratedChunk generate_chunk(uint64_t round_id, uint64_t chunk_start, uint64_t chunk_size)
    {
        GeneratedChunk chunk;
        chunk.round_ids.resize(chunk_size);
        for (uint64_t offset = 0; offset < chunk_size; ++offset)
        {
            chunk.round_ids[offset] = host::make_subround_id(round_id, chunk_start + offset);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            prepare_chunk_locked(chunk_start, chunk.round_ids);
        }

        chunk.packages.resize(static_cast<size_t>(chunk_size * party_count_));
        chunk.local_secrets.assign(chunk_size, 0);

        int status = noise::kOk;
        check_oe(
            ecall_sharegen_batch(
                enclave_,
                &status,
                chunk.round_ids.data(),
                chunk.round_ids.size(),
                reinterpret_cast<share_package_t*>(chunk.packages.data()),
                chunk.packages.size(),
                chunk.local_secrets.data()),
            "ecall_sharegen_batch transport failed");
        check_status(status, "ecall_sharegen_batch rejected");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (uint64_t offset = 0; offset < chunk_size; ++offset)
            {
                round_.local_secrets[chunk_start + offset] = chunk.local_secrets[offset];
            }
            round_.current_item = chunk_start;
        }

        log("batch " + std::to_string(round_id) + ": enclave generated chunk start=" + std::to_string(chunk_start) + " size=" + std::to_string(chunk_size));
        return chunk;
    }

    void send_chunk(uint64_t chunk_start, const GeneratedChunk& chunk)
    {
        const uint64_t chunk_size = chunk.round_ids.size();

        for (uint64_t receiver = 1; receiver <= party_count_; ++receiver)
        {
            host::BatchShareMessage message;
            message.packages.reserve(chunk_size);

            for (uint64_t offset = 0; offset < chunk_size; ++offset)
            {
                message.packages.push_back(chunk.packages[offset * party_count_ + (receiver - 1)]);
            }

            if (receiver == party_id_)
            {
                log("chunk " + std::to_string(chunk_start) + ": storing self batch");
                const host::BatchAckMessage ack = process_batch_share_packages(message.packages);
                apply_batch_ack(ack, chunk_start);
                continue;
            }

            log("chunk " + std::to_string(chunk_start) + ": sending batch shares to party " + std::to_string(receiver));
            const std::string reply = host::request_reply(peers_[receiver - 1], host::build_batch_share_message(message));
            host::BatchAckMessage ack;
            if (!host::parse_batch_ack_message(reply, &ack))
            {
                throw std::runtime_error("Invalid batch ack reply: " + reply);
            }
            apply_batch_ack(ack, chunk_start);
        }
    }

    host::BatchAckMessage handle_batch_share_request(const host::BatchShareMessage& message)
    {
        if (message.packages.empty())
        {
            throw std::runtime_error("Received empty batch share message");
        }

        const uint64_t batch_round_id = batch_round_from_subround(message.packages.front().round_id);
        const uint64_t chunk_start = batch_index_from_subround(message.packages.front().round_id);
        std::vector<uint64_t> round_ids;
        round_ids.reserve(message.packages.size());
        for (const auto& share : message.packages)
        {
            if (batch_round_from_subround(share.round_id) != batch_round_id)
            {
                throw std::runtime_error("Mixed batch rounds in one batch share message");
            }
            round_ids.push_back(share.round_id);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (round_.batch_round_id != batch_round_id)
            {
                throw std::runtime_error("Received batch share for unexpected batch round");
            }
            prepare_chunk_locked(chunk_start, round_ids);
        }

        return process_batch_share_packages(message.packages);
    }

    host::BatchAckMessage process_batch_share_packages(const std::vector<noise::SharePackage>& packages)
    {
        host::BatchAckMessage message;
        message.acks.resize(packages.size());
        int status = noise::kOk;

        std::vector<noise::SharePackage> mutable_packages = packages;
        check_oe(
            ecall_store_batch(
                enclave_,
                &status,
                reinterpret_cast<share_package_t*>(mutable_packages.data()),
                mutable_packages.size(),
                reinterpret_cast<ack_message_t*>(message.acks.data())),
            "ecall_store_batch transport failed");
        check_status(status, "ecall_store_batch rejected");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (size_t offset = 0; offset < packages.size(); ++offset)
            {
                const uint64_t sender = packages[offset].sender_id;
                if (!chunk_received_from_[offset][sender - 1])
                {
                    chunk_received_from_[offset][sender - 1] = true;
                    round_.current_chunk_received_counts[offset] += 1;
                    log("subround " + std::to_string(packages[offset].round_id) + ": stored share from party " + std::to_string(sender));
                }
            }
        }

        round_cv_.notify_all();
        return message;
    }

    void apply_batch_ack(const host::BatchAckMessage& message, uint64_t chunk_start)
    {
        if (message.acks.empty())
        {
            throw std::runtime_error("Received empty batch ack");
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (round_.current_chunk_start != chunk_start || round_.current_chunk_size != message.acks.size())
        {
            throw std::runtime_error("Batch ack does not match current chunk");
        }

        for (size_t offset = 0; offset < message.acks.size(); ++offset)
        {
            const auto& ack = message.acks[offset];
            if (!noise::ProgMPCHandler::verify_ack(ack))
            {
                throw std::runtime_error("Invalid batch ack signature");
            }

            if (!chunk_acked_by_[offset][ack.acking_party - 1])
            {
                chunk_acked_by_[offset][ack.acking_party - 1] = true;
                round_.current_chunk_ack_counts[offset] += 1;
            }
        }
    }

    void wait_for_chunk(uint64_t round_id, uint64_t chunk_start)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        round_cv_.wait(lock, [this, round_id, chunk_start]() {
            return round_.state == "ERROR" ||
                   round_.batch_round_id != round_id ||
                   (round_.current_chunk_start == chunk_start && all_chunk_received_locked());
        });

        if (round_.state == "ERROR")
        {
            throw std::runtime_error("Batch entered ERROR state");
        }
    }

    void finalize_chunk(uint64_t round_id, uint64_t chunk_start)
    {
        std::vector<noise::SharePoint> aggregates(round_.current_chunk_size);
        int status = noise::kOk;
        check_oe(
            ecall_done_batch(
                enclave_,
                &status,
                reinterpret_cast<share_point_t*>(aggregates.data()),
                aggregates.size()),
            "ecall_done_batch transport failed");
        check_status(status, "ecall_done_batch rejected");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (round_.batch_round_id != round_id || round_.current_chunk_start != chunk_start)
            {
                throw std::runtime_error("Chunk state changed before finalize");
            }

            for (size_t offset = 0; offset < aggregates.size(); ++offset)
            {
                round_.aggregates[chunk_start + offset] = aggregates[offset];
            }

            round_.completed_items += aggregates.size();
            round_.current_item = chunk_start + aggregates.size() - 1;
            round_.current_chunk_done = true;
        }

        round_cv_.notify_all();
        log("chunk " + std::to_string(chunk_start) + ": aggregated " + std::to_string(aggregates.size()) + " noises");
    }

    host::StatusSnapshot snapshot()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        host::StatusSnapshot status;
        status.party_id = party_id_;
        status.round_id = round_.batch_round_id;
        status.batch_size = round_.batch_size;
        status.state = round_.state;
        status.current_item = round_.current_item;
        status.completed_items = round_.completed_items;
        status.received_shares = round_.current_chunk_received_counts.empty() ? 0 : round_.current_chunk_received_counts.front();
        status.ack_count = round_.current_chunk_ack_counts.empty() ? 0 : round_.current_chunk_ack_counts.front();
        status.expected_shares = party_count_;
        status.success = (round_.batch_size != 0 && round_.completed_items == round_.batch_size) ? 1 : 0;
        status.local_secrets = round_.local_secrets;
        status.aggregates = round_.aggregates;
        return status;
    }

    void prepare_batch_locked(uint64_t round_id, uint64_t batch_size)
    {
        if (batch_size == 0)
        {
            throw std::runtime_error("batch_size must be positive");
        }

        if (round_.batch_round_id == round_id)
        {
            return;
        }

        round_ = RoundState{};
        round_.batch_round_id = round_id;
        round_.batch_size = batch_size;
        round_.state = "WAITING";
        round_.local_secrets.assign(batch_size, 0);
        round_.aggregates.assign(batch_size, noise::SharePoint{});
        clear_chunk_tracking_locked();
    }

    void prepare_chunk_locked(uint64_t chunk_start, const std::vector<uint64_t>& round_ids)
    {
        if (round_.current_chunk_start == chunk_start &&
            round_.current_chunk_size == round_ids.size() &&
            round_.current_chunk_round_ids == round_ids)
        {
            return;
        }

        round_.current_chunk_start = chunk_start;
        round_.current_chunk_size = round_ids.size();
        round_.current_chunk_round_ids = round_ids;
        round_.current_chunk_received_counts.assign(round_ids.size(), 0);
        round_.current_chunk_ack_counts.assign(round_ids.size(), 0);
        round_.current_chunk_done = false;

        for (size_t i = 0; i < noise::kMaxParallelBatch; ++i)
        {
            chunk_received_from_[i].fill(false);
            chunk_acked_by_[i].fill(false);
        }
    }

    void clear_chunk_tracking_locked()
    {
        round_.current_chunk_start = 0;
        round_.current_chunk_size = 0;
        round_.current_chunk_round_ids.clear();
        round_.current_chunk_received_counts.clear();
        round_.current_chunk_ack_counts.clear();
        round_.current_chunk_done = false;
        for (size_t i = 0; i < noise::kMaxParallelBatch; ++i)
        {
            chunk_received_from_[i].fill(false);
            chunk_acked_by_[i].fill(false);
        }
    }

    bool all_chunk_received_locked() const
    {
        if (round_.current_chunk_received_counts.empty())
        {
            return false;
        }

        return std::all_of(
            round_.current_chunk_received_counts.begin(),
            round_.current_chunk_received_counts.end(),
            [this](uint64_t count) { return count == party_count_; });
    }

    void log(const std::string& message)
    {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        std::lock_guard<std::mutex> lock(output_mutex_);
        std::cout << "[" << ms << "][party " << party_id_ << "] " << message << std::endl;
    }
};
} // namespace

int main(int argc, const char* argv[])
{
    if (argc < 4)
    {
        std::cerr << "Usage: noise_party <enclave_path> <config_path> <party_name>" << std::endl;
        return 1;
    }

    try
    {
        const std::string enclave_path = argv[1];
        const std::string config_path = argv[2];
        const std::string party_name = argv[3];
        const auto config = host::load_runtime_config(config_path);
        const auto& self = host::find_party_config(config, party_name);
        const auto peers = host::endpoints_from_config(config);

        PartyNode party(
            enclave_path,
            self.id,
            config.party_count,
            config.threshold,
            self.endpoint.port,
            peers);
        party.initialize();
        party.serve_forever();
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}
