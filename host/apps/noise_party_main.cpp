#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <cstdlib>

#include <grpcpp/grpcpp.h>
#include <openenclave/host.h>

#include "../../algebra/sharing/open.hpp"
#include "../../enclave/common/noise_types.h"
#include "../config/config.hpp"
#include "../dkg/encryption.hpp"
#include "../dkg/planner.hpp"
#include "../dkg/preprocessing_store.hpp"
#include "../dkg/serialization.hpp"
#include "../protocol/control_protocol.hpp"
#include "../protocol/grpc_utils.hpp"
#include "noise_u.h"

namespace
{
constexpr int kGrpcMessageLimitBytes = 512 * 1024 * 1024;

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

enum class ProtocolMode
{
    kNoise,
    kTriple,
    kBit,
};

const char* mode_batch_label(ProtocolMode mode)
{
    switch (mode)
    {
    case ProtocolMode::kNoise:
        return "batch";
    case ProtocolMode::kTriple:
        return "triple batch";
    case ProtocolMode::kBit:
        return "bit batch";
    }
    return "batch";
}

class PartyNode
{
public:
    PartyNode(
        std::string enclave_path,
        host::RuntimeConfig config,
        uint64_t party_id,
        uint64_t party_count,
        uint64_t threshold,
        uint32_t noise_bound_bits,
        uint16_t listen_port,
        std::vector<host::Endpoint> peers)
        : enclave_path_(std::move(enclave_path)),
          config_(std::move(config)),
          party_id_(party_id),
          party_count_(party_count),
          threshold_(threshold),
          noise_bound_bits_(noise_bound_bits),
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
            ecall_init_party(enclave_, &status, party_id_, party_count_, threshold_, noise_bound_bits_),
            "ecall_init_party transport failed");
        check_status(status, "ecall_init_party rejected");
        init_channels();
        log("grpc listening on port " + std::to_string(listen_port_));
    }

    void StartRound(uint64_t round_id, uint64_t batch_size, uint32_t noise_bound_bits_override = 0)
    {
        start_round(round_id, batch_size, noise_bound_bits_override);
    }

    void StartTripleRound(uint64_t round_id, uint64_t batch_size)
    {
        start_triple_round(round_id, batch_size);
    }

    void StartBitRound(uint64_t round_id, uint64_t batch_size)
    {
        start_bit_round(round_id, batch_size);
    }

    void StartKeygen(uint64_t round_id, const std::string& session_id, const std::string& preproc_root, const std::string& output_dir)
    {
        start_keygen(round_id, session_id, preproc_root, output_dir);
    }

    host::BatchAckMessage HandleBatchSharePackages(const std::vector<noise::SharePackage>& packages)
    {
        return handle_batch_share_packages(packages);
    }

    void HandleBatchTripleDPackages(const std::vector<noise::TripleDPackage>& packages)
    {
        handle_batch_triple_d_packages(packages);
    }

    void HandleBatchBitVPackages(const std::vector<noise::BitVPackage>& packages)
    {
        handle_batch_bit_v_packages(packages);
    }

    void HandleBatchKeygenOpenPackages(const std::vector<noise_rpc::KeygenOpenSharePackage>& packages)
    {
        handle_batch_keygen_open_packages(packages);
    }

    host::StatusSnapshot GetStatus() { return snapshot(); }

private:
    struct RoundState
    {
        uint64_t batch_round_id = 0;
        uint64_t batch_size = 0;
        uint32_t noise_bound_bits = 0;
        std::string state = "IDLE";
        uint64_t completed_items = 0;
        uint64_t current_item = 0;
        uint64_t current_chunk_start = 0;
        uint64_t current_chunk_size = 0;
        std::vector<uint64_t> current_chunk_round_ids;
        std::vector<uint64_t> current_chunk_received_counts;
        std::vector<uint64_t> current_chunk_ack_counts;
        bool current_chunk_done = false;
        std::vector<noise::RingElementRaw> local_secrets;
        std::vector<noise::SharePoint> aggregates;
    };

    struct GeneratedChunk
    {
        std::vector<uint64_t> round_ids;
        std::vector<noise::SharePackage> packages;
        std::vector<noise::RingElementRaw> local_secrets;
    };

    struct TripleRoundState
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
        bool current_chunk_done = false;
        std::vector<noise::TripleShare> triples;
    };

    struct GeneratedTripleChunk
    {
        std::vector<uint64_t> round_ids;
        std::vector<noise::TripleDPackage> packages;
    };

    struct BitRoundState
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
        bool current_chunk_done = false;
        std::vector<noise::BitShare> bits;
    };

    struct GeneratedBitChunk
    {
        std::vector<uint64_t> round_ids;
        std::vector<noise::BitVPackage> packages;
    };

    struct KeygenState
    {
        uint64_t round_id = 0;
        std::string session_id;
        std::string preproc_root;
        std::string output_dir;
        std::string state = "IDLE";
        uint64_t completed_items = 0;
        uint64_t batch_size = 1;
        std::string summary_path;
    };

    std::string enclave_path_;
    host::RuntimeConfig config_;
    uint64_t party_id_;
    uint64_t party_count_;
    uint64_t threshold_;
    uint32_t noise_bound_bits_;
    uint16_t listen_port_;
    std::vector<host::Endpoint> peers_;
    std::vector<std::unique_ptr<noise_rpc::NoiseParty::Stub>> stubs_;
    oe_enclave_t* enclave_ = nullptr;

    std::mutex mutex_;
    std::condition_variable round_cv_;
    std::mutex output_mutex_;
    std::mutex enclave_mutex_;
    RoundState round_;
    TripleRoundState triple_round_;
    BitRoundState bit_round_;
    KeygenState keygen_;
    std::array<std::array<bool, noise::kMaxParties>, noise::kMaxParallelBatch> chunk_received_from_{};
    std::array<std::array<bool, noise::kMaxParties>, noise::kMaxParallelBatch> chunk_acked_by_{};
    std::array<std::array<bool, noise::kMaxParties>, noise::kMaxParallelBatch> triple_received_from_{};
    std::array<std::array<bool, noise::kMaxParties>, noise::kMaxParallelBatch> bit_received_from_{};
    std::map<uint64_t, std::vector<algebra::RingShare>> keygen_open_shares_;

    void stop()
    {
        if (enclave_ != nullptr)
        {
            oe_terminate_enclave(enclave_);
            enclave_ = nullptr;
        }
    }

    void init_channels()
    {
        stubs_.clear();
        stubs_.reserve(peers_.size());
        for (const auto& peer : peers_)
        {
            const std::string target = host::endpoint_to_target(peer);
            auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
            stubs_.push_back(noise_rpc::NoiseParty::NewStub(channel));
        }
    }

    void start_round(uint64_t round_id, uint64_t batch_size, uint32_t noise_bound_bits_override)
    {
        bool should_launch = false;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            prepare_batch_locked(round_id, batch_size, noise_bound_bits_override);
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

    void start_triple_round(uint64_t round_id, uint64_t batch_size)
    {
        bool should_launch = false;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            prepare_triple_batch_locked(round_id, batch_size);
            if (triple_round_.state == "WAITING")
            {
                triple_round_.state = "TRIPLE_RUNNING";
                should_launch = true;
            }
        }

        if (should_launch)
        {
            std::thread([this, round_id, batch_size]() {
                try
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                    run_triple_batch(round_id, batch_size);
                }
                catch (const std::exception& ex)
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (triple_round_.batch_round_id == round_id)
                    {
                        triple_round_.state = "ERROR";
                    }
                    round_cv_.notify_all();
                    log(std::string("triple batch ") + std::to_string(round_id) + ": failed: " + ex.what());
                }
            }).detach();
        }
    }

    void start_bit_round(uint64_t round_id, uint64_t batch_size)
    {
        bool should_launch = false;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            prepare_bit_batch_locked(round_id, batch_size);
            if (bit_round_.state == "WAITING")
            {
                bit_round_.state = "BIT_RUNNING";
                should_launch = true;
            }
        }

        if (should_launch)
        {
            std::thread([this, round_id, batch_size]() {
                try
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                    run_bit_batch(round_id, batch_size);
                }
                catch (const std::exception& ex)
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (bit_round_.batch_round_id == round_id)
                    {
                        bit_round_.state = "ERROR";
                    }
                    round_cv_.notify_all();
                    log(std::string("bit batch ") + std::to_string(round_id) + ": failed: " + ex.what());
                }
            }).detach();
        }
    }

    void run_batch(uint64_t round_id, uint64_t batch_size)
    {
        log("batch " + std::to_string(round_id) + ": started with batch_size = " + std::to_string(batch_size));

        for (uint64_t chunk_start = 0; chunk_start < batch_size; chunk_start += noise::kMaxParallelBatch)
        {
            wait_for_peers_ready(round_id, chunk_start);
            const uint64_t chunk_size = std::min<uint64_t>(noise::kMaxParallelBatch, batch_size - chunk_start);
            GeneratedChunk chunk = generate_chunk(round_id, chunk_start, chunk_size);
            wait_for_peers_generated(round_id, chunk_start, chunk_size);
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

    void run_triple_batch(uint64_t round_id, uint64_t batch_size)
    {
        log("triple batch " + std::to_string(round_id) + ": started with batch_size = " + std::to_string(batch_size));

        for (uint64_t chunk_start = 0; chunk_start < batch_size; chunk_start += noise::kMaxParallelBatch)
        {
            wait_for_triple_peers_ready(round_id, chunk_start);
            const uint64_t chunk_size = std::min<uint64_t>(noise::kMaxParallelBatch, batch_size - chunk_start);
            GeneratedTripleChunk chunk = generate_triple_chunk(round_id, chunk_start, chunk_size);
            wait_for_triple_peers_generated(round_id, chunk_start, chunk_size);
            send_triple_chunk(chunk);
            wait_for_triple_chunk(round_id, chunk_start);
            finalize_triple_chunk(round_id, chunk_start);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (triple_round_.batch_round_id == round_id && triple_round_.completed_items == triple_round_.batch_size)
            {
                triple_round_.state = "TRIPLE_DONE";
            }
        }
        round_cv_.notify_all();
        log("triple batch " + std::to_string(round_id) + ": all items completed");
    }

    void run_bit_batch(uint64_t round_id, uint64_t batch_size)
    {
        log("bit batch " + std::to_string(round_id) + ": started with batch_size = " + std::to_string(batch_size));

        for (uint64_t chunk_start = 0; chunk_start < batch_size; chunk_start += noise::kMaxParallelBatch)
        {
            wait_for_bit_peers_ready(round_id, chunk_start);
            const uint64_t chunk_size = std::min<uint64_t>(noise::kMaxParallelBatch, batch_size - chunk_start);
            GeneratedBitChunk chunk = generate_bit_chunk(round_id, chunk_start, chunk_size);
            wait_for_bit_peers_generated(round_id, chunk_start, chunk_size);
            send_bit_chunk(chunk);
            wait_for_bit_chunk(round_id, chunk_start);
            finalize_bit_chunk(round_id, chunk_start);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (bit_round_.batch_round_id == round_id && bit_round_.completed_items == bit_round_.batch_size)
            {
                bit_round_.state = "BIT_DONE";
            }
        }
        round_cv_.notify_all();
        log("bit batch " + std::to_string(round_id) + ": all items completed");
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
        chunk.local_secrets.assign(chunk_size, noise::RingElementRaw{});

        int status = noise::kOk;
        {
            std::lock_guard<std::mutex> enclave_lock(enclave_mutex_);
            check_oe(
                ecall_sharegen_batch_with_bound(
                    enclave_,
                    &status,
                    chunk.round_ids.data(),
                    chunk.round_ids.size(),
                    reinterpret_cast<share_package_t*>(chunk.packages.data()),
                    chunk.packages.size(),
                    reinterpret_cast<ring_element_t*>(chunk.local_secrets.data()),
                    round_.noise_bound_bits == 0 ? noise_bound_bits_ : round_.noise_bound_bits),
                "ecall_sharegen_batch_with_bound transport failed");
        }
        check_status(status, "ecall_sharegen_batch_with_bound rejected");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (uint64_t offset = 0; offset < chunk_size; ++offset)
            {
                round_.local_secrets[chunk_start + offset] = chunk.local_secrets[offset];
            }
            round_.current_item = chunk_start + chunk_size;
        }

        log("batch " + std::to_string(round_id) + ": enclave generated chunk start=" + std::to_string(chunk_start) + " size=" + std::to_string(chunk_size));
        return chunk;
    }

    GeneratedTripleChunk generate_triple_chunk(uint64_t round_id, uint64_t chunk_start, uint64_t chunk_size)
    {
        GeneratedTripleChunk chunk;
        chunk.round_ids.resize(chunk_size);
        for (uint64_t offset = 0; offset < chunk_size; ++offset)
        {
            chunk.round_ids[offset] = host::make_subround_id(round_id, chunk_start + offset);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            prepare_triple_chunk_locked(chunk_start, chunk.round_ids);
        }

        chunk.packages.assign(chunk_size, noise::TripleDPackage{});
        int status = noise::kOk;
        {
            std::lock_guard<std::mutex> enclave_lock(enclave_mutex_);
            check_oe(
                ecall_triple_generate_batch(
                    enclave_,
                    &status,
                    chunk.round_ids.data(),
                    chunk.round_ids.size(),
                    reinterpret_cast<triple_d_package_t*>(chunk.packages.data()),
                    chunk.packages.size()),
                "ecall_triple_generate_batch transport failed");
        }
        check_status(status, "ecall_triple_generate_batch rejected");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            triple_round_.current_item = chunk_start + chunk_size;
            for (uint64_t offset = 0; offset < chunk_size; ++offset)
            {
                if (!triple_received_from_[offset][party_id_ - 1])
                {
                    triple_received_from_[offset][party_id_ - 1] = true;
                    triple_round_.current_chunk_received_counts[offset] += 1;
                }
            }
        }

        return chunk;
    }

    GeneratedBitChunk generate_bit_chunk(uint64_t round_id, uint64_t chunk_start, uint64_t chunk_size)
    {
        GeneratedBitChunk chunk;
        chunk.round_ids.resize(chunk_size);
        for (uint64_t offset = 0; offset < chunk_size; ++offset)
        {
            chunk.round_ids[offset] = host::make_subround_id(round_id, chunk_start + offset);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            prepare_bit_chunk_locked(chunk_start, chunk.round_ids);
        }

        chunk.packages.assign(chunk_size, noise::BitVPackage{});
        int status = noise::kOk;
        {
            std::lock_guard<std::mutex> enclave_lock(enclave_mutex_);
            check_oe(
                ecall_bit_generate_batch(
                    enclave_,
                    &status,
                    chunk.round_ids.data(),
                    chunk.round_ids.size(),
                    reinterpret_cast<bit_v_package_t*>(chunk.packages.data()),
                    chunk.packages.size()),
                "ecall_bit_generate_batch transport failed");
        }
        check_status(status, "ecall_bit_generate_batch rejected");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            bit_round_.current_item = chunk_start + chunk_size;
            for (uint64_t offset = 0; offset < chunk_size; ++offset)
            {
                if (!bit_received_from_[offset][party_id_ - 1])
                {
                    bit_received_from_[offset][party_id_ - 1] = true;
                    bit_round_.current_chunk_received_counts[offset] += 1;
                }
            }
        }

        return chunk;
    }

    void send_chunk(uint64_t chunk_start, const GeneratedChunk& chunk)
    {
        const uint64_t chunk_size = chunk.round_ids.size();

        for (uint64_t receiver = 1; receiver <= party_count_; ++receiver)
        {
            std::vector<noise::SharePackage> packages;
            packages.reserve(chunk_size);

            for (uint64_t offset = 0; offset < chunk_size; ++offset)
            {
                packages.push_back(chunk.packages[offset * party_count_ + (receiver - 1)]);
            }

            if (receiver == party_id_)
            {
                log("chunk " + std::to_string(chunk_start) + ": storing self batch");
                const host::BatchAckMessage ack = process_batch_share_packages(packages);
                apply_batch_ack(ack, chunk_start);
                continue;
            }

            log("chunk " + std::to_string(chunk_start) + ": sending batch shares to party " + std::to_string(receiver));
            noise_rpc::BatchShareRequest request;
            for (const auto& share : packages)
            {
                auto* entry = request.add_packages();
                host::fill_share_package_proto(share, entry);
            }

            grpc::ClientContext context;
            noise_rpc::BatchAckReply reply;
            const auto status = stubs_[receiver - 1]->BatchShare(&context, request, &reply);
            if (!status.ok())
            {
                throw std::runtime_error("BatchShare RPC failed for party " + std::to_string(receiver) + ": " + status.error_message());
            }

            host::BatchAckMessage ack;
            ack.acks.reserve(reply.acks_size());
            for (const auto& ack_proto : reply.acks())
            {
                ack.acks.push_back(host::parse_ack_message_proto(ack_proto));
            }
            apply_batch_ack(ack, chunk_start);
        }
    }

    void send_triple_chunk(const GeneratedTripleChunk& chunk)
    {
        for (uint64_t receiver = 1; receiver <= party_count_; ++receiver)
        {
            if (receiver == party_id_)
            {
                continue;
            }

            noise_rpc::BatchTripleDRequest request;
            for (const auto& pkg : chunk.packages)
            {
                auto* entry = request.add_packages();
                host::fill_triple_d_package_proto(pkg, entry);
            }

            grpc::ClientContext context;
            noise_rpc::BatchTripleAckReply reply;
            const auto status = stubs_[receiver - 1]->BatchTripleD(&context, request, &reply);
            if (!status.ok())
            {
                throw std::runtime_error("BatchTripleD RPC failed for party " + std::to_string(receiver) + ": " + status.error_message());
            }
            if (!reply.ok())
            {
                throw std::runtime_error("BatchTripleD rejected by party " + std::to_string(receiver));
            }
        }
    }

    void send_bit_chunk(const GeneratedBitChunk& chunk)
    {
        for (uint64_t receiver = 1; receiver <= party_count_; ++receiver)
        {
            if (receiver == party_id_)
            {
                continue;
            }

            noise_rpc::BatchBitVRequest request;
            for (const auto& pkg : chunk.packages)
            {
                auto* entry = request.add_packages();
                host::fill_bit_v_package_proto(pkg, entry);
            }

            grpc::ClientContext context;
            noise_rpc::BatchBitAckReply reply;
            const auto status = stubs_[receiver - 1]->BatchBitV(&context, request, &reply);
            if (!status.ok())
            {
                throw std::runtime_error("BatchBitV RPC failed for party " + std::to_string(receiver) + ": " + status.error_message());
            }
            if (!reply.ok())
            {
                throw std::runtime_error("BatchBitV rejected by party " + std::to_string(receiver));
            }
        }
    }

    host::BatchAckMessage handle_batch_share_packages(const std::vector<noise::SharePackage>& packages)
    {
        if (packages.empty())
        {
            throw std::runtime_error("Received empty batch share message");
        }

        const uint64_t batch_round_id = batch_round_from_subround(packages.front().round_id);
        const uint64_t chunk_start = batch_index_from_subround(packages.front().round_id);
        std::vector<uint64_t> round_ids;
        round_ids.reserve(packages.size());
        for (const auto& share : packages)
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

        return process_batch_share_packages(packages);
    }

    void handle_batch_triple_d_packages(const std::vector<noise::TripleDPackage>& packages)
    {
        if (packages.empty())
        {
            throw std::runtime_error("Received empty triple batch share message");
        }

        const uint64_t batch_round_id = batch_round_from_subround(packages.front().round_id);
        const uint64_t chunk_start = batch_index_from_subround(packages.front().round_id);
        std::vector<uint64_t> round_ids;
        round_ids.reserve(packages.size());
        for (const auto& pkg : packages)
        {
            if (batch_round_from_subround(pkg.round_id) != batch_round_id)
            {
                throw std::runtime_error("Mixed triple batch rounds in one triple message");
            }
            round_ids.push_back(pkg.round_id);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (triple_round_.batch_round_id != batch_round_id)
            {
                throw std::runtime_error("Received triple batch share for unexpected batch round");
            }
            prepare_triple_chunk_locked(chunk_start, round_ids);
        }

        std::vector<noise::TripleDPackage> mutable_packages = packages;
        int status = noise::kOk;
        {
            std::lock_guard<std::mutex> enclave_lock(enclave_mutex_);
            check_oe(
                ecall_triple_store_batch(
                    enclave_,
                    &status,
                    reinterpret_cast<triple_d_package_t*>(mutable_packages.data()),
                    mutable_packages.size()),
                "ecall_triple_store_batch transport failed");
        }
        check_status(status, "ecall_triple_store_batch rejected");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (size_t offset = 0; offset < packages.size(); ++offset)
            {
                const uint64_t sender = packages[offset].sender_id;
                if (!triple_received_from_[offset][sender - 1])
                {
                    triple_received_from_[offset][sender - 1] = true;
                    triple_round_.current_chunk_received_counts[offset] += 1;
                }
            }
        }

        round_cv_.notify_all();
    }

    void handle_batch_bit_v_packages(const std::vector<noise::BitVPackage>& packages)
    {
        if (packages.empty())
        {
            throw std::runtime_error("Received empty bit batch share message");
        }

        const uint64_t batch_round_id = batch_round_from_subround(packages.front().round_id);
        const uint64_t chunk_start = batch_index_from_subround(packages.front().round_id);
        std::vector<uint64_t> round_ids;
        round_ids.reserve(packages.size());
        for (const auto& pkg : packages)
        {
            if (batch_round_from_subround(pkg.round_id) != batch_round_id)
            {
                throw std::runtime_error("Mixed bit batch rounds in one bit message");
            }
            round_ids.push_back(pkg.round_id);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (bit_round_.batch_round_id != batch_round_id)
            {
                throw std::runtime_error("Received bit batch share for unexpected batch round");
            }
            prepare_bit_chunk_locked(chunk_start, round_ids);
        }

        std::vector<noise::BitVPackage> mutable_packages = packages;
        int status = noise::kOk;
        {
            std::lock_guard<std::mutex> enclave_lock(enclave_mutex_);
            check_oe(
                ecall_bit_store_batch(
                    enclave_,
                    &status,
                    reinterpret_cast<bit_v_package_t*>(mutable_packages.data()),
                    mutable_packages.size()),
                "ecall_bit_store_batch transport failed");
        }
        check_status(status, "ecall_bit_store_batch rejected");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (size_t offset = 0; offset < packages.size(); ++offset)
            {
                const uint64_t sender = packages[offset].sender_id;
                if (!bit_received_from_[offset][sender - 1])
                {
                    bit_received_from_[offset][sender - 1] = true;
                    bit_round_.current_chunk_received_counts[offset] += 1;
                }
            }
        }

        round_cv_.notify_all();
    }

    host::BatchAckMessage process_batch_share_packages(const std::vector<noise::SharePackage>& packages)
    {
        host::BatchAckMessage message;
        message.acks.resize(packages.size());
        int status = noise::kOk;

        std::vector<noise::SharePackage> mutable_packages = packages;
        {
            std::lock_guard<std::mutex> enclave_lock(enclave_mutex_);
            check_oe(
                ecall_store_batch(
                    enclave_,
                    &status,
                    reinterpret_cast<share_package_t*>(mutable_packages.data()),
                    mutable_packages.size(),
                    reinterpret_cast<ack_message_t*>(message.acks.data())),
                "ecall_store_batch transport failed");
        }
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
            if (!noise::verify_ack(ack))
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
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

        while (true)
        {
            check_oe(
                [&]() {
                    std::lock_guard<std::mutex> enclave_lock(enclave_mutex_);
                    return ecall_done_batch(
                        enclave_,
                        &status,
                        reinterpret_cast<share_point_t*>(aggregates.data()),
                        aggregates.size());
                }(),
                "ecall_done_batch transport failed");

            if (status == noise::kOk)
            {
                break;
            }

            if (status != noise::kInsufficientShares)
            {
                check_status(status, "ecall_done_batch rejected");
            }

            if (std::chrono::steady_clock::now() >= deadline)
            {
                check_status(status, "ecall_done_batch rejected");
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

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

    void wait_for_triple_chunk(uint64_t round_id, uint64_t chunk_start)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        round_cv_.wait(lock, [this, round_id, chunk_start]() {
            return triple_round_.state == "ERROR" ||
                   triple_round_.batch_round_id != round_id ||
                   (triple_round_.current_chunk_start == chunk_start && triple_chunk_ready_locked());
        });

        if (triple_round_.state == "ERROR")
        {
            throw std::runtime_error("Triple batch entered ERROR state");
        }
    }

    void finalize_triple_chunk(uint64_t round_id, uint64_t chunk_start)
    {
        std::vector<noise::TripleShare> triples(triple_round_.current_chunk_size);
        int status = noise::kOk;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

        while (true)
        {
            check_oe(
                [&]() {
                    std::lock_guard<std::mutex> enclave_lock(enclave_mutex_);
                    return ecall_triple_done_batch(
                        enclave_,
                        &status,
                        reinterpret_cast<triple_share_t*>(triples.data()),
                        triples.size());
                }(),
                "ecall_triple_done_batch transport failed");

            if (status == noise::kOk)
            {
                break;
            }

            if (status != noise::kNotReady)
            {
                check_status(status, "ecall_triple_done_batch rejected");
            }

            if (std::chrono::steady_clock::now() >= deadline)
            {
                check_status(status, "ecall_triple_done_batch rejected");
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (triple_round_.batch_round_id != round_id || triple_round_.current_chunk_start != chunk_start)
            {
                throw std::runtime_error("Triple chunk state changed before finalize");
            }

            for (size_t offset = 0; offset < triples.size(); ++offset)
            {
                triple_round_.triples[chunk_start + offset] = triples[offset];
            }

            triple_round_.completed_items += triples.size();
            triple_round_.current_item = chunk_start + triples.size() - 1;
            triple_round_.current_chunk_done = true;
        }

        round_cv_.notify_all();
    }

    void wait_for_bit_chunk(uint64_t round_id, uint64_t chunk_start)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        round_cv_.wait(lock, [this, round_id, chunk_start]() {
            return bit_round_.state == "ERROR" ||
                   bit_round_.batch_round_id != round_id ||
                   (bit_round_.current_chunk_start == chunk_start && bit_chunk_ready_locked());
        });

        if (bit_round_.state == "ERROR")
        {
            throw std::runtime_error("Bit batch entered ERROR state");
        }
    }

    void finalize_bit_chunk(uint64_t round_id, uint64_t chunk_start)
    {
        std::vector<noise::BitShare> bits(bit_round_.current_chunk_size);
        int status = noise::kOk;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

        while (true)
        {
            check_oe(
                [&]() {
                    std::lock_guard<std::mutex> enclave_lock(enclave_mutex_);
                    return ecall_bit_done_batch(
                        enclave_,
                        &status,
                        reinterpret_cast<bit_share_t*>(bits.data()),
                        bits.size());
                }(),
                "ecall_bit_done_batch transport failed");

            if (status == noise::kOk)
            {
                break;
            }

            if (status != noise::kNotReady)
            {
                check_status(status, "ecall_bit_done_batch rejected");
            }

            if (std::chrono::steady_clock::now() >= deadline)
            {
                check_status(status, "ecall_bit_done_batch rejected");
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (bit_round_.batch_round_id != round_id || bit_round_.current_chunk_start != chunk_start)
            {
                throw std::runtime_error("Bit chunk state changed before finalize");
            }

            for (size_t offset = 0; offset < bits.size(); ++offset)
            {
                bit_round_.bits[chunk_start + offset] = bits[offset];
            }

            bit_round_.completed_items += bits.size();
            bit_round_.current_item = chunk_start + bits.size() - 1;
            bit_round_.current_chunk_done = true;
        }

        round_cv_.notify_all();
    }

    void start_keygen(uint64_t round_id, const std::string& session_id, const std::string& preproc_root, const std::string& output_dir)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const bool failed_before = keygen_.state.rfind("KEYGEN_FAILED", 0) == 0;
            if (keygen_.state != "IDLE" && keygen_.state != "KEYGEN_DONE" && !failed_before)
            {
                throw std::runtime_error("keygen already running");
            }

            keygen_ = KeygenState{};
            keygen_.round_id = round_id;
            keygen_.session_id = session_id;
            keygen_.preproc_root = preproc_root;
            keygen_.output_dir = output_dir;
            keygen_.state = "KEYGEN_RUNNING";
            keygen_.batch_size = 1;
            keygen_open_shares_.clear();
        }

        std::thread([this, round_id, session_id, preproc_root, output_dir]() {
            try
            {
                run_keygen(round_id, session_id, preproc_root, output_dir);
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (keygen_.round_id == round_id)
                    {
                        keygen_.completed_items = 1;
                        keygen_.state = "KEYGEN_DONE";
                    }
                }
                round_cv_.notify_all();
            }
            catch (const std::exception& ex)
            {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (keygen_.round_id == round_id)
                    {
                        keygen_.state = std::string("KEYGEN_FAILED:") + ex.what();
                    }
                }
                round_cv_.notify_all();
                log(std::string("keygen failed: ") + ex.what());
            }
        }).detach();
    }

    void handle_batch_keygen_open_packages(const std::vector<noise_rpc::KeygenOpenSharePackage>& packages)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& package : packages)
        {
            uint64_t round_id = 0;
            uint64_t sender_id = 0;
            const noise::RingElementRaw raw = host::parse_keygen_open_share_proto(package, &round_id, &sender_id);
            auto& shares = keygen_open_shares_[round_id];
            const auto it = std::find_if(
                shares.begin(),
                shares.end(),
                [sender_id](const algebra::RingShare& share) { return share.owner == sender_id; });
            if (it == shares.end())
            {
                shares.push_back(algebra::RingShare{sender_id, noise::ring_from_raw(raw)});
            }
        }
        round_cv_.notify_all();
    }

    algebra::ResiduePolyF4Z128 open_share_online(uint64_t round_id, const algebra::RingShare& local_share)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto& shares = keygen_open_shares_[round_id];
            const auto it = std::find_if(
                shares.begin(),
                shares.end(),
                [this](const algebra::RingShare& share) { return share.owner == party_id_; });
            if (it == shares.end())
            {
                shares.push_back(local_share);
            }
        }

        noise_rpc::BatchKeygenOpenRequest request;
        host::fill_keygen_open_share_proto(
            round_id,
            party_id_,
            noise::raw_from_ring(local_share.value),
            request.add_packages());

        for (size_t i = 0; i < stubs_.size(); ++i)
        {
            if (i + 1 == party_id_)
            {
                continue;
            }
            grpc::ClientContext context;
            noise_rpc::BatchKeygenOpenReply reply;
            const grpc::Status status = stubs_[i]->BatchKeygenOpen(&context, request, &reply);
            if (!status.ok() || !reply.ok())
            {
                throw std::runtime_error("BatchKeygenOpen failed for peer " + std::to_string(i + 1));
            }
        }

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        std::unique_lock<std::mutex> lock(mutex_);
        round_cv_.wait_until(lock, deadline, [&]() {
            const auto it = keygen_open_shares_.find(round_id);
            return it != keygen_open_shares_.end() && it->second.size() >= (2 * threshold_ + 1);
        });

        const auto it = keygen_open_shares_.find(round_id);
        if (it == keygen_open_shares_.end() || it->second.size() < (2 * threshold_ + 1))
        {
            throw std::runtime_error("Timed out waiting for online open shares");
        }

        algebra::ResiduePolyF4Z128 opened;
        if (!algebra::RingOpen::robust_open(it->second, static_cast<size_t>(threshold_), 0, &opened))
        {
            throw std::runtime_error("Failed to reconstruct online open value");
        }
        return opened;
    }

    algebra::RingShare mul_online(
        uint64_t* open_counter,
        const algebra::RingShare& lhs,
        const algebra::RingShare& rhs,
        const algebra::RingTripleShare& triple)
    {
        if (open_counter == nullptr)
        {
            throw std::runtime_error("null open counter");
        }

        const algebra::RingShare epsilon_share{
            party_id_,
            lhs.value + triple.a.value
        };
        const algebra::RingShare rho_share{
            party_id_,
            rhs.value + triple.b.value
        };

        const algebra::ResiduePolyF4Z128 epsilon = open_share_online((*open_counter)++, epsilon_share);
        const algebra::ResiduePolyF4Z128 rho = open_share_online((*open_counter)++, rho_share);
        return algebra::RingShare{
            party_id_,
            rhs.value * epsilon - triple.a.value * rho + triple.c.value
        };
    }

    void run_keygen(uint64_t round_id, const std::string& session_id, const std::string& preproc_root, const std::string& output_dir)
    {
        host::dkg::DkgPlan loaded_plan;
        host::dkg::PreprocessedKeygenMaterial material;
        std::string error_message;
        const std::string session_root = host::dkg::PreprocessingStore::session_dir(preproc_root, session_id);
        const std::string party_session = "party_" + std::to_string(party_id_);
        if (!host::dkg::PreprocessingStore::load(session_root, party_session, &loaded_plan, &material, &error_message))
        {
            throw std::runtime_error(error_message);
        }
        (void)loaded_plan;

        const host::dkg::DkgPlan plan = host::dkg::build_plan(config_);
        if (!host::dkg::DistributedKeyGen::validate_preprocessing(plan, material, &error_message))
        {
            throw std::runtime_error(error_message);
        }

        host::dkg::KeygenOutput key_output;
        key_output.plan = plan;
        key_output.public_seed = material.seed;

        auto verify_noise_record = [&](const host::dkg::SharedNoiseVector& item) {
            if (item.shares.size() != 1)
            {
                throw std::runtime_error("Local noise record must contain exactly one share");
            }
            noise::SharePoint point{};
            point.round_id = item.round_id;
            point.x = item.shares[0].owner;
            point.y = noise::raw_from_ring(item.shares[0].value);
            point.sigma = item.sigma;
            int status = noise::kOk;
            check_oe(
                ecall_verify_noise_output(enclave_, &status, reinterpret_cast<share_point_t*>(&point)),
                "ecall_verify_noise_output transport failed");
            check_status(status, "ecall_verify_noise_output rejected");
        };

        auto verify_bit_record = [&](const host::dkg::SharedBitVector& item) {
            if (item.shares.size() != 1)
            {
                throw std::runtime_error("Local bit record must contain exactly one share");
            }
            noise::BitShare bit{};
            bit.round_id = item.round_id;
            bit.b = noise::raw_from_ring(item.shares[0].value);
            bit.sigma = item.sigma;
            int status = noise::kOk;
            check_oe(
                ecall_verify_bit_output(enclave_, &status, reinterpret_cast<bit_share_t*>(&bit)),
                "ecall_verify_bit_output transport failed");
            check_status(status, "ecall_verify_bit_output rejected");
        };

        auto verify_triple_record = [&](const host::dkg::SharedTripleVector& item) {
            if (item.triples.size() != 1)
            {
                throw std::runtime_error("Local triple record must contain exactly one share");
            }
            noise::TripleShare triple{};
            triple.round_id = item.round_id;
            triple.a = noise::raw_from_ring(item.triples[0].a.value);
            triple.b = noise::raw_from_ring(item.triples[0].b.value);
            triple.c = noise::raw_from_ring(item.triples[0].c.value);
            triple.sigma = item.sigma;
            int status = noise::kOk;
            check_oe(
                ecall_verify_triple_output(enclave_, &status, reinterpret_cast<triple_share_t*>(&triple)),
                "ecall_verify_triple_output transport failed");
            check_status(status, "ecall_verify_triple_output rejected");
        };

        for (const auto& item : material.raw_bits)
        {
            verify_bit_record(item);
        }
        for (const auto& item : material.noises)
        {
            verify_noise_record(item);
        }
        for (const auto& item : material.triples)
        {
            verify_triple_record(item);
        }

        auto find_local_share = [&](const std::vector<algebra::RingShare>& shares, const char* label) {
            for (const auto& share : shares)
            {
                if (share.owner == party_id_)
                {
                    return share;
                }
            }
            throw std::runtime_error(std::string("Missing local share for ") + label);
        };

        struct LocalNoisePool
        {
            std::map<host::dkg::NoiseKind, std::deque<algebra::RingShare>> by_kind;
        } noise_pool;

        for (const auto& item : material.noises)
        {
            noise_pool.by_kind[item.kind].push_back(find_local_share(item.shares, "noise"));
        }

        std::deque<algebra::RingTripleShare> triple_pool;
        for (const auto& item : material.triples)
        {
            bool found = false;
            for (const auto& triple : item.triples)
            {
                if (triple.a.owner == party_id_)
                {
                    triple_pool.push_back(triple);
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                throw std::runtime_error("Missing local triple share");
            }
        }

        auto pop_noise = [&](host::dkg::NoiseKind kind, const char* label) {
            auto it = noise_pool.by_kind.find(kind);
            if (it == noise_pool.by_kind.end() || it->second.empty())
            {
                throw std::runtime_error(std::string("Exhausted local noise pool for ") + label);
            }
            algebra::RingShare share = it->second.front();
            it->second.pop_front();
            return share;
        };

        auto pop_noise_vec = [&](host::dkg::NoiseKind kind, size_t amount, const char* label) {
            std::vector<algebra::RingShare> shares;
            shares.reserve(amount);
            for (size_t i = 0; i < amount; ++i)
            {
                shares.push_back(pop_noise(kind, label));
            }
            return shares;
        };

        auto pop_triple = [&]() {
            if (triple_pool.empty())
            {
                throw std::runtime_error("Exhausted local triple pool");
            }
            const algebra::RingTripleShare triple = triple_pool.front();
            triple_pool.pop_front();
            return triple;
        };

        auto extract_segment = [&](size_t start, size_t count, const char* label) {
            std::vector<algebra::RingShare> out;
            out.reserve(count);
            for (size_t i = 0; i < count; ++i)
            {
                if (start + i >= material.raw_bits.size())
                {
                    throw std::runtime_error(std::string("Insufficient raw bits for ") + label);
                }
                out.push_back(find_local_share(material.raw_bits[start + i].shares, label));
            }
            return out;
        };

        size_t raw_offset = 0;
        const auto lwe = extract_segment(raw_offset, plan.shape.lwe_secret_bits, "lwe");
        raw_offset += plan.shape.lwe_secret_bits;
        const auto lwe_hat = extract_segment(raw_offset, plan.shape.lwe_hat_secret_bits, "lwe_hat");
        raw_offset += plan.shape.lwe_hat_secret_bits;
        const auto glwe = extract_segment(raw_offset, plan.shape.glwe_secret_bits, "glwe");
        raw_offset += plan.shape.glwe_secret_bits;
        const auto compression_glwe = extract_segment(raw_offset, plan.shape.compression_secret_bits, "compression_glwe");
        raw_offset += plan.shape.compression_secret_bits;
        const auto sns_glwe = extract_segment(raw_offset, plan.shape.sns_glwe_secret_bits, "sns_glwe");
        raw_offset += plan.shape.sns_glwe_secret_bits;
        const auto sns_compression_glwe = extract_segment(raw_offset, plan.shape.sns_compression_secret_bits, "sns_compression_glwe");

        key_output.secret_shares.lwe = lwe;
        key_output.secret_shares.lwe_hat = lwe_hat;
        key_output.secret_shares.glwe = glwe;
        key_output.secret_shares.compression_glwe = compression_glwe;
        key_output.secret_shares.sns_glwe = sns_glwe;
        key_output.secret_shares.sns_compression_glwe = sns_compression_glwe;

        uint64_t open_counter = (round_id << 32U) | 1U;
        key_output.public_material.pk.reserve(plan.shape.public_key_ciphertexts);
        for (size_t i = 0; i < plan.shape.public_key_ciphertexts; ++i)
        {
            host::dkg::SharedLweCiphertext ctxt;
            if (!host::dkg::DistributedEncryption::enc_lwe(
                    material.seed,
                    static_cast<uint64_t>(i),
                    noise::RingElementRaw{},
                    lwe,
                    pop_noise(host::dkg::NoiseKind::kLweHat, "pk"),
                    lwe.size(),
                    true,
                    &ctxt))
            {
                throw std::runtime_error("Failed to build pk ciphertext");
            }
            key_output.public_material.pk.push_back(ctxt);
        }

        key_output.public_material.ksk.reserve(glwe.size());
        for (size_t i = 0; i < glwe.size(); ++i)
        {
            host::dkg::SharedLevCiphertext ctxt;
            if (!host::dkg::DistributedEncryption::enc_lev(
                    material.seed,
                    0x100000ULL + static_cast<uint64_t>(i * plan.params.regular.ks_level),
                    noise::raw_from_ring(glwe[i].value),
                    lwe,
                    pop_noise_vec(host::dkg::NoiseKind::kLwe, plan.params.regular.ks_level, "ksk"),
                    lwe.size(),
                    plan.params.regular.ks_base_log,
                    plan.params.regular.ks_level,
                    true,
                    &ctxt))
            {
                throw std::runtime_error("Failed to build ksk ciphertext");
            }
            key_output.public_material.ksk.push_back(ctxt);
        }

        if (plan.params.regular.pksk_destination == host::dkg::PkskDestination::kSmall)
        {
            key_output.public_material.pksk_lwe.reserve(lwe_hat.size());
            for (size_t i = 0; i < lwe_hat.size(); ++i)
            {
                host::dkg::SharedLevCiphertext ctxt;
                if (!host::dkg::DistributedEncryption::enc_lev(
                        material.seed,
                        0x200000ULL + static_cast<uint64_t>(i * plan.params.regular.pksk_level),
                        noise::raw_from_ring(lwe_hat[i].value),
                        lwe,
                        pop_noise_vec(host::dkg::NoiseKind::kLwe, plan.params.regular.pksk_level, "pksk_lwe"),
                        lwe.size(),
                        plan.params.regular.pksk_base_log,
                        plan.params.regular.pksk_level,
                        true,
                        &ctxt))
                {
                    throw std::runtime_error("Failed to build pksk_lwe ciphertext");
                }
                key_output.public_material.pksk_lwe.push_back(ctxt);
            }
        }
        else if (plan.params.regular.pksk_destination == host::dkg::PkskDestination::kBig)
        {
            key_output.public_material.pksk_glwe.reserve(lwe_hat.size());
            for (size_t i = 0; i < lwe_hat.size(); ++i)
            {
                host::dkg::SharedGlevCiphertext ctxt;
                if (!host::dkg::DistributedEncryption::enc_glev(
                        material.seed,
                        0x300000ULL + static_cast<uint64_t>(i * plan.params.regular.pksk_level),
                        noise::raw_from_ring(lwe_hat[i].value),
                        glwe,
                        pop_noise_vec(host::dkg::NoiseKind::kGlwe, plan.params.regular.pksk_level, "pksk_glwe"),
                        glwe.size(),
                        plan.params.regular.pksk_base_log,
                        plan.params.regular.pksk_level,
                        true,
                        &ctxt))
                {
                    throw std::runtime_error("Failed to build pksk_glwe ciphertext");
                }
                key_output.public_material.pksk_glwe.push_back(ctxt);
            }
        }

        key_output.public_material.bk.reserve(lwe.size());
        for (size_t i = 0; i < lwe.size(); ++i)
        {
            std::vector<algebra::RingShare> multiplied_rows;
            multiplied_rows.reserve(glwe.size());
            for (const auto& glwe_share : glwe)
            {
                multiplied_rows.push_back(mul_online(&open_counter, glwe_share, lwe[i], pop_triple()));
            }

            std::vector<std::vector<algebra::RingShare>> row_noise(glwe.size() + 1);
            for (size_t row = 0; row < row_noise.size(); ++row)
            {
                row_noise[row] = pop_noise_vec(host::dkg::NoiseKind::kGlwe, plan.params.regular.bk_level, "bk");
            }

            host::dkg::SharedGgswCiphertext ctxt;
            if (!host::dkg::DistributedEncryption::enc_ggsw(
                    material.seed,
                    0x400000ULL + static_cast<uint64_t>(i * row_noise.size() * plan.params.regular.bk_level),
                    noise::raw_from_ring(lwe[i].value),
                    glwe,
                    glwe,
                    multiplied_rows,
                    row_noise,
                    glwe.size(),
                    plan.params.regular.bk_base_log,
                    plan.params.regular.bk_level,
                    true,
                    &ctxt))
            {
                throw std::runtime_error("Failed to build bk ciphertext");
            }
            key_output.public_material.bk.push_back(ctxt);
        }

        if (!sns_glwe.empty())
        {
            key_output.public_material.bk_sns.reserve(lwe.size());
            for (size_t i = 0; i < lwe.size(); ++i)
            {
                std::vector<algebra::RingShare> multiplied_rows;
                multiplied_rows.reserve(sns_glwe.size());
                for (const auto& sns_share : sns_glwe)
                {
                    multiplied_rows.push_back(mul_online(&open_counter, sns_share, lwe[i], pop_triple()));
                }

                std::vector<std::vector<algebra::RingShare>> row_noise(sns_glwe.size() + 1);
                for (size_t row = 0; row < row_noise.size(); ++row)
                {
                    row_noise[row] = pop_noise_vec(host::dkg::NoiseKind::kGlweSns, plan.params.sns.bk_level, "bk_sns");
                }

                host::dkg::SharedGgswCiphertext ctxt;
                if (!host::dkg::DistributedEncryption::enc_ggsw(
                        material.seed,
                        0x500000ULL + static_cast<uint64_t>(i * row_noise.size() * plan.params.sns.bk_level),
                        noise::raw_from_ring(lwe[i].value),
                        sns_glwe,
                        sns_glwe,
                        multiplied_rows,
                        row_noise,
                        sns_glwe.size(),
                        plan.params.sns.bk_base_log,
                        plan.params.sns.bk_level,
                        true,
                        &ctxt))
                {
                    throw std::runtime_error("Failed to build bk_sns ciphertext");
                }
                key_output.public_material.bk_sns.push_back(ctxt);
            }
        }

        if (!compression_glwe.empty())
        {
            key_output.public_material.compression_key.reserve(glwe.size());
            for (size_t i = 0; i < glwe.size(); ++i)
            {
                std::vector<algebra::RingShare> multiplied_rows;
                multiplied_rows.reserve(compression_glwe.size());
                for (const auto& compression_share : compression_glwe)
                {
                    multiplied_rows.push_back(mul_online(&open_counter, compression_share, glwe[i], pop_triple()));
                }

                std::vector<std::vector<algebra::RingShare>> row_noise(compression_glwe.size() + 1);
                for (size_t row = 0; row < row_noise.size(); ++row)
                {
                    row_noise[row] = pop_noise_vec(
                        host::dkg::NoiseKind::kCompressionKsk,
                        plan.params.regular.compression.packing_ks_level,
                        "compression_key");
                }

                host::dkg::SharedGgswCiphertext ctxt;
                if (!host::dkg::DistributedEncryption::enc_ggsw(
                        material.seed,
                        0x600000ULL + static_cast<uint64_t>(i * row_noise.size() * plan.params.regular.compression.packing_ks_level),
                        noise::raw_from_ring(glwe[i].value),
                        compression_glwe,
                        compression_glwe,
                        multiplied_rows,
                        row_noise,
                        compression_glwe.size(),
                        plan.params.regular.compression.packing_ks_base_log,
                        plan.params.regular.compression.packing_ks_level,
                        true,
                        &ctxt))
                {
                    throw std::runtime_error("Failed to build compression key ciphertext");
                }
                key_output.public_material.compression_key.push_back(ctxt);
            }

            key_output.public_material.decompression_key.reserve(compression_glwe.size());
            for (size_t i = 0; i < compression_glwe.size(); ++i)
            {
                host::dkg::SharedGlevCiphertext ctxt;
                if (!host::dkg::DistributedEncryption::enc_glev(
                        material.seed,
                        0x700000ULL + static_cast<uint64_t>(i * plan.params.regular.compression.br_level),
                        noise::raw_from_ring(compression_glwe[i].value),
                        glwe,
                        pop_noise_vec(host::dkg::NoiseKind::kGlwe, plan.params.regular.compression.br_level, "decompression_key"),
                        glwe.size(),
                        plan.params.regular.compression.br_base_log,
                        plan.params.regular.compression.br_level,
                        true,
                        &ctxt))
                {
                    throw std::runtime_error("Failed to build decompression key ciphertext");
                }
                key_output.public_material.decompression_key.push_back(ctxt);
            }
        }

        if (!sns_compression_glwe.empty())
        {
            key_output.public_material.sns_compression_key.reserve(sns_glwe.size());
            for (size_t i = 0; i < sns_glwe.size(); ++i)
            {
                std::vector<algebra::RingShare> multiplied_rows;
                multiplied_rows.reserve(sns_compression_glwe.size());
                for (const auto& compression_share : sns_compression_glwe)
                {
                    multiplied_rows.push_back(mul_online(&open_counter, compression_share, sns_glwe[i], pop_triple()));
                }

                std::vector<std::vector<algebra::RingShare>> row_noise(sns_compression_glwe.size() + 1);
                for (size_t row = 0; row < row_noise.size(); ++row)
                {
                    row_noise[row] = pop_noise_vec(
                        host::dkg::NoiseKind::kSnsCompressionKsk,
                        plan.params.sns.compression.packing_ks_level,
                        "sns_compression_key");
                }

                host::dkg::SharedGgswCiphertext ctxt;
                if (!host::dkg::DistributedEncryption::enc_ggsw(
                        material.seed,
                        0x800000ULL + static_cast<uint64_t>(i * row_noise.size() * plan.params.sns.compression.packing_ks_level),
                        noise::raw_from_ring(sns_glwe[i].value),
                        sns_compression_glwe,
                        sns_compression_glwe,
                        multiplied_rows,
                        row_noise,
                        sns_compression_glwe.size(),
                        plan.params.sns.compression.packing_ks_base_log,
                        plan.params.sns.compression.packing_ks_level,
                        true,
                        &ctxt))
                {
                    throw std::runtime_error("Failed to build sns compression key ciphertext");
                }
                key_output.public_material.sns_compression_key.push_back(ctxt);
            }
        }

        std::filesystem::create_directories(output_dir);
        const std::filesystem::path summary_path = std::filesystem::path(output_dir) / ("keygen_party_" + std::to_string(party_id_) + ".txt");
        const std::filesystem::path secret_key_path = std::filesystem::path(output_dir) / ("party_" + std::to_string(party_id_) + ".secret.key");
        const std::filesystem::path public_key_path = std::filesystem::path(output_dir) / ("party_" + std::to_string(party_id_) + ".public.key");

        host::dkg::SecretKeyBundle secret_bundle;
        secret_bundle.plan = key_output.plan;
        secret_bundle.public_seed = key_output.public_seed;
        secret_bundle.secret_shares = key_output.secret_shares;

        host::dkg::PublicKeyBundle public_bundle;
        public_bundle.plan = key_output.plan;
        public_bundle.public_seed = key_output.public_seed;
        public_bundle.public_material = key_output.public_material;

        if (!host::dkg::save_secret_key_file(secret_key_path.string(), secret_bundle, &error_message))
        {
            throw std::runtime_error(error_message);
        }
        if (!host::dkg::save_public_key_file(public_key_path.string(), public_bundle, &error_message))
        {
            throw std::runtime_error(error_message);
        }
        std::ofstream summary(summary_path);
        if (!summary)
        {
            throw std::runtime_error("Failed to write keygen summary");
        }
        summary << "party_id=" << party_id_ << "\n";
        summary << "session_id=" << session_id << "\n";
        summary << "preset=" << plan.params.preset_name << "\n";
        summary << "seed_low=" << material.seed.low << "\n";
        summary << "seed_high=" << material.seed.high << "\n";
        summary << "lwe_shares=" << lwe.size() << "\n";
        summary << "lwe_hat_shares=" << lwe_hat.size() << "\n";
        summary << "glwe_shares=" << glwe.size() << "\n";
        summary << "compression_glwe_shares=" << compression_glwe.size() << "\n";
        summary << "sns_glwe_shares=" << sns_glwe.size() << "\n";
        summary << "sns_compression_glwe_shares=" << sns_compression_glwe.size() << "\n";
        summary << "pk_ctxts=" << key_output.public_material.pk.size() << "\n";
        summary << "ksk_ctxts=" << key_output.public_material.ksk.size() << "\n";
        summary << "pksk_lwe_ctxts=" << key_output.public_material.pksk_lwe.size() << "\n";
        summary << "pksk_glwe_ctxts=" << key_output.public_material.pksk_glwe.size() << "\n";
        summary << "bk_ctxts=" << key_output.public_material.bk.size() << "\n";
        summary << "bk_sns_ctxts=" << key_output.public_material.bk_sns.size() << "\n";
        summary << "compression_ctxts=" << key_output.public_material.compression_key.size() << "\n";
        summary << "decompression_ctxts=" << key_output.public_material.decompression_key.size() << "\n";
        summary << "sns_compression_ctxts=" << key_output.public_material.sns_compression_key.size() << "\n";
        summary << "secret_key_file=" << secret_key_path.string() << "\n";
        summary << "public_key_file=" << public_key_path.string() << "\n";

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (keygen_.round_id == round_id)
            {
                keygen_.summary_path = summary_path.string();
            }
        }
    }

    host::StatusSnapshot snapshot()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        host::StatusSnapshot status;
        status.party_id = party_id_;
        if (keygen_.state != "IDLE")
        {
            status.round_id = keygen_.round_id;
            status.batch_size = keygen_.batch_size;
            status.state = keygen_.state;
            status.current_item = keygen_.completed_items;
            status.completed_items = keygen_.completed_items;
            status.received_shares = 0;
            status.ack_count = 0;
            status.expected_shares = party_count_;
            status.success = keygen_.state == "KEYGEN_DONE" ? 1 : 0;
            return status;
        }
        if (bit_round_.state != "IDLE")
        {
            status.round_id = bit_round_.batch_round_id;
            status.batch_size = bit_round_.batch_size;
            status.state = bit_round_.state;
            status.current_item = bit_round_.current_item;
            status.completed_items = bit_round_.completed_items;
            status.received_shares = bit_round_.current_chunk_received_counts.empty() ? 0 : bit_round_.current_chunk_received_counts.front();
            status.ack_count = 0;
            status.expected_shares = 2 * threshold_ + 1;
            status.success = (bit_round_.batch_size != 0 && bit_round_.completed_items == bit_round_.batch_size) ? 1 : 0;
            status.bits = bit_round_.bits;
            return status;
        }
        if (triple_round_.state != "IDLE")
        {
            status.round_id = triple_round_.batch_round_id;
            status.batch_size = triple_round_.batch_size;
            status.state = triple_round_.state;
            status.current_item = triple_round_.current_item;
            status.completed_items = triple_round_.completed_items;
            status.received_shares = triple_round_.current_chunk_received_counts.empty() ? 0 : triple_round_.current_chunk_received_counts.front();
            status.ack_count = 0;
            status.expected_shares = 2 * threshold_ + 1;
            status.success = (triple_round_.batch_size != 0 && triple_round_.completed_items == triple_round_.batch_size) ? 1 : 0;
            status.triples = triple_round_.triples;
            return status;
        }
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

    void prepare_batch_locked(uint64_t round_id, uint64_t batch_size, uint32_t noise_bound_bits_override)
    {
        if (batch_size == 0)
        {
            throw std::runtime_error("batch_size must be positive");
        }

        if (round_.batch_round_id == round_id)
        {
            return;
        }

        clear_finished_protocol_states_locked();
        round_ = RoundState{};
        round_.batch_round_id = round_id;
        round_.batch_size = batch_size;
        round_.noise_bound_bits = noise_bound_bits_override;
        round_.state = "WAITING";
        round_.local_secrets.assign(batch_size, noise::RingElementRaw{});
        round_.aggregates.assign(batch_size, noise::SharePoint{});
        clear_chunk_tracking_locked();
    }

    void prepare_triple_batch_locked(uint64_t round_id, uint64_t batch_size)
    {
        if (batch_size == 0)
        {
            throw std::runtime_error("triple batch_size must be positive");
        }

        if (triple_round_.batch_round_id == round_id)
        {
            return;
        }

        clear_finished_protocol_states_locked();
        triple_round_ = TripleRoundState{};
        triple_round_.batch_round_id = round_id;
        triple_round_.batch_size = batch_size;
        triple_round_.state = "WAITING";
        triple_round_.triples.assign(batch_size, noise::TripleShare{});
        clear_triple_chunk_tracking_locked();
    }

    void prepare_bit_batch_locked(uint64_t round_id, uint64_t batch_size)
    {
        if (batch_size == 0)
        {
            throw std::runtime_error("bit batch_size must be positive");
        }

        if (bit_round_.batch_round_id == round_id)
        {
            return;
        }

        clear_finished_protocol_states_locked();
        bit_round_ = BitRoundState{};
        bit_round_.batch_round_id = round_id;
        bit_round_.batch_size = batch_size;
        bit_round_.state = "WAITING";
        bit_round_.bits.assign(batch_size, noise::BitShare{});
        clear_bit_chunk_tracking_locked();
    }

    void clear_finished_protocol_states_locked()
    {
        if (round_.state == "DONE" || round_.state == "ERROR")
        {
            round_ = RoundState{};
            clear_chunk_tracking_locked();
        }
        if (triple_round_.state == "TRIPLE_DONE" || triple_round_.state == "ERROR")
        {
            triple_round_ = TripleRoundState{};
            clear_triple_chunk_tracking_locked();
        }
        if (bit_round_.state == "BIT_DONE" || bit_round_.state == "ERROR")
        {
            bit_round_ = BitRoundState{};
            clear_bit_chunk_tracking_locked();
        }
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

    bool triple_chunk_ready_locked() const
    {
        if (triple_round_.current_chunk_received_counts.empty())
        {
            return false;
        }

        return std::all_of(
            triple_round_.current_chunk_received_counts.begin(),
            triple_round_.current_chunk_received_counts.end(),
            [this](uint64_t count) { return count == party_count_; });
    }

    bool bit_chunk_ready_locked() const
    {
        if (bit_round_.current_chunk_received_counts.empty())
        {
            return false;
        }

        return std::all_of(
            bit_round_.current_chunk_received_counts.begin(),
            bit_round_.current_chunk_received_counts.end(),
            [this](uint64_t count) { return count == party_count_; });
    }

    void prepare_triple_chunk_locked(uint64_t chunk_start, const std::vector<uint64_t>& round_ids)
    {
        if (triple_round_.current_chunk_start == chunk_start &&
            triple_round_.current_chunk_size == round_ids.size() &&
            triple_round_.current_chunk_round_ids == round_ids)
        {
            return;
        }

        triple_round_.current_chunk_start = chunk_start;
        triple_round_.current_chunk_size = round_ids.size();
        triple_round_.current_chunk_round_ids = round_ids;
        triple_round_.current_chunk_received_counts.assign(round_ids.size(), 0);
        triple_round_.current_chunk_done = false;

        for (size_t i = 0; i < noise::kMaxParallelBatch; ++i)
        {
            triple_received_from_[i].fill(false);
        }
    }

    void clear_triple_chunk_tracking_locked()
    {
        triple_round_.current_chunk_start = 0;
        triple_round_.current_chunk_size = 0;
        triple_round_.current_chunk_round_ids.clear();
        triple_round_.current_chunk_received_counts.clear();
        triple_round_.current_chunk_done = false;
        for (size_t i = 0; i < noise::kMaxParallelBatch; ++i)
        {
            triple_received_from_[i].fill(false);
        }
    }

    void prepare_bit_chunk_locked(uint64_t chunk_start, const std::vector<uint64_t>& round_ids)
    {
        if (bit_round_.current_chunk_start == chunk_start &&
            bit_round_.current_chunk_size == round_ids.size() &&
            bit_round_.current_chunk_round_ids == round_ids)
        {
            return;
        }

        bit_round_.current_chunk_start = chunk_start;
        bit_round_.current_chunk_size = round_ids.size();
        bit_round_.current_chunk_round_ids = round_ids;
        bit_round_.current_chunk_received_counts.assign(round_ids.size(), 0);
        bit_round_.current_chunk_done = false;

        for (size_t i = 0; i < noise::kMaxParallelBatch; ++i)
        {
            bit_received_from_[i].fill(false);
        }
    }

    void clear_bit_chunk_tracking_locked()
    {
        bit_round_.current_chunk_start = 0;
        bit_round_.current_chunk_size = 0;
        bit_round_.current_chunk_round_ids.clear();
        bit_round_.current_chunk_received_counts.clear();
        bit_round_.current_chunk_done = false;
        for (size_t i = 0; i < noise::kMaxParallelBatch; ++i)
        {
            bit_received_from_[i].fill(false);
        }
    }

    void log(const std::string& message)
    {
        static const bool verbose = []() {
            const char* env = std::getenv("NOISE_PARTY_VERBOSE");
            if (env == nullptr)
            {
                env = std::getenv("NOISE_LOG_VERBOSE");
            }
            return env != nullptr && std::string(env) == "1";
        }();

        if (!verbose)
        {
            const bool important =
                message.find("failed") != std::string::npos ||
                message.find("error") != std::string::npos ||
                message.find("grpc listening") != std::string::npos;
            if (!important)
            {
                return;
            }
        }

        const auto now = std::chrono::system_clock::now().time_since_epoch();
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        std::lock_guard<std::mutex> lock(output_mutex_);
        std::cout << "[" << ms << "][party " << party_id_ << "] " << message << std::endl;
    }

    void wait_for_peers_ready(uint64_t round_id, uint64_t chunk_start)
    {
        wait_for_protocol_peers_ready(round_id, chunk_start, ProtocolMode::kNoise);
    }

    void wait_for_peers_generated(uint64_t round_id, uint64_t chunk_start, uint64_t chunk_size)
    {
        wait_for_protocol_peers_generated(round_id, chunk_start, chunk_size, ProtocolMode::kNoise);
    }

    void wait_for_triple_peers_ready(uint64_t round_id, uint64_t chunk_start)
    {
        wait_for_protocol_peers_ready(round_id, chunk_start, ProtocolMode::kTriple);
    }

    void wait_for_triple_peers_generated(uint64_t round_id, uint64_t chunk_start, uint64_t chunk_size)
    {
        wait_for_protocol_peers_generated(round_id, chunk_start, chunk_size, ProtocolMode::kTriple);
    }

    void wait_for_bit_peers_ready(uint64_t round_id, uint64_t chunk_start)
    {
        wait_for_protocol_peers_ready(round_id, chunk_start, ProtocolMode::kBit);
    }

    void wait_for_bit_peers_generated(uint64_t round_id, uint64_t chunk_start, uint64_t chunk_size)
    {
        wait_for_protocol_peers_generated(round_id, chunk_start, chunk_size, ProtocolMode::kBit);
    }

    void wait_for_protocol_peers_ready(uint64_t round_id, uint64_t chunk_start, ProtocolMode mode)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);

        while (std::chrono::steady_clock::now() < deadline)
        {
            bool ready = true;

            for (size_t i = 0; i < peers_.size(); ++i)
            {
                if (static_cast<uint64_t>(i + 1) == party_id_)
                {
                    continue;
                }

                noise_rpc::StatusRequest request;
                request.set_full(false);
                grpc::ClientContext context;
                noise_rpc::StatusReply response;
                const auto rpc_status = stubs_[i]->Status(&context, request, &response);
                if (!rpc_status.ok())
                {
                    throw std::runtime_error("Status RPC failed for party " + std::to_string(i + 1) + ": " + rpc_status.error_message());
                }
                const host::StatusSnapshot status = host::parse_status_proto(response);

                if (status.state == "ERROR")
                {
                    throw std::runtime_error("Peer entered ERROR state: party " + std::to_string(status.party_id));
                }

                if (status.round_id != round_id || status.completed_items != chunk_start)
                {
                    ready = false;
                    break;
                }
            }

            if (ready)
            {
                return;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        throw std::runtime_error(
            std::string("Timed out waiting for peers to reach ") +
            mode_batch_label(mode) +
            " chunk start " +
            std::to_string(chunk_start));
    }

    void wait_for_protocol_peers_generated(uint64_t round_id, uint64_t chunk_start, uint64_t chunk_size, ProtocolMode mode)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
        const uint64_t generated_marker = chunk_start + chunk_size;

        while (std::chrono::steady_clock::now() < deadline)
        {
            bool ready = true;

            for (size_t i = 0; i < peers_.size(); ++i)
            {
                if (static_cast<uint64_t>(i + 1) == party_id_)
                {
                    continue;
                }

                noise_rpc::StatusRequest request;
                request.set_full(false);
                grpc::ClientContext context;
                noise_rpc::StatusReply response;
                const auto rpc_status = stubs_[i]->Status(&context, request, &response);
                if (!rpc_status.ok())
                {
                    throw std::runtime_error("Status RPC failed for party " + std::to_string(i + 1) + ": " + rpc_status.error_message());
                }
                const host::StatusSnapshot status = host::parse_status_proto(response);

                if (status.state == "ERROR")
                {
                    throw std::runtime_error("Peer entered ERROR state: party " + std::to_string(status.party_id));
                }

                if (status.round_id != round_id ||
                    status.completed_items != chunk_start ||
                    status.current_item < generated_marker)
                {
                    ready = false;
                    break;
                }
            }

            if (ready)
            {
                return;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        throw std::runtime_error(
            std::string("Timed out waiting for peers to generate ") +
            mode_batch_label(mode) +
            " chunk start " +
            std::to_string(chunk_start));
    }
};

class NoisePartyServiceImpl final : public noise_rpc::NoiseParty::Service
{
public:
    explicit NoisePartyServiceImpl(PartyNode* node)
        : node_(node)
    {
    }

    grpc::Status StartRound(grpc::ServerContext*,
                            const noise_rpc::StartRequest* request,
                            noise_rpc::StartReply* reply) override
    {
        try
        {
            node_->StartRound(request->round_id(), request->batch_size(), request->noise_bound_bits());
            reply->set_ok(true);
            reply->set_message("STARTED");
            return grpc::Status::OK;
        }
        catch (const std::exception& ex)
        {
            reply->set_ok(false);
            reply->set_message(ex.what());
            return grpc::Status::OK;
        }
    }

    grpc::Status BatchShare(grpc::ServerContext*,
                            const noise_rpc::BatchShareRequest* request,
                            noise_rpc::BatchAckReply* reply) override
    {
        try
        {
            std::vector<noise::SharePackage> packages;
            packages.reserve(request->packages_size());
            for (const auto& entry : request->packages())
            {
                packages.push_back(host::parse_share_package_proto(entry));
            }
            const host::BatchAckMessage ack = node_->HandleBatchSharePackages(packages);
            for (const auto& ack_item : ack.acks)
            {
                auto* entry = reply->add_acks();
                host::fill_ack_message_proto(ack_item, entry);
            }
            return grpc::Status::OK;
        }
        catch (const std::exception& ex)
        {
            return grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        }
    }

    grpc::Status StartTripleRound(grpc::ServerContext*,
                                  const noise_rpc::StartRequest* request,
                                  noise_rpc::StartReply* reply) override
    {
        try
        {
            node_->StartTripleRound(request->round_id(), request->batch_size());
            reply->set_ok(true);
            reply->set_message("TRIPLE_STARTED");
            return grpc::Status::OK;
        }
        catch (const std::exception& ex)
        {
            reply->set_ok(false);
            reply->set_message(ex.what());
            return grpc::Status::OK;
        }
    }

    grpc::Status BatchTripleD(grpc::ServerContext*,
                              const noise_rpc::BatchTripleDRequest* request,
                              noise_rpc::BatchTripleAckReply* reply) override
    {
        try
        {
            std::vector<noise::TripleDPackage> packages;
            packages.reserve(request->packages_size());
            for (const auto& entry : request->packages())
            {
                packages.push_back(host::parse_triple_d_package_proto(entry));
            }
            node_->HandleBatchTripleDPackages(packages);
            reply->set_ok(true);
            return grpc::Status::OK;
        }
        catch (const std::exception& ex)
        {
            reply->set_ok(false);
            return grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        }
    }

    grpc::Status StartBitRound(grpc::ServerContext*,
                               const noise_rpc::StartRequest* request,
                               noise_rpc::StartReply* reply) override
    {
        try
        {
            node_->StartBitRound(request->round_id(), request->batch_size());
            reply->set_ok(true);
            reply->set_message("BIT_STARTED");
            return grpc::Status::OK;
        }
        catch (const std::exception& ex)
        {
            reply->set_ok(false);
            reply->set_message(ex.what());
            return grpc::Status::OK;
        }
    }

    grpc::Status BatchBitV(grpc::ServerContext*,
                           const noise_rpc::BatchBitVRequest* request,
                           noise_rpc::BatchBitAckReply* reply) override
    {
        try
        {
            std::vector<noise::BitVPackage> packages;
            packages.reserve(request->packages_size());
            for (const auto& entry : request->packages())
            {
                packages.push_back(host::parse_bit_v_package_proto(entry));
            }
            node_->HandleBatchBitVPackages(packages);
            reply->set_ok(true);
            return grpc::Status::OK;
        }
        catch (const std::exception& ex)
        {
            reply->set_ok(false);
            return grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        }
    }

    grpc::Status StartKeygen(grpc::ServerContext*,
                             const noise_rpc::KeygenStartRequest* request,
                             noise_rpc::StartReply* reply) override
    {
        try
        {
            node_->StartKeygen(
                request->round_id(),
                request->session_id(),
                request->preproc_root(),
                request->output_dir());
            reply->set_ok(true);
            reply->set_message("STARTED");
            return grpc::Status::OK;
        }
        catch (const std::exception& ex)
        {
            reply->set_ok(false);
            reply->set_message(ex.what());
            return grpc::Status::OK;
        }
    }

    grpc::Status BatchKeygenOpen(grpc::ServerContext*,
                                 const noise_rpc::BatchKeygenOpenRequest* request,
                                 noise_rpc::BatchKeygenOpenReply* reply) override
    {
        try
        {
            std::vector<noise_rpc::KeygenOpenSharePackage> packages;
            packages.reserve(static_cast<size_t>(request->packages_size()));
            for (const auto& entry : request->packages())
            {
                packages.push_back(entry);
            }
            node_->HandleBatchKeygenOpenPackages(packages);
            reply->set_ok(true);
            return grpc::Status::OK;
        }
        catch (const std::exception& ex)
        {
            reply->set_ok(false);
            return grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        }
    }

    grpc::Status Status(grpc::ServerContext*,
                        const noise_rpc::StatusRequest* request,
                        noise_rpc::StatusReply* reply) override
    {
        const bool full = request->full();
        host::StatusSnapshot status = node_->GetStatus();
        host::fill_status_proto(status, reply, full);
        return grpc::Status::OK;
    }

private:
    PartyNode* node_;
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
            config,
            self.id,
            config.party_count,
            config.threshold,
            config.noise_bound_bits,
            self.endpoint.port,
            peers);
        party.initialize();
        NoisePartyServiceImpl service(&party);
        grpc::ServerBuilder builder;
        const std::string listen_addr = "0.0.0.0:" + std::to_string(self.endpoint.port);
        builder.SetMaxReceiveMessageSize(kGrpcMessageLimitBytes);
        builder.SetMaxSendMessageSize(kGrpcMessageLimitBytes);
        builder.AddListeningPort(listen_addr, grpc::InsecureServerCredentials());
        builder.RegisterService(&service);
        std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
        if (!server)
        {
            throw std::runtime_error("Failed to start gRPC server on " + listen_addr);
        }
        std::cout << "gRPC server listening on " << listen_addr << std::endl;
        server->Wait();
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}
