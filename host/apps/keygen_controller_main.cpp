// Controller entry point for the online key-generation phase. It triggers a
// single coordinated round and reports cross-party progress to the operator.

#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "../config/config.hpp"
#include "../protocol/grpc_utils.hpp"

namespace
{
constexpr int kGrpcMessageLimitBytes = 512 * 1024 * 1024;

uint64_t parse_u64(const char* text)
{
    return std::stoull(text);
}

std::string format_duration(std::chrono::seconds seconds)
{
    const auto total = seconds.count();
    const auto hours = total / 3600;
    const auto minutes = (total % 3600) / 60;
    const auto secs = total % 60;
    std::ostringstream out;
    if (hours > 0)
    {
        out << hours << "h";
    }
    if (hours > 0 || minutes > 0)
    {
        out << minutes << "m";
    }
    out << secs << "s";
    return out.str();
}

std::string keygen_stage_from_state(const std::string& state)
{
    const std::string prefix = "KEYGEN_RUNNING:";
    if (state.rfind(prefix, 0) == 0)
    {
        return state.substr(prefix.size());
    }
    if (state == "KEYGEN_DONE")
    {
        return "done";
    }
    return "starting";
}

std::string format_keygen_progress_line(
    const std::string& stage,
    uint64_t completed,
    uint64_t total,
    std::chrono::steady_clock::duration elapsed)
{
    const uint64_t percent = total == 0 ? 100 : (completed * 100) / total;
    const auto elapsed_secs = std::chrono::duration_cast<std::chrono::seconds>(elapsed);
    std::ostringstream out;
    out << "[keygen] stage=" << stage
        << " generated=" << completed << "/" << total
        << " progress=" << percent << "%"
        << " elapsed=" << format_duration(elapsed_secs);

    if (completed == 0 || completed >= total)
    {
        out << " eta=" << (completed >= total ? "0s" : "--");
    }
    else
    {
        const double rate = static_cast<double>(completed) /
            std::max(1.0, static_cast<double>(elapsed_secs.count()));
        const double remaining = static_cast<double>(total - completed) / std::max(rate, 1e-9);
        out << " eta=" << format_duration(std::chrono::seconds(static_cast<int64_t>(remaining)));
    }
    return out.str();
}
}

int main(int argc, const char* argv[])
{
    if (argc != 6)
    {
        std::cerr << "Usage: keygen_controller <round_id> <session_id> <config_path> <preproc_root> <output_dir>" << std::endl;
        return 1;
    }

    try
    {
        const uint64_t round_id = parse_u64(argv[1]);
        const std::string session_id = argv[2];
        const host::RuntimeConfig config = host::load_runtime_config(argv[3]);
        const std::string preproc_root = argv[4];
        const std::string output_dir = argv[5];

        const auto peers = host::endpoints_from_config(config);
        std::vector<std::unique_ptr<dkg_rpc::PartyNodeRpc::Stub>> stubs;
        stubs.reserve(peers.size());
        grpc::ChannelArguments channel_args;
        channel_args.SetMaxReceiveMessageSize(kGrpcMessageLimitBytes);
        channel_args.SetMaxSendMessageSize(kGrpcMessageLimitBytes);

        for (const auto& peer : peers)
        {
            auto channel = grpc::CreateCustomChannel(
                host::endpoint_to_target(peer),
                grpc::InsecureChannelCredentials(),
                channel_args);
            stubs.push_back(dkg_rpc::PartyNodeRpc::NewStub(channel));
        }

        for (size_t i = 0; i < stubs.size(); ++i)
        {
            grpc::ClientContext context;
            dkg_rpc::KeygenStartRequest request;
            request.set_round_id(round_id);
            request.set_session_id(session_id);
            request.set_preproc_root(preproc_root);
            request.set_output_dir(output_dir);
            dkg_rpc::StartReply reply;
            const grpc::Status status = stubs[i]->StartKeygen(&context, request, &reply);
            if (!status.ok())
            {
                throw std::runtime_error("StartKeygen RPC failed for " + peers[i].host + ": " + status.error_message());
            }
            if (!reply.ok())
            {
                throw std::runtime_error("Party rejected keygen start: " + peers[i].host + ": " + reply.message());
            }
            std::cout << peers[i].host << ": started keygen session " << session_id << std::endl;
        }

        const auto start_time = std::chrono::steady_clock::now();
        auto last_heartbeat = start_time;
        uint64_t next_progress_mark = 5;
        std::string last_stage;
        std::cout << format_keygen_progress_line("starting", 0, 1, std::chrono::steady_clock::duration::zero())
                  << std::endl;

        const auto deadline = start_time + std::chrono::hours(24);
        std::vector<host::StatusSnapshot> snapshots(stubs.size());
        while (std::chrono::steady_clock::now() < deadline)
        {
            bool all_done = true;
            uint64_t min_completed = 0;
            uint64_t total_items = 1;
            std::string stage = "starting";
            bool initialized = false;
            for (size_t i = 0; i < stubs.size(); ++i)
            {
                grpc::ClientContext context;
                dkg_rpc::StatusRequest request;
                request.set_full(false);
                dkg_rpc::StatusReply reply;
                const grpc::Status status = stubs[i]->Status(&context, request, &reply);
                if (!status.ok())
                {
                    throw std::runtime_error("Status RPC failed for " + peers[i].host + ": " + status.error_message());
                }
                snapshots[i] = host::parse_status_proto(reply);
                if (snapshots[i].state.rfind("KEYGEN_FAILED", 0) == 0)
                {
                    throw std::runtime_error("Keygen failed on party " + std::to_string(snapshots[i].party_id) + ": " + snapshots[i].state);
                }
                all_done = all_done && snapshots[i].state == "KEYGEN_DONE";
                const uint64_t party_total = std::max<uint64_t>(snapshots[i].batch_size, 1);
                const uint64_t party_completed = std::min<uint64_t>(snapshots[i].completed_items, party_total);
                if (!initialized || party_completed < min_completed)
                {
                    min_completed = party_completed;
                    total_items = party_total;
                    stage = keygen_stage_from_state(snapshots[i].state);
                    initialized = true;
                }
                else
                {
                    total_items = std::max(total_items, party_total);
                }
            }

            if (all_done)
            {
                min_completed = total_items;
                stage = "done";
            }
            const uint64_t progress = total_items == 0 ? 100 : (min_completed * 100) / total_items;
            const auto now = std::chrono::steady_clock::now();
            if (stage != last_stage)
            {
                std::cout << format_keygen_progress_line(stage, min_completed, total_items, now - start_time)
                          << std::endl;
                last_stage = stage;
                last_heartbeat = now;
            }
            while (next_progress_mark <= 100 && progress >= next_progress_mark)
            {
                const uint64_t display_completed = next_progress_mark == 100 ? total_items : min_completed;
                std::cout << format_keygen_progress_line(stage, display_completed, total_items, now - start_time)
                          << std::endl;
                next_progress_mark += 5;
                last_heartbeat = now;
            }
            if (!all_done && now - last_heartbeat >= std::chrono::seconds(30))
            {
                std::cout << format_keygen_progress_line(stage, min_completed, total_items, now - start_time)
                          << std::endl;
                last_heartbeat = now;
            }

            if (all_done)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        for (size_t i = 0; i < stubs.size(); ++i)
        {
            grpc::ClientContext context;
            dkg_rpc::StatusRequest request;
            request.set_full(false);
            dkg_rpc::StatusReply reply;
            const grpc::Status status = stubs[i]->Status(&context, request, &reply);
            if (!status.ok())
            {
                throw std::runtime_error("Final Status RPC failed for " + peers[i].host + ": " + status.error_message());
            }
            snapshots[i] = host::parse_status_proto(reply);
            if (snapshots[i].state != "KEYGEN_DONE")
            {
                throw std::runtime_error("Keygen did not finish on party " + std::to_string(snapshots[i].party_id));
            }
        }

        std::cout << "Online keygen session " << session_id << " finished successfully." << std::endl;
        for (const auto& snapshot : snapshots)
        {
            std::cout << "party " << snapshot.party_id << ": " << snapshot.state << std::endl;
        }
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}

