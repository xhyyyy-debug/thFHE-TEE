#include <chrono>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "../config/config.hpp"
#include "../protocol/grpc_utils.hpp"

namespace
{
uint64_t parse_u64(const char* text)
{
    return std::stoull(text);
}
}

int main(int argc, const char* argv[])
{
    if (argc != 6)
    {
        std::cerr << "Usage: noise_keygen <round_id> <session_id> <config_path> <preproc_root> <output_dir>" << std::endl;
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
        std::vector<std::unique_ptr<noise_rpc::NoiseParty::Stub>> stubs;
        stubs.reserve(peers.size());
        grpc::ChannelArguments channel_args;
        channel_args.SetMaxReceiveMessageSize(64 * 1024 * 1024);
        channel_args.SetMaxSendMessageSize(64 * 1024 * 1024);

        for (const auto& peer : peers)
        {
            auto channel = grpc::CreateCustomChannel(
                host::endpoint_to_target(peer),
                grpc::InsecureChannelCredentials(),
                channel_args);
            stubs.push_back(noise_rpc::NoiseParty::NewStub(channel));
        }

        for (size_t i = 0; i < stubs.size(); ++i)
        {
            grpc::ClientContext context;
            noise_rpc::KeygenStartRequest request;
            request.set_round_id(round_id);
            request.set_session_id(session_id);
            request.set_preproc_root(preproc_root);
            request.set_output_dir(output_dir);
            noise_rpc::StartReply reply;
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

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(10);
        std::vector<host::StatusSnapshot> snapshots(stubs.size());
        while (std::chrono::steady_clock::now() < deadline)
        {
            bool all_done = true;
            for (size_t i = 0; i < stubs.size(); ++i)
            {
                grpc::ClientContext context;
                noise_rpc::StatusRequest request;
                request.set_full(false);
                noise_rpc::StatusReply reply;
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
            noise_rpc::StatusRequest request;
            request.set_full(false);
            noise_rpc::StatusReply reply;
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
