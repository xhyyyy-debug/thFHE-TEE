#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "../enclave/prog_mpc.h"
#include "config.hpp"
#include "control_protocol.hpp"
#include "network.hpp"

namespace
{
uint64_t parse_u64(const char* text)
{
    return std::stoull(text);
}
} // namespace

int main(int argc, const char* argv[])
{
    if (argc < 4)
    {
        std::cerr << "Usage: noise_ctl <round_id> <batch_size> <config_path>" << std::endl;
        return 1;
    }

    try
    {
        const uint64_t round_id = parse_u64(argv[1]);
        const uint64_t batch_size = parse_u64(argv[2]);
        const auto config = host::load_runtime_config(argv[3]);
        const uint64_t party_count = config.party_count;
        const uint64_t threshold = config.threshold;
        const auto peers = host::endpoints_from_config(config);

        for (const auto& peer : peers)
        {
            const std::string reply = host::request_reply(peer, host::build_start_message(round_id, batch_size));
            std::cout << peer.host << ": " << reply << std::endl;
        }

        std::vector<host::StatusSnapshot> snapshots(party_count);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);

        while (std::chrono::steady_clock::now() < deadline)
        {
            bool all_done = true;
            for (size_t i = 0; i < peers.size(); ++i)
            {
                const std::string reply = host::request_reply(peers[i], host::build_status_request());
                if (!host::parse_status_response(reply, &snapshots[i]))
                {
                    throw std::runtime_error("Invalid status reply from " + peers[i].host + ": " + reply);
                }

                all_done = all_done && snapshots[i].state == "DONE" && snapshots[i].completed_items == batch_size;
            }

            if (all_done)
            {
                break;
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        std::cout << "Status summary:" << std::endl;
        for (const auto& snapshot : snapshots)
        {
            std::cout << "  party=" << snapshot.party_id
                      << " state=" << snapshot.state
                      << " completed_items=" << snapshot.completed_items << "/" << snapshot.batch_size
                      << " received_shares=" << snapshot.received_shares << "/" << snapshot.expected_shares
                      << " ack_count=" << snapshot.ack_count
                      << std::endl;
        }

        for (const auto& snapshot : snapshots)
        {
            if (snapshot.state != "DONE" || snapshot.completed_items != batch_size)
            {
                std::cerr << "Round did not complete on all parties." << std::endl;
                return 2;
            }
        }

        bool success = true;
        for (uint64_t item = 0; item < batch_size; ++item)
        {
            std::vector<noise::SharePoint> aggregate_shares;
            aggregate_shares.reserve(threshold + 1);
            uint64_t expected_noise = 0;

            for (size_t i = 0; i < snapshots.size(); ++i)
            {
                if (snapshots[i].local_secrets.size() != batch_size || snapshots[i].aggregates.size() != batch_size)
                {
                    throw std::runtime_error("Incomplete batch results from party " + std::to_string(snapshots[i].party_id));
                }

                expected_noise = noise::mod_add(expected_noise, snapshots[i].local_secrets[item]);
                if (aggregate_shares.size() < threshold + 1)
                {
                    aggregate_shares.push_back(snapshots[i].aggregates[item]);
                }
            }

            const uint64_t reconstructed = noise::ProgMPCHandler::reconstruct_secret(
                aggregate_shares.data(),
                aggregate_shares.size());
            const bool item_success = reconstructed == expected_noise;
            success = success && item_success;

            std::cout << "Batch item " << item
                      << ": reconstructed=" << reconstructed
                      << " expected=" << expected_noise
                      << " verification=" << (item_success ? "SUCCESS" : "FAILED")
                      << std::endl;
        }

        std::cout << "Batch verification: " << (success ? "SUCCESS" : "FAILED") << std::endl;
        return success ? 0 : 3;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}
