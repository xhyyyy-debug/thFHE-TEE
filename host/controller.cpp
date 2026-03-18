#include <chrono>
#include <iostream>
#include <sstream>
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

bool verify_enabled()
{
    const char* env = std::getenv("NOISE_VERIFY");
    if (env == nullptr)
    {
        return true;
    }
    return std::string(env) != "0";
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
} // namespace

int main(int argc, const char* argv[])
{
    if (const char* env = std::getenv("NOISE_DEBUG_ARGS"); env != nullptr && std::string(env) == "1")
    {
        std::cerr << "Args(" << argc << "):";
        for (int i = 0; i < argc; ++i)
        {
            std::cerr << " [" << i << "]=" << (argv[i] ? argv[i] : "");
        }
        std::cerr << std::endl;
    }

    if (argc < 3)
    {
        std::cerr << "Usage: noise_ctl <round_id> <config_path>" << std::endl;
        std::cerr << "   or: noise_ctl <round_id> <batch_size> <config_path>" << std::endl;
        std::cerr << "   or: noise_ctl <round_id> <total_size> <batch_size> <config_path>" << std::endl;
        return 1;
    }

    try
    {
        const uint64_t round_id = parse_u64(argv[1]);
        uint64_t total_size = 0;
        uint64_t batch_size = 0;
        const char* config_path = nullptr;

        if (argc >= 5)
        {
            total_size = parse_u64(argv[2]);
            batch_size = parse_u64(argv[3]);
            config_path = argv[4];
        }
        else if (argc == 4)
        {
            total_size = parse_u64(argv[2]);
            batch_size = total_size;
            config_path = argv[3];
        }
        else
        {
            config_path = argv[2];
        }

        const auto config = host::load_runtime_config(config_path);

        if (batch_size == 0)
        {
            batch_size = config.noise_degree;
            total_size = batch_size;
        }
        else if (total_size == 0)
        {
            total_size = batch_size;
        }

        const uint64_t party_count = config.party_count;
        const uint64_t threshold = config.threshold;
        const auto peers = host::endpoints_from_config(config);

        const uint64_t total_batches = (total_size + batch_size - 1) / batch_size;
        const auto overall_start = std::chrono::steady_clock::now();
        uint64_t completed_total = 0;

        std::vector<host::StatusSnapshot> snapshots(party_count);
        bool overall_success = true;

        for (uint64_t batch_index = 0; batch_index < total_batches; ++batch_index)
        {
            const uint64_t current_size = std::min(batch_size, total_size - completed_total);
            const uint64_t current_round = round_id + batch_index;
            const auto monitor_start = std::chrono::steady_clock::now();
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
            uint64_t next_generation_mark = 5;

            std::cout << "Starting batch " << (batch_index + 1) << "/" << total_batches
                      << " round_id=" << current_round
                      << " batch_size=" << current_size
                      << std::endl;

            for (const auto& peer : peers)
            {
                const std::string reply = host::request_reply(peer, host::build_start_message(current_round, current_size));
                std::cout << peer.host << ": " << reply << std::endl;
            }

            while (std::chrono::steady_clock::now() < deadline)
            {
                bool all_done = true;
                uint64_t min_completed = current_size;
                for (size_t i = 0; i < peers.size(); ++i)
                {
                    const std::string reply = host::request_reply(peers[i], host::build_status_request());
                    if (!host::parse_status_response(reply, &snapshots[i]))
                    {
                        throw std::runtime_error("Invalid status reply from " + peers[i].host + ": " + reply);
                    }

                    all_done = all_done && snapshots[i].state == "DONE" && snapshots[i].completed_items == current_size;
                    min_completed = std::min(min_completed, snapshots[i].completed_items);
                }

                const uint64_t percent = (min_completed * 100) / current_size;
                if (percent >= next_generation_mark || all_done)
                {
                    const auto now = std::chrono::steady_clock::now();
                    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - monitor_start);
                    std::chrono::seconds eta(0);
                    if (min_completed > 0 && elapsed.count() > 0)
                    {
                        const auto total_est = (elapsed.count() * current_size) / min_completed;
                        const auto remain = total_est > elapsed.count() ? total_est - elapsed.count() : 0;
                        eta = std::chrono::seconds(remain);
                    }

                    std::cout << "Generation " << percent << "% (" << min_completed << "/" << current_size << ")"
                              << " elapsed=" << format_duration(elapsed)
                              << " eta=" << format_duration(eta)
                              << std::endl;

                    while (next_generation_mark <= percent)
                    {
                        next_generation_mark += 5;
                    }
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
                if (snapshot.state != "DONE" || snapshot.completed_items != current_size)
                {
                    std::cerr << "Round did not complete on all parties." << std::endl;
                    return 2;
                }
            }

            bool success = true;
            if (verify_enabled())
            {
                for (size_t i = 0; i < peers.size(); ++i)
                {
                    const std::string reply = host::request_reply(peers[i], host::build_status_request_full());
                    if (!host::parse_status_response(reply, &snapshots[i]))
                    {
                        throw std::runtime_error("Invalid status reply from " + peers[i].host + ": " + reply);
                    }
                }

                const auto verify_start = std::chrono::steady_clock::now();
                uint64_t next_progress_mark = 5;
                for (uint64_t item = 0; item < current_size; ++item)
                {
                    std::vector<noise::SharePoint> aggregate_shares;
                    aggregate_shares.reserve(threshold + 1);
                    noise::RingElementRaw expected_noise{};

                    for (size_t i = 0; i < snapshots.size(); ++i)
                    {
                        if (snapshots[i].local_secrets.size() != current_size || snapshots[i].aggregates.size() != current_size)
                        {
                            throw std::runtime_error("Incomplete batch results from party " + std::to_string(snapshots[i].party_id));
                        }

                        expected_noise = noise::ring_add(expected_noise, snapshots[i].local_secrets[item]);
                        if (aggregate_shares.size() < threshold + 1)
                        {
                            aggregate_shares.push_back(snapshots[i].aggregates[item]);
                        }
                    }

                    const noise::RingElementRaw reconstructed = noise::ProgMPCHandler::reconstruct_secret(
                        aggregate_shares.data(),
                        aggregate_shares.size());
                    const bool item_success = noise::ring_equal(reconstructed, expected_noise);
                    success = success && item_success;

                    const uint64_t completed = item + 1;
                    const uint64_t percent = (completed * 100) / current_size;
                    if (percent >= next_progress_mark || completed == current_size)
                    {
                        const auto now = std::chrono::steady_clock::now();
                        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - verify_start);
                        std::chrono::seconds eta(0);
                        if (completed > 0 && elapsed.count() > 0)
                        {
                            const auto total_est = (elapsed.count() * current_size) / completed;
                            const auto remain = total_est > elapsed.count() ? total_est - elapsed.count() : 0;
                            eta = std::chrono::seconds(remain);
                        }

                        std::cout << "Verify " << percent << "% (" << completed << "/" << current_size << ")"
                                  << " elapsed=" << format_duration(elapsed)
                                  << " eta=" << format_duration(eta)
                                  << std::endl;

                        while (next_progress_mark <= percent)
                        {
                            next_progress_mark += 5;
                        }
                    }
                }

                std::cout << "Batch verification: " << (success ? "SUCCESS" : "FAILED") << std::endl;
            }
            else
            {
                std::cout << "Batch verification: SKIPPED (NOISE_VERIFY=0)" << std::endl;
            }

            overall_success = overall_success && success;
            completed_total += current_size;

            const auto overall_now = std::chrono::steady_clock::now();
            const auto overall_elapsed = std::chrono::duration_cast<std::chrono::seconds>(overall_now - overall_start);
            std::chrono::seconds overall_eta(0);
            if (completed_total > 0 && overall_elapsed.count() > 0)
            {
                const auto total_est = (overall_elapsed.count() * total_size) / completed_total;
                const auto remain = total_est > overall_elapsed.count() ? total_est - overall_elapsed.count() : 0;
                overall_eta = std::chrono::seconds(remain);
            }

            const uint64_t overall_percent = (completed_total * 100) / total_size;
            std::cout << "Overall " << overall_percent << "% (" << completed_total << "/" << total_size << ")"
                      << " elapsed=" << format_duration(overall_elapsed)
                      << " eta=" << format_duration(overall_eta)
                      << std::endl;
        }

        return overall_success ? 0 : 3;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}
