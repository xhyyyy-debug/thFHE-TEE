// Controller entry point for the offline preprocessing phase. It plans required
// materials, orchestrates party rounds, and streams signed artifacts to disk.

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "../../enclave/common/noise_types.h"
#include "../config/config.hpp"
#include "../dkg/planner.hpp"
#include "../dkg/preprocessing_artifacts.hpp"
#include "../protocol/grpc_utils.hpp"

namespace
{
constexpr int kGrpcMessageLimitBytes = 512 * 1024 * 1024;
constexpr uint64_t kDefaultPreprocRoundSize = 100000;

enum class Mode
{
    kNoise,
    kBit,
    kTriple,
};

uint64_t parse_u64(const char* text)
{
    return std::stoull(text);
}

host::dkg::PublicSeed derive_seed(uint64_t session_id)
{
    return host::dkg::PublicSeed{
        noise::mix64(session_id ^ 0x50524550524f43ULL),
        noise::mix64((session_id << 1U) ^ 0x4b455947454eULL)
    };
}

std::string done_state(Mode mode)
{
    switch (mode)
    {
    case Mode::kNoise:
        return "DONE";
    case Mode::kBit:
        return "BIT_DONE";
    case Mode::kTriple:
        return "TRIPLE_DONE";
    }
    return "DONE";
}

std::string mode_name(Mode mode)
{
    switch (mode)
    {
    case Mode::kNoise:
        return "noise";
    case Mode::kBit:
        return "bit";
    case Mode::kTriple:
        return "triple";
    }
    return "unknown";
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

std::string format_progress_line(
    const std::string& label,
    uint64_t completed,
    uint64_t total,
    std::chrono::steady_clock::duration elapsed)
{
    const uint64_t percent = total == 0 ? 100 : (completed * 100) / total;
    const auto elapsed_secs = std::chrono::duration_cast<std::chrono::seconds>(elapsed);
    std::ostringstream out;
    out << "[preproc] " << label
        << " generated=" << completed << "/" << total
        << " progress=" << percent << "%";
    out << " elapsed=" << format_duration(elapsed_secs);

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

std::chrono::seconds preprocessing_timeout(Mode mode, uint64_t batch_size)
{
    switch (mode)
    {
    case Mode::kBit:
    case Mode::kTriple:
        return std::chrono::minutes(10);
    case Mode::kNoise:
        if (batch_size >= 1000000)
        {
            return std::chrono::hours(2);
        }
        if (batch_size >= 100000)
        {
            return std::chrono::minutes(30);
        }
        return std::chrono::minutes(10);
    }
    return std::chrono::minutes(10);
}

struct ProgressTracker
{
    bool initialized = false;
    uint64_t next_progress_mark = 5;
    std::chrono::steady_clock::time_point start_time{};
    std::chrono::steady_clock::time_point last_heartbeat{};
};

void start_round(
    Mode mode,
    uint64_t round_id,
    uint64_t batch_size,
    uint32_t noise_bound_bits,
    std::vector<std::unique_ptr<dkg_rpc::PartyNodeRpc::Stub>>& stubs,
    const std::vector<host::Endpoint>& peers)
{
    for (size_t i = 0; i < stubs.size(); ++i)
    {
        grpc::ClientContext context;
        dkg_rpc::StartRequest request;
        request.set_round_id(round_id);
        request.set_batch_size(batch_size);
        request.set_noise_bound_bits(noise_bound_bits);
        dkg_rpc::StartReply reply;
        grpc::Status status;
        switch (mode)
        {
        case Mode::kNoise:
            status = stubs[i]->StartRound(&context, request, &reply);
            break;
        case Mode::kBit:
            status = stubs[i]->StartBitRound(&context, request, &reply);
            break;
        case Mode::kTriple:
            status = stubs[i]->StartTripleRound(&context, request, &reply);
            break;
        }
        if (!status.ok())
        {
            throw std::runtime_error("Start RPC failed for " + peers[i].host + ": " + status.error_message());
        }
        if (!reply.ok())
        {
            throw std::runtime_error("Party rejected preprocessing start: " + peers[i].host + ": " + reply.message());
        }
    }
}

std::vector<host::StatusSnapshot> wait_and_fetch(
    Mode mode,
    uint64_t expected_round_id,
    const std::string& label,
    uint64_t batch_size,
    uint64_t completed_base,
    uint64_t total_size,
    ProgressTracker* tracker,
    std::vector<std::unique_ptr<dkg_rpc::PartyNodeRpc::Stub>>& stubs,
    const std::vector<host::Endpoint>& peers)
{
    if (tracker == nullptr)
    {
        throw std::runtime_error("Progress tracker must not be null");
    }

    const auto timeout = preprocessing_timeout(mode, batch_size);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    const auto round_start = std::chrono::steady_clock::now();
    std::vector<host::StatusSnapshot> snapshots(stubs.size());

    if (!tracker->initialized)
    {
        tracker->initialized = true;
        tracker->start_time = round_start;
        tracker->last_heartbeat = round_start;
        std::cout << format_progress_line(label, 0, total_size, std::chrono::steady_clock::duration::zero())
                  << std::endl;
        std::cout << "[preproc] " << label
                  << " timeout=" << format_duration(std::chrono::duration_cast<std::chrono::seconds>(timeout))
                  << std::endl;
    }

    while (std::chrono::steady_clock::now() < deadline)
    {
        bool all_done = true;
        uint64_t min_completed = batch_size;
        for (size_t i = 0; i < stubs.size(); ++i)
        {
            grpc::ClientContext context;
            dkg_rpc::StatusRequest request;
            request.set_full(false);
            dkg_rpc::StatusReply reply;
            const auto status = stubs[i]->Status(&context, request, &reply);
            if (!status.ok())
            {
                throw std::runtime_error("Status RPC failed for " + peers[i].host + ": " + status.error_message());
            }
            snapshots[i] = host::parse_status_proto(reply);
            if (snapshots[i].state == "ERROR")
            {
                throw std::runtime_error("Preprocessing round failed on party " + std::to_string(snapshots[i].party_id));
            }
            all_done = all_done &&
                snapshots[i].round_id == expected_round_id &&
                snapshots[i].state == done_state(mode) &&
                snapshots[i].completed_items == batch_size;
            if (snapshots[i].round_id != expected_round_id)
            {
                min_completed = std::min<uint64_t>(min_completed, 0);
            }
            else
            {
                min_completed = std::min(min_completed, snapshots[i].completed_items);
            }
        }

        const uint64_t effective_completed = completed_base + min_completed;
        const uint64_t progress = total_size == 0 ? 100 : (effective_completed * 100) / total_size;
        while (tracker->next_progress_mark <= 100 && progress >= tracker->next_progress_mark)
        {
            const uint64_t display_completed =
                (tracker->next_progress_mark == 100) ? total_size : effective_completed;
            std::cout << format_progress_line(
                label,
                display_completed,
                total_size,
                std::chrono::steady_clock::now() - tracker->start_time)
                      << std::endl;
            tracker->next_progress_mark += 5;
            tracker->last_heartbeat = std::chrono::steady_clock::now();
        }

        const auto now = std::chrono::steady_clock::now();
        if (!all_done && now - tracker->last_heartbeat >= std::chrono::seconds(30))
        {
            std::cout << format_progress_line(
                label,
                effective_completed,
                total_size,
                now - tracker->start_time)
                      << std::endl;
            tracker->last_heartbeat = now;
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
        request.set_full(true);
        dkg_rpc::StatusReply reply;
        const auto status = stubs[i]->Status(&context, request, &reply);
        if (!status.ok())
        {
            throw std::runtime_error("Status(full) RPC failed for " + peers[i].host + ": " + status.error_message());
        }
        snapshots[i] = host::parse_status_proto(reply);
        if (snapshots[i].round_id != expected_round_id ||
            snapshots[i].state != done_state(mode) ||
            snapshots[i].completed_items != batch_size)
        {
            throw std::runtime_error("Preprocessing round did not finish on party " + std::to_string(snapshots[i].party_id));
        }
    }

    if (completed_base + batch_size >= total_size && tracker->next_progress_mark <= 100)
    {
        std::cout << format_progress_line(
            label,
            total_size,
            total_size,
            std::chrono::steady_clock::now() - tracker->start_time)
                  << std::endl;
        tracker->next_progress_mark = 105;
    }

    return snapshots;
}

void append_bits(
    std::vector<host::dkg::PreprocessingStreamWriter>* writers,
    const std::vector<host::StatusSnapshot>& snapshots,
    uint64_t batch_size,
    std::string* error_message)
{
    for (uint64_t item = 0; item < batch_size; ++item)
    {
        for (const auto& snapshot : snapshots)
        {
            host::dkg::SharedBitVector bit;
            bit.round_id = snapshot.bits[item].round_id;
            bit.sigma = snapshot.bits[item].sigma;
            bit.shares.push_back(algebra::RingShare{
                snapshot.party_id,
                noise::ring_from_raw(snapshot.bits[item].b)
            });
            if (!(*writers)[snapshot.party_id - 1].write_raw_bit(bit, error_message))
            {
                throw std::runtime_error(error_message != nullptr ? *error_message : "Failed to write preprocessing bit");
            }
        }
    }
}

void append_triples(
    std::vector<host::dkg::PreprocessingStreamWriter>* writers,
    const std::vector<host::StatusSnapshot>& snapshots,
    uint64_t batch_size,
    std::string* error_message)
{
    for (uint64_t item = 0; item < batch_size; ++item)
    {
        for (const auto& snapshot : snapshots)
        {
            host::dkg::SharedTripleVector triple;
            triple.round_id = snapshot.triples[item].round_id;
            triple.sigma = snapshot.triples[item].sigma;
            triple.triples.push_back(algebra::RingTripleShare{
                algebra::RingShare{snapshot.party_id, noise::ring_from_raw(snapshot.triples[item].a)},
                algebra::RingShare{snapshot.party_id, noise::ring_from_raw(snapshot.triples[item].b)},
                algebra::RingShare{snapshot.party_id, noise::ring_from_raw(snapshot.triples[item].c)}
            });
            if (!(*writers)[snapshot.party_id - 1].write_triple(triple, error_message))
            {
                throw std::runtime_error(error_message != nullptr ? *error_message : "Failed to write preprocessing triple");
            }
        }
    }
}

void append_noises(
    std::vector<host::dkg::PreprocessingStreamWriter>* writers,
    const std::vector<host::StatusSnapshot>& snapshots,
    uint64_t batch_size,
    host::dkg::NoiseKind kind,
    uint32_t bound_bits,
    std::string* error_message)
{
    for (uint64_t item = 0; item < batch_size; ++item)
    {
        for (const auto& snapshot : snapshots)
        {
            host::dkg::SharedNoiseVector noise_batch;
            noise_batch.kind = kind;
            noise_batch.bound_bits = bound_bits;
            noise_batch.round_id = snapshot.aggregates[item].round_id;
            noise_batch.sigma = snapshot.aggregates[item].sigma;
            noise_batch.shares.push_back(algebra::RingShare{
                snapshot.party_id,
                noise::ring_from_raw(snapshot.aggregates[item].y)
            });
            if (!(*writers)[snapshot.party_id - 1].write_noise(noise_batch, error_message))
            {
                throw std::runtime_error(error_message != nullptr ? *error_message : "Failed to write preprocessing noise");
            }
        }
    }
}
} // namespace

int main(int argc, const char* argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: preprocessing_controller <session_id> <config_path> <output_dir>" << std::endl;
        return 1;
    }

    try
    {
        const uint64_t session_id = parse_u64(argv[1]);
        const host::RuntimeConfig config = host::load_runtime_config(argv[2]);
        const std::string output_dir = argv[3];
        const host::dkg::DkgPlan plan = host::dkg::build_plan(config);

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

        size_t total_noise_count = 0;
        for (const auto& info : plan.preprocessing.noise_batches)
        {
            total_noise_count += info.amount;
        }

        const host::dkg::PublicSeed preproc_seed = derive_seed(session_id);
        const std::string session_root = host::dkg::PreprocessingArtifactStore::session_dir(output_dir, std::to_string(session_id));
        std::filesystem::create_directories(session_root);

        std::vector<host::dkg::PreprocessingStreamWriter> writers(peers.size());
        std::string error_message;
        for (size_t i = 0; i < writers.size(); ++i)
        {
            const std::filesystem::path party_dir = std::filesystem::path(session_root) / ("party_" + std::to_string(i + 1));
            std::filesystem::create_directories(party_dir);
            {
                std::ofstream meta(party_dir / "meta.txt");
                if (!meta)
                {
                    throw std::runtime_error("Failed to write preprocessing meta");
                }
                meta << "preset=" << plan.params.preset_name << "\n";
                meta << "keyset_mode=" << host::dkg::to_string(plan.params.keyset_mode) << "\n";
                meta << "seed_low=" << preproc_seed.low << "\n";
                meta << "seed_high=" << preproc_seed.high << "\n";
                meta << "raw_secret_bits=" << plan.preprocessing.raw_secret_bits << "\n";
                meta << "total_triples=" << plan.preprocessing.total_triples << "\n";
            }
            if (!writers[i].open(
                    (party_dir / "preprocessing.bin").string(),
                    plan,
                    preproc_seed,
                    plan.preprocessing.raw_secret_bits,
                    total_noise_count,
                    plan.preprocessing.total_triples,
                    &error_message))
            {
                throw std::runtime_error(error_message);
            }
        }
        uint64_t round_id = session_id * 1000ULL + 1ULL;
        const auto overall_start = std::chrono::steady_clock::now();
        const uint64_t round_size = kDefaultPreprocRoundSize;

        if (plan.preprocessing.raw_secret_bits != 0)
        {
            std::cout << "[preproc] starting bit total=" << plan.preprocessing.raw_secret_bits << std::endl;
            ProgressTracker progress;
            for (uint64_t completed = 0; completed < plan.preprocessing.raw_secret_bits; completed += round_size)
            {
                const uint64_t current_size = std::min<uint64_t>(round_size, plan.preprocessing.raw_secret_bits - completed);
                start_round(Mode::kBit, round_id, current_size, 0, stubs, peers);
                append_bits(
                    &writers,
                    wait_and_fetch(
                        Mode::kBit,
                        round_id,
                        "bit",
                        current_size,
                        completed,
                        plan.preprocessing.raw_secret_bits,
                        &progress,
                        stubs,
                        peers),
                    current_size,
                    &error_message);
                round_id += 1;
            }
        }

        for (const host::dkg::NoiseInfo& info : plan.preprocessing.noise_batches)
        {
            if (info.amount == 0)
            {
                continue;
            }
            std::ostringstream label;
            label << mode_name(Mode::kNoise) << "(" << host::dkg::to_string(info.kind)
                  << ",bound=" << info.bound_bits << ")";
            std::cout << "[preproc] starting " << label.str()
                      << " total=" << info.amount << std::endl;
            ProgressTracker progress;
            for (uint64_t completed = 0; completed < info.amount; completed += round_size)
            {
                const uint64_t current_size = std::min<uint64_t>(round_size, info.amount - completed);
                start_round(Mode::kNoise, round_id, current_size, info.bound_bits, stubs, peers);
                append_noises(
                    &writers,
                    wait_and_fetch(
                        Mode::kNoise,
                        round_id,
                        label.str(),
                        current_size,
                        completed,
                        info.amount,
                        &progress,
                        stubs,
                        peers),
                    current_size,
                    info.kind,
                    info.bound_bits,
                    &error_message);
                round_id += 1;
            }
        }

        if (plan.preprocessing.total_triples != 0)
        {
            std::cout << "[preproc] starting triple total=" << plan.preprocessing.total_triples << std::endl;
            ProgressTracker progress;
            for (uint64_t completed = 0; completed < plan.preprocessing.total_triples; completed += round_size)
            {
                const uint64_t current_size = std::min<uint64_t>(round_size, plan.preprocessing.total_triples - completed);
                start_round(Mode::kTriple, round_id, current_size, 0, stubs, peers);
                append_triples(
                    &writers,
                    wait_and_fetch(
                        Mode::kTriple,
                        round_id,
                        "triple",
                        current_size,
                        completed,
                        plan.preprocessing.total_triples,
                        &progress,
                        stubs,
                        peers),
                    current_size,
                    &error_message);
                round_id += 1;
            }
        }

        for (auto& writer : writers)
        {
            if (!writer.close(&error_message))
            {
                throw std::runtime_error(error_message);
            }
        }

        const auto total_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - overall_start);
        std::cout << "[preproc] all materials finished"
                  << " total_elapsed=" << format_duration(total_elapsed)
                  << std::endl;
        std::cout << "Saved preprocessing session " << session_id
                  << " to " << session_root
                  << std::endl;
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}

