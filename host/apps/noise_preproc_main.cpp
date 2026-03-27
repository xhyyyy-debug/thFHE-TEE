#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "../../enclave/prog_mpc.h"
#include "../config/config.hpp"
#include "../dkg/planner.hpp"
#include "../dkg/preprocessing_store.hpp"
#include "../protocol/grpc_utils.hpp"

namespace
{
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

void start_round(
    Mode mode,
    uint64_t round_id,
    uint64_t batch_size,
    uint32_t noise_bound_bits,
    std::vector<std::unique_ptr<noise_rpc::NoiseParty::Stub>>& stubs,
    const std::vector<host::Endpoint>& peers)
{
    for (size_t i = 0; i < stubs.size(); ++i)
    {
        grpc::ClientContext context;
        noise_rpc::StartRequest request;
        request.set_round_id(round_id);
        request.set_batch_size(batch_size);
        request.set_noise_bound_bits(noise_bound_bits);
        noise_rpc::StartReply reply;
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
    const std::string& label,
    uint64_t batch_size,
    std::vector<std::unique_ptr<noise_rpc::NoiseParty::Stub>>& stubs,
    const std::vector<host::Endpoint>& peers)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
    const auto start = std::chrono::steady_clock::now();
    std::vector<host::StatusSnapshot> snapshots(stubs.size());
    uint64_t next_progress_mark = 5;

    while (std::chrono::steady_clock::now() < deadline)
    {
        bool all_done = true;
        uint64_t min_completed = batch_size;
        for (size_t i = 0; i < stubs.size(); ++i)
        {
            grpc::ClientContext context;
            noise_rpc::StatusRequest request;
            request.set_full(false);
            noise_rpc::StatusReply reply;
            const auto status = stubs[i]->Status(&context, request, &reply);
            if (!status.ok())
            {
                throw std::runtime_error("Status RPC failed for " + peers[i].host + ": " + status.error_message());
            }
            snapshots[i] = host::parse_status_proto(reply);
            all_done = all_done &&
                snapshots[i].state == done_state(mode) &&
                snapshots[i].completed_items == batch_size;
            min_completed = std::min(min_completed, snapshots[i].completed_items);
        }

        const uint64_t progress = batch_size == 0 ? 100 : (min_completed * 100) / batch_size;
        while (next_progress_mark <= 100 && progress >= next_progress_mark)
        {
            const uint64_t display_completed = (next_progress_mark == 100) ? batch_size : min_completed;
            std::cout << format_progress_line(
                label,
                display_completed,
                batch_size,
                std::chrono::steady_clock::now() - start)
                      << std::endl;
            next_progress_mark += 5;
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
        request.set_full(true);
        noise_rpc::StatusReply reply;
        const auto status = stubs[i]->Status(&context, request, &reply);
        if (!status.ok())
        {
            throw std::runtime_error("Status(full) RPC failed for " + peers[i].host + ": " + status.error_message());
        }
        snapshots[i] = host::parse_status_proto(reply);
        if (snapshots[i].state != done_state(mode) || snapshots[i].completed_items != batch_size)
        {
            throw std::runtime_error("Preprocessing round did not finish on party " + std::to_string(snapshots[i].party_id));
        }
    }

    return snapshots;
}

void append_bits(
    std::vector<host::dkg::PreprocessedKeygenMaterial>* materials,
    const std::vector<host::StatusSnapshot>& snapshots,
    uint64_t batch_size)
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
            (*materials)[snapshot.party_id - 1].raw_bits.push_back(bit);
        }
    }
}

void append_triples(
    std::vector<host::dkg::PreprocessedKeygenMaterial>* materials,
    const std::vector<host::StatusSnapshot>& snapshots,
    uint64_t batch_size)
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
            (*materials)[snapshot.party_id - 1].triples.push_back(triple);
        }
    }
}

void append_noises(
    std::vector<host::dkg::PreprocessedKeygenMaterial>* materials,
    const std::vector<host::StatusSnapshot>& snapshots,
    uint64_t batch_size,
    host::dkg::NoiseKind kind,
    uint32_t bound_bits)
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
            (*materials)[snapshot.party_id - 1].noises.push_back(noise_batch);
        }
    }
}
} // namespace

int main(int argc, const char* argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: noise_preproc <session_id> <config_path> <output_dir>" << std::endl;
        return 1;
    }

    try
    {
        const uint64_t session_id = parse_u64(argv[1]);
        const host::RuntimeConfig config = host::load_runtime_config(argv[2]);
        const std::string output_dir = argv[3];
        const host::dkg::DkgPlan plan = host::dkg::build_plan(config);

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

        std::vector<host::dkg::PreprocessedKeygenMaterial> materials(peers.size());
        for (auto& material : materials)
        {
            material.seed = derive_seed(session_id);
        }
        uint64_t round_id = session_id * 1000ULL + 1ULL;
        const auto overall_start = std::chrono::steady_clock::now();

        if (plan.preprocessing.raw_secret_bits != 0)
        {
            std::cout << "[preproc] starting bit total=" << plan.preprocessing.raw_secret_bits << std::endl;
            start_round(Mode::kBit, round_id, plan.preprocessing.raw_secret_bits, 0, stubs, peers);
            append_bits(
                &materials,
                wait_and_fetch(Mode::kBit, "bit", plan.preprocessing.raw_secret_bits, stubs, peers),
                plan.preprocessing.raw_secret_bits);
            round_id += 1;
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
            start_round(Mode::kNoise, round_id, info.amount, info.bound_bits, stubs, peers);
            append_noises(
                &materials,
                wait_and_fetch(Mode::kNoise, label.str(), info.amount, stubs, peers),
                info.amount,
                info.kind,
                info.bound_bits);
            round_id += 1;
        }

        if (plan.preprocessing.total_triples != 0)
        {
            std::cout << "[preproc] starting triple total=" << plan.preprocessing.total_triples << std::endl;
            start_round(Mode::kTriple, round_id, plan.preprocessing.total_triples, 0, stubs, peers);
            append_triples(
                &materials,
                wait_and_fetch(Mode::kTriple, "triple", plan.preprocessing.total_triples, stubs, peers),
                plan.preprocessing.total_triples);
        }

        std::string error_message;
        const std::string session_root = host::dkg::PreprocessingStore::session_dir(output_dir, std::to_string(session_id));
        for (size_t i = 0; i < materials.size(); ++i)
        {
            const std::string party_session = "party_" + std::to_string(i + 1);
            if (!host::dkg::PreprocessingStore::save(session_root, party_session, plan, materials[i], &error_message))
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
