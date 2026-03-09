#ifndef PROG_MPC_H
#define PROG_MPC_H

#include <array>
#include <cstddef>
#include <cstdint>

#include "../algebra/fields.hpp"
#include "../algebra/shamir.hpp"

namespace noise
{
constexpr algebra::Num kPrimeModulus = 2305843009213693951ULL;
constexpr size_t kMaxParties = 16;
constexpr size_t kMaxParallelBatch = 32;

using Field = algebra::RuntimePrimeField;
using Shamir = algebra::ShamirSecretSharing<kMaxParties, kMaxParties>;
using ShareValue = algebra::Num;

enum StatusCode : int32_t
{
    kOk = 0,
    kInvalidArgument = 1,
    kVerificationFailed = 2,
    kInsufficientShares = 3
};

struct SharePackage
{
    uint64_t round_id;
    uint64_t sender_id;
    uint64_t receiver_id;
    ShareValue share_x;
    ShareValue share_y;
    uint64_t sigma;
};

struct AckMessage
{
    uint64_t round_id;
    uint64_t acking_party;
    uint64_t for_sender;
    uint64_t sigma;
    uint64_t accepted;
};

struct SharePoint
{
    ShareValue x;
    ShareValue y;
};

inline uint64_t mix64(uint64_t value)
{
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31U;
    return value;
}

inline ShareValue mod_add(ShareValue lhs, ShareValue rhs)
{
    static const Field field(kPrimeModulus);
    return field.add(lhs, rhs);
}

class ProgMPCHandler
{
public:
    ProgMPCHandler() : field_(kPrimeModulus)
    {
        reset_state();
    }

    int init(uint64_t party_id, uint64_t party_count, uint64_t threshold)
    {
        if (party_id == 0 || party_count == 0 || party_count > kMaxParties || threshold >= party_count)
        {
            return kInvalidArgument;
        }

        id_ = party_id;
        n_ = party_count;
        t_ = threshold;
        prng_state_ = mix64((party_id << 32U) ^ party_count ^ (threshold << 8U) ^ 0x6e6f697365ULL);
        clear_round();
        return kOk;
    }

    int sharegen(uint64_t round_id, SharePackage* packages, size_t package_count, ShareValue* sampled_secret)
    {
        return sharegen_batch(&round_id, 1, packages, package_count, sampled_secret);
    }

    int sharegen_batch(
        const uint64_t* round_ids,
        size_t batch_count,
        SharePackage* packages,
        size_t package_count,
        ShareValue* sampled_secrets)
    {
        if (round_ids == nullptr || packages == nullptr || sampled_secrets == nullptr)
        {
            return kInvalidArgument;
        }

        if (batch_count == 0 || batch_count > kMaxParallelBatch || package_count < batch_count * n_)
        {
            return kInvalidArgument;
        }

        for (size_t batch_index = 0; batch_index < batch_count; ++batch_index)
        {
            if (round_ids[batch_index] == 0)
            {
                return kInvalidArgument;
            }
        }

        begin_batch(round_ids, batch_count);
        for (size_t batch_index = 0; batch_index < batch_count; ++batch_index)
        {
            generate_share_set(batch_index, packages + (batch_index * n_), sampled_secrets + batch_index);
        }

        return kOk;
    }

    int store(const SharePackage& share, AckMessage* ack)
    {
        if (ack == nullptr)
        {
            return kInvalidArgument;
        }

        return store_batch(&share, 1, ack);
    }

    int store_batch(const SharePackage* shares, size_t batch_count, AckMessage* acks)
    {
        if (shares == nullptr || acks == nullptr || batch_count == 0 || batch_count > kMaxParallelBatch)
        {
            return kInvalidArgument;
        }

        if (active_batch_count_ == 0)
        {
            std::array<uint64_t, kMaxParallelBatch> round_ids{};
            for (size_t i = 0; i < batch_count; ++i)
            {
                round_ids[i] = shares[i].round_id;
            }
            begin_batch(round_ids.data(), batch_count);
        }

        if (active_batch_count_ != batch_count)
        {
            return kInvalidArgument;
        }

        for (size_t i = 0; i < batch_count; ++i)
        {
            const auto& share = shares[i];
            if (share.round_id == 0 || share.round_id != active_round_ids_[i] || share.receiver_id != id_ || share.share_x != id_ || share.sender_id == 0 || share.sender_id > n_)
            {
                return kInvalidArgument;
            }

            if (share.sigma != sign_share(share.round_id, share.sender_id, share.receiver_id, share.share_x, share.share_y))
            {
                return kVerificationFailed;
            }

            stored_shares_[i][share.sender_id - 1] = field_.mod(share.share_y);
            received_mask_[i][share.sender_id - 1] = true;

            acks[i].round_id = share.round_id;
            acks[i].acking_party = id_;
            acks[i].for_sender = share.sender_id;
            acks[i].accepted = 1;
            acks[i].sigma = sign_ack(share.round_id, id_, share.sender_id);
        }

        return kOk;
    }

    int done(SharePoint* aggregate) const
    {
        if (aggregate == nullptr)
        {
            return kInvalidArgument;
        }

        return done_batch(aggregate, 1);
    }

    int done_batch(SharePoint* aggregates, size_t batch_count) const
    {
        if (aggregates == nullptr || batch_count == 0 || batch_count > active_batch_count_)
        {
            return kInvalidArgument;
        }

        for (size_t batch_index = 0; batch_index < batch_count; ++batch_index)
        {
            size_t received = 0;
            ShareValue total = 0;
            for (size_t party_index = 0; party_index < n_; ++party_index)
            {
                if (received_mask_[batch_index][party_index])
                {
                    ++received;
                    total = field_.add(total, stored_shares_[batch_index][party_index]);
                }
            }

            if (received < n_)
            {
                return kInsufficientShares;
            }

            aggregates[batch_index].x = id_;
            aggregates[batch_index].y = total;
        }

        return kOk;
    }

    ShareValue last_secret() const
    {
        return last_secret_;
    }

    static bool verify_ack(const AckMessage& ack)
    {
        return ack.accepted == 1 && ack.sigma == sign_ack(ack.round_id, ack.acking_party, ack.for_sender);
    }

    static ShareValue reconstruct_secret(const SharePoint* shares, size_t share_count)
    {
        static const Field field(kPrimeModulus);

        std::array<Shamir::Share, kMaxParties> shamir_shares{};
        for (size_t i = 0; i < share_count; ++i)
        {
            shamir_shares[i] = {shares[i].x, shares[i].y};
        }

        return Shamir::reconstruct(field, shamir_shares.data(), share_count);
    }

private:
    Field field_;
    uint64_t id_ = 0;
    uint64_t n_ = 0;
    uint64_t t_ = 0;
    size_t active_batch_count_ = 0;
    uint64_t prng_state_ = 0;
    ShareValue last_secret_ = 0;
    std::array<uint64_t, kMaxParallelBatch> active_round_ids_{};
    std::array<std::array<ShareValue, kMaxParties>, kMaxParallelBatch> stored_shares_{};
    std::array<std::array<bool, kMaxParties>, kMaxParallelBatch> received_mask_{};

    void reset_state()
    {
        id_ = 0;
        n_ = 0;
        t_ = 0;
        active_batch_count_ = 0;
        prng_state_ = 0;
        last_secret_ = 0;
        clear_round();
    }

    void begin_batch(const uint64_t* round_ids, size_t batch_count)
    {
        clear_round();
        active_batch_count_ = batch_count;
        for (size_t i = 0; i < batch_count; ++i)
        {
            active_round_ids_[i] = round_ids[i];
        }
    }

    void clear_round()
    {
        active_batch_count_ = 0;
        active_round_ids_.fill(0);
        last_secret_ = 0;
        for (size_t i = 0; i < kMaxParallelBatch; ++i)
        {
            stored_shares_[i].fill(0);
            received_mask_[i].fill(false);
        }
    }

    uint64_t next_random()
    {
        prng_state_ ^= prng_state_ >> 12U;
        prng_state_ ^= prng_state_ << 25U;
        prng_state_ ^= prng_state_ >> 27U;
        return prng_state_ * 2685821657736338717ULL;
    }

    void generate_share_set(size_t batch_index, SharePackage* packages, ShareValue* sampled_secret)
    {
        const ShareValue secret = next_random() % kPrimeModulus;
        const auto shares = Shamir::split(
            field_,
            secret,
            static_cast<size_t>(t_),
            static_cast<size_t>(n_),
            [this]() { return next_random() % kPrimeModulus; });

        last_secret_ = secret;
        *sampled_secret = secret;

        for (size_t i = 0; i < n_; ++i)
        {
            const uint64_t receiver_id = static_cast<uint64_t>(i + 1);
            packages[i].round_id = active_round_ids_[batch_index];
            packages[i].sender_id = id_;
            packages[i].receiver_id = receiver_id;
            packages[i].share_x = shares[i].x;
            packages[i].share_y = shares[i].y;
            packages[i].sigma = sign_share(active_round_ids_[batch_index], id_, receiver_id, shares[i].x, shares[i].y);
        }
    }

    static uint64_t sign_share(uint64_t round_id, uint64_t sender_id, uint64_t receiver_id, ShareValue x, ShareValue y)
    {
        return mix64(round_id ^ sender_id ^ (receiver_id << 11U) ^ (x << 19U) ^ (y << 1U) ^ 0x5348415245ULL);
    }

    static uint64_t sign_ack(uint64_t round_id, uint64_t acking_party, uint64_t for_sender)
    {
        return mix64(round_id ^ acking_party ^ (for_sender << 17U) ^ 0x41434bULL);
    }
};
} // namespace noise

#endif
