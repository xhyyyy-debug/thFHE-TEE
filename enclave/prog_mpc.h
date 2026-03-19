#ifndef PROG_MPC_H
#define PROG_MPC_H

#include <array>
#include <cstddef>
#include <cstdint>

#include "../algebra/galois_ring.hpp"
#include "../algebra/shamir_ring.hpp"

namespace noise
{
constexpr size_t kMaxParties = 16;
constexpr size_t kMaxParallelBatch = 2048;
constexpr uint32_t kDefaultNoiseBoundBits = 8;

using RingElement = algebra::ResiduePolyF4Z128;

struct Z128Raw
{
    uint64_t lo;
    uint64_t hi;
};

struct RingElementRaw
{
    Z128Raw coeffs[4];
};

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
    uint64_t share_x;
    RingElementRaw share_y;
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
    uint64_t x;
    RingElementRaw y;
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

inline RingElementRaw ring_add(const RingElementRaw& lhs, const RingElementRaw& rhs)
{
    RingElement a{};
    RingElement b{};
    for (size_t i = 0; i < 4; ++i)
    {
        a.coefs[i] = algebra::Z128(lhs.coeffs[i].lo, lhs.coeffs[i].hi);
        b.coefs[i] = algebra::Z128(rhs.coeffs[i].lo, rhs.coeffs[i].hi);
    }
    const RingElement c = a + b;
    RingElementRaw out{};
    for (size_t i = 0; i < 4; ++i)
    {
        out.coeffs[i].lo = c.coefs[i].lo;
        out.coeffs[i].hi = c.coefs[i].hi;
    }
    return out;
}

inline bool ring_equal(const RingElementRaw& lhs, const RingElementRaw& rhs)
{
    for (size_t i = 0; i < 4; ++i)
    {
        if (lhs.coeffs[i].lo != rhs.coeffs[i].lo || lhs.coeffs[i].hi != rhs.coeffs[i].hi)
        {
            return false;
        }
    }
    return true;
}

class ProgMPCHandler
{
public:
    ProgMPCHandler()
    {
        reset_state();
    }

    int init(uint64_t party_id, uint64_t party_count, uint64_t threshold, uint32_t noise_bound_bits)
    {
        if (party_id == 0 || party_count == 0 || party_count > kMaxParties || threshold >= party_count)
        {
            return kInvalidArgument;
        }

        if (noise_bound_bits == 0 || noise_bound_bits > 126)
        {
            return kInvalidArgument;
        }

        id_ = party_id;
        n_ = party_count;
        t_ = threshold;
        noise_bound_bits_ = noise_bound_bits;
        prng_state_ = mix64((party_id << 32U) ^ party_count ^ (threshold << 8U) ^ 0x6e6f697365ULL);
        clear_round();
        return kOk;
    }

    int sharegen(uint64_t round_id, SharePackage* packages, size_t package_count, RingElementRaw* sampled_secret)
    {
        return sharegen_batch(&round_id, 1, packages, package_count, sampled_secret);
    }

    int sharegen_batch(
        const uint64_t* round_ids,
        size_t batch_count,
        SharePackage* packages,
        size_t package_count,
        RingElementRaw* sampled_secrets)
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

        bool round_mismatch = false;
        if (active_batch_count_ == 0)
        {
            begin_batch(round_ids, batch_count);
        }
        else
        {
            if (active_batch_count_ != batch_count)
            {
                round_mismatch = true;
            }
            else
            {
                for (size_t i = 0; i < batch_count; ++i)
                {
                    if (active_round_ids_[i] != round_ids[i])
                    {
                        round_mismatch = true;
                        break;
                    }
                }
            }

            if (round_mismatch)
            {
                bool any_received = false;
                for (size_t i = 0; i < kMaxParallelBatch && !any_received; ++i)
                {
                    for (size_t j = 0; j < n_; ++j)
                    {
                        if (received_mask_[i][j])
                        {
                            any_received = true;
                            break;
                        }
                    }
                }

                if (any_received)
                {
                    return kInvalidArgument;
                }

                begin_batch(round_ids, batch_count);
            }
        }
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

        auto begin_from_shares = [&](size_t count) {
            std::array<uint64_t, kMaxParallelBatch> round_ids{};
            for (size_t i = 0; i < count; ++i)
            {
                round_ids[i] = shares[i].round_id;
            }
            begin_batch(round_ids.data(), count);
        };

        if (active_batch_count_ == 0)
        {
            begin_from_shares(batch_count);
        }

        bool round_mismatch = false;
        if (active_batch_count_ != batch_count)
        {
            round_mismatch = true;
        }
        else
        {
            for (size_t i = 0; i < batch_count; ++i)
            {
                if (active_round_ids_[i] != shares[i].round_id)
                {
                    round_mismatch = true;
                    break;
                }
            }
        }

        if (round_mismatch)
        {
            bool any_received = false;
            for (size_t i = 0; i < kMaxParallelBatch && !any_received; ++i)
            {
                for (size_t j = 0; j < n_; ++j)
                {
                    if (received_mask_[i][j])
                    {
                        any_received = true;
                        break;
                    }
                }
            }

            if (any_received)
            {
                return kInvalidArgument;
            }

            begin_from_shares(batch_count);
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

            RingElement element{};
            for (size_t j = 0; j < 4; ++j)
            {
                element.coefs[j] = algebra::Z128(share.share_y.coeffs[j].lo, share.share_y.coeffs[j].hi);
            }
            stored_shares_[i][share.sender_id - 1] = element;
            received_mask_[i][share.sender_id - 1] = true;

            acks[i].round_id = share.round_id;
            acks[i].acking_party = id_;
            acks[i].for_sender = share.sender_id;
            acks[i].accepted = 1;
            acks[i].sigma = sign_ack(share.round_id, id_, share.sender_id);
        }

        return kOk;
    }

    int done(SharePoint* aggregate)
    {
        if (aggregate == nullptr)
        {
            return kInvalidArgument;
        }

        return done_batch(aggregate, 1);
    }

    int done_batch(SharePoint* aggregates, size_t batch_count)
    {
        if (aggregates == nullptr || batch_count == 0 || batch_count > active_batch_count_)
        {
            return kInvalidArgument;
        }

        for (size_t batch_index = 0; batch_index < batch_count; ++batch_index)
        {
            size_t received = 0;
            RingElement total = RingElement::zero();
            for (size_t party_index = 0; party_index < n_; ++party_index)
            {
                if (received_mask_[batch_index][party_index])
                {
                    ++received;
                    total = total + stored_shares_[batch_index][party_index];
                }
            }

            if (received < n_)
            {
                return kInsufficientShares;
            }

            aggregates[batch_index].x = id_;
            for (size_t j = 0; j < 4; ++j)
            {
                aggregates[batch_index].y.coeffs[j].lo = total.coefs[j].lo;
                aggregates[batch_index].y.coeffs[j].hi = total.coefs[j].hi;
            }
        }

        clear_round();
        return kOk;
    }

    RingElementRaw last_secret() const
    {
        return last_secret_;
    }

    static bool verify_ack(const AckMessage& ack)
    {
        return ack.accepted == 1 && ack.sigma == sign_ack(ack.round_id, ack.acking_party, ack.for_sender);
    }

    static RingElementRaw reconstruct_secret(const SharePoint* shares, size_t share_count)
    {
        std::vector<algebra::RingShare> ring_shares;
        ring_shares.reserve(share_count);
        for (size_t i = 0; i < share_count; ++i)
        {
            RingElement element{};
            for (size_t j = 0; j < 4; ++j)
            {
                element.coefs[j] = algebra::Z128(shares[i].y.coeffs[j].lo, shares[i].y.coeffs[j].hi);
            }
            ring_shares.push_back(algebra::RingShare{shares[i].x, element});
        }

        RingElement reconstructed{};
        if (!algebra::ShamirRing::reconstruct(ring_shares, &reconstructed))
        {
            return RingElementRaw{};
        }

        RingElementRaw out{};
        for (size_t i = 0; i < 4; ++i)
        {
            out.coeffs[i].lo = reconstructed.coefs[i].lo;
            out.coeffs[i].hi = reconstructed.coefs[i].hi;
        }
        return out;
    }

private:
    uint64_t id_ = 0;
    uint64_t n_ = 0;
    uint64_t t_ = 0;
    uint32_t noise_bound_bits_ = kDefaultNoiseBoundBits;
    size_t active_batch_count_ = 0;
    uint64_t prng_state_ = 0;
    RingElementRaw last_secret_{};
    std::array<uint64_t, kMaxParallelBatch> active_round_ids_{};
    std::array<std::array<RingElement, kMaxParties>, kMaxParallelBatch> stored_shares_{};
    std::array<std::array<bool, kMaxParties>, kMaxParallelBatch> received_mask_{};

    void reset_state()
    {
        id_ = 0;
        n_ = 0;
        t_ = 0;
        active_batch_count_ = 0;
        prng_state_ = 0;
        last_secret_ = RingElementRaw{};
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
        last_secret_ = RingElementRaw{};
        for (size_t i = 0; i < kMaxParallelBatch; ++i)
        {
            for (size_t j = 0; j < kMaxParties; ++j)
            {
                stored_shares_[i][j] = RingElement::zero();
            }
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

    algebra::Z128 make_z128_from_u64(uint64_t lo, uint64_t hi) const
    {
        return algebra::Z128(lo, hi);
    }

    algebra::Z128 z128_mask(uint32_t bits) const
    {
        if (bits >= 128)
        {
            return algebra::Z128::max();
        }
        if (bits == 0)
        {
            return algebra::Z128::zero();
        }
        if (bits < 64)
        {
            return algebra::Z128((1ULL << bits) - 1ULL, 0);
        }
        return algebra::Z128(~0ULL, (1ULL << (bits - 64)) - 1ULL);
    }

    algebra::Z128 z128_pow2(uint32_t bits) const
    {
        if (bits >= 128)
        {
            return algebra::Z128::zero();
        }
        if (bits < 64)
        {
            return algebra::Z128(1ULL << bits, 0);
        }
        return algebra::Z128(0, 1ULL << (bits - 64));
    }

    algebra::Z128 z128_and(const algebra::Z128& lhs, const algebra::Z128& rhs) const
    {
        return algebra::Z128(lhs.lo & rhs.lo, lhs.hi & rhs.hi);
    }

    algebra::Z128 z128_shr1(const algebra::Z128& value) const
    {
        const uint64_t lo = (value.lo >> 1U) | (value.hi << 63U);
        const uint64_t hi = value.hi >> 1U;
        return algebra::Z128(lo, hi);
    }

    bool z128_eq(const algebra::Z128& lhs, const algebra::Z128& rhs) const
    {
        return lhs.lo == rhs.lo && lhs.hi == rhs.hi;
    }

    algebra::Z128 sample_tuniform_z128()
    {
        const uint32_t range_bits = noise_bound_bits_ + 2;
        const algebra::Z128 mask = z128_mask(range_bits);
        const algebra::Z128 rand = algebra::Z128(next_random(), next_random());
        const algebra::Z128 sample = z128_and(rand, mask);

        const algebra::Z128 zero = algebra::Z128::zero();
        const algebra::Z128 maxv = mask;
        const algebra::Z128 bound_pow2 = z128_pow2(noise_bound_bits_);

        if (z128_eq(sample, zero))
        {
            return zero - bound_pow2;
        }

        if (z128_eq(sample, maxv))
        {
            return bound_pow2;
        }

        algebra::Z128 inner = sample - algebra::Z128::one();
        inner = z128_shr1(inner);
        return (zero - bound_pow2) + algebra::Z128::one() + inner;
    }

    uint64_t hash_ring(const RingElementRaw& value) const
    {
        uint64_t h = 0x9e3779b97f4a7c15ULL;
        for (size_t i = 0; i < 4; ++i)
        {
            h = mix64(h ^ value.coeffs[i].lo);
            h = mix64(h ^ value.coeffs[i].hi);
        }
        return h;
    }

    void generate_share_set(size_t batch_index, SharePackage* packages, RingElementRaw* sampled_secret)
    {
        RingElement secret = RingElement::from_scalar(sample_tuniform_z128());
        const auto shares = algebra::ShamirRing::share(
            secret,
            static_cast<size_t>(n_),
            static_cast<size_t>(t_),
            [this]() {
                return sample_tuniform_z128();
            });

        last_secret_ = RingElementRaw{};
        for (size_t i = 0; i < 4; ++i)
        {
            last_secret_.coeffs[i].lo = secret.coefs[i].lo;
            last_secret_.coeffs[i].hi = secret.coefs[i].hi;
        }
        *sampled_secret = last_secret_;

        for (size_t i = 0; i < n_; ++i)
        {
            const uint64_t receiver_id = static_cast<uint64_t>(i + 1);
            packages[i].round_id = active_round_ids_[batch_index];
            packages[i].sender_id = id_;
            packages[i].receiver_id = receiver_id;
            packages[i].share_x = receiver_id;
            for (size_t j = 0; j < 4; ++j)
            {
                packages[i].share_y.coeffs[j].lo = shares[i].value.coefs[j].lo;
                packages[i].share_y.coeffs[j].hi = shares[i].value.coefs[j].hi;
            }
            packages[i].sigma = sign_share(active_round_ids_[batch_index], id_, receiver_id, packages[i].share_x, packages[i].share_y);
        }
    }

    uint64_t sign_share(uint64_t round_id, uint64_t sender_id, uint64_t receiver_id, uint64_t x, const RingElementRaw& y) const
    {
        const uint64_t h = hash_ring(y);
        return mix64(round_id ^ sender_id ^ (receiver_id << 11U) ^ (x << 19U) ^ (h << 1U) ^ 0x5348415245ULL);
    }

    static uint64_t sign_ack(uint64_t round_id, uint64_t acking_party, uint64_t for_sender)
    {
        return mix64(round_id ^ acking_party ^ (for_sender << 17U) ^ 0x41434bULL);
    }
};
} // namespace noise

#endif
