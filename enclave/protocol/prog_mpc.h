#ifndef NOISE_PROTOCOL_PROG_MPC_H
#define NOISE_PROTOCOL_PROG_MPC_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <openenclave/enclave.h>

#include "../../algebra/sharing/shamir_ring.hpp"
#include "../common/noise_types.h"
#include "../mpc/bits.h"
#include "../mpc/triples.h"
#include "../prss/state.h"

namespace noise
{
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
        initialize_auth_keys();
        storage_auth_key_ = generate_storage_auth_key();

        const prss::SessionId128 sid{
            mix64((party_id << 40U) ^ (party_count << 16U) ^ threshold ^ 0x50525353ULL),
            mix64((party_id << 20U) ^ (party_count << 4U) ^ (threshold << 48U) ^ 0x50525a53ULL)
        };
        int status = prss_state_.init_fixed(party_id, party_count, threshold, sid);
        if (status != kOk)
        {
            return status;
        }
        status = triple_handler_.init(party_id, party_count, threshold, &prss_state_);
        if (status != kOk)
        {
            return status;
        }
        triple_handler_.set_storage_auth_key(storage_auth_key_);
        status = bit_handler_.init(party_id, party_count, threshold, &prss_state_);
        if (status != kOk)
        {
            return status;
        }
        bit_handler_.set_storage_auth_key(storage_auth_key_);
        return kOk;
    }

    int prss_next(RingElementRaw* out)
    {
        if (out == nullptr)
        {
            return kInvalidArgument;
        }

        RingElement value = RingElement::zero();
        const int status = prss_state_.prss_next(&value);
        if (status != kOk)
        {
            return status;
        }

        *out = raw_from_ring(value);
        return kOk;
    }

    int przs_next(RingElementRaw* out)
    {
        if (out == nullptr)
        {
            return kInvalidArgument;
        }

        RingElement value = RingElement::zero();
        const int status = prss_state_.przs_next(&value);
        if (status != kOk)
        {
            return status;
        }

        *out = raw_from_ring(value);
        return kOk;
    }

    int sharegen(uint64_t round_id, SharePackage* packages, size_t package_count, RingElementRaw* sampled_secret)
    {
        return sharegen_batch_with_bound(&round_id, 1, packages, package_count, sampled_secret, noise_bound_bits_);
    }

    int sharegen_batch(
        const uint64_t* round_ids,
        size_t batch_count,
        SharePackage* packages,
        size_t package_count,
        RingElementRaw* sampled_secrets)
    {
        return sharegen_batch_with_bound(
            round_ids,
            batch_count,
            packages,
            package_count,
            sampled_secrets,
            noise_bound_bits_);
    }

    int sharegen_batch_with_bound(
        const uint64_t* round_ids,
        size_t batch_count,
        SharePackage* packages,
        size_t package_count,
        RingElementRaw* sampled_secrets,
        uint32_t noise_bound_bits)
    {
        if (round_ids == nullptr || packages == nullptr || sampled_secrets == nullptr)
        {
            return kInvalidArgument;
        }

        if (batch_count == 0 || batch_count > kMaxParallelBatch || package_count < batch_count * n_)
        {
            return kInvalidArgument;
        }

        if (noise_bound_bits == 0 || noise_bound_bits > 126)
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
            generate_share_set(
                batch_index,
                packages + (batch_index * n_),
                sampled_secrets + batch_index,
                noise_bound_bits);
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

            stored_shares_[i][share.sender_id - 1] = ring_from_raw(share.share_y);
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

            aggregates[batch_index].round_id = active_round_ids_[batch_index];
            aggregates[batch_index].x = id_;
            aggregates[batch_index].y = raw_from_ring(total);
            aggregates[batch_index].sigma = sign_noise_output(
                active_round_ids_[batch_index],
                id_,
                aggregates[batch_index].x,
                aggregates[batch_index].y);
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
            ring_shares.push_back(algebra::RingShare{shares[i].x, ring_from_raw(shares[i].y)});
        }

        RingElement reconstructed{};
        if (!algebra::ShamirRing::reconstruct(ring_shares, &reconstructed))
        {
            return RingElementRaw{};
        }

        return raw_from_ring(reconstructed);
    }

    int triple_generate_batch(
        const uint64_t* round_ids,
        size_t batch_count,
        TripleDPackage* packages,
        size_t package_count)
    {
        return triple_handler_.generate_batch(round_ids, batch_count, packages, package_count);
    }

    int triple_store_batch(const TripleDPackage* packages, size_t batch_count)
    {
        return triple_handler_.store_batch(packages, batch_count);
    }

    int triple_done_batch(TripleShare* triples, size_t batch_count)
    {
        return triple_handler_.done_batch(triples, batch_count);
    }

    int bit_generate_batch(
        const uint64_t* round_ids,
        size_t batch_count,
        BitVPackage* packages,
        size_t package_count)
    {
        return bit_handler_.generate_batch(round_ids, batch_count, packages, package_count);
    }

    int bit_store_batch(const BitVPackage* packages, size_t batch_count)
    {
        return bit_handler_.store_batch(packages, batch_count);
    }

    int bit_done_batch(BitShare* bits, size_t batch_count)
    {
        return bit_handler_.done_batch(bits, batch_count);
    }

    int verify_noise_output(const SharePoint* point) const
    {
        if (point == nullptr || point->x == 0 || point->x > n_)
        {
            return kInvalidArgument;
        }
        return point->sigma == sign_noise_output(point->round_id, point->x, point->x, point->y)
            ? kOk
            : kVerificationFailed;
    }

    int verify_triple_output(const TripleShare* triple) const
    {
        return triple_handler_.verify_output(triple);
    }

    int verify_bit_output(const BitShare* bit) const
    {
        return bit_handler_.verify_output(bit);
    }

private:
    uint64_t id_ = 0;
    uint64_t n_ = 0;
    uint64_t t_ = 0;
    uint32_t noise_bound_bits_ = kDefaultNoiseBoundBits;
    size_t active_batch_count_ = 0;
    uint64_t prng_state_ = 0;
    RingElementRaw last_secret_{};
    prss::PRSSState prss_state_{};
    mpc::TripleHandler triple_handler_{};
    mpc::BitHandler bit_handler_{};
    std::array<uint64_t, kMaxParallelBatch> active_round_ids_{};
    std::array<uint64_t, kMaxParties> auth_keys_{};
    uint64_t storage_auth_key_ = 0;
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

    bool z128_lt(const algebra::Z128& lhs, const algebra::Z128& rhs) const
    {
        if (lhs.hi != rhs.hi)
        {
            return lhs.hi < rhs.hi;
        }
        return lhs.lo < rhs.lo;
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

    bool z128_get_bit(const algebra::Z128& value, uint32_t bit_index) const
    {
        if (bit_index >= 128)
        {
            return false;
        }
        if (bit_index < 64)
        {
            return ((value.lo >> bit_index) & 1ULL) != 0;
        }
        return ((value.hi >> (bit_index - 64U)) & 1ULL) != 0;
    }

    algebra::Z128 z128_set_bit(algebra::Z128 value, uint32_t bit_index) const
    {
        if (bit_index >= 128)
        {
            return value;
        }
        if (bit_index < 64)
        {
            value.lo |= (1ULL << bit_index);
        }
        else
        {
            value.hi |= (1ULL << (bit_index - 64U));
        }
        return value;
    }

    uint32_t z128_bit_length(const algebra::Z128& value) const
    {
        if (value.hi != 0)
        {
            uint32_t bits = 64;
            uint64_t hi = value.hi;
            while (hi != 0)
            {
                ++bits;
                hi >>= 1U;
            }
            return bits;
        }

        uint32_t bits = 0;
        uint64_t lo = value.lo;
        while (lo != 0)
        {
            ++bits;
            lo >>= 1U;
        }
        return bits;
    }

    algebra::Z128 z128_random_bits(uint32_t bit_count)
    {
        if (bit_count == 0)
        {
            return algebra::Z128::zero();
        }
        if (bit_count >= 128)
        {
            return algebra::Z128(next_random(), next_random());
        }
        return z128_and(algebra::Z128(next_random(), next_random()), z128_mask(bit_count));
    }

    algebra::Z128 z128_div_u64(const algebra::Z128& value, uint64_t divisor) const
    {
        if (divisor == 0)
        {
            return algebra::Z128::zero();
        }

        algebra::Z128 quotient = algebra::Z128::zero();
        uint64_t remainder = 0;
        for (int32_t bit = 127; bit >= 0; --bit)
        {
            remainder = (remainder << 1U) | (z128_get_bit(value, static_cast<uint32_t>(bit)) ? 1ULL : 0ULL);
            if (remainder >= divisor)
            {
                remainder -= divisor;
                quotient = z128_set_bit(quotient, static_cast<uint32_t>(bit));
            }
        }
        return quotient;
    }

    algebra::Z128 sample_tuniform_z128(uint32_t noise_bound_bits)
    {
        const algebra::Z128 final_bound = z128_pow2(noise_bound_bits);
        const algebra::Z128 local_bound = z128_div_u64(final_bound, n_);
        const algebra::Z128 range = local_bound + local_bound + algebra::Z128::one();
        const algebra::Z128 range_minus_one = range - algebra::Z128::one();
        const uint32_t sample_bits = z128_bit_length(range_minus_one);

        algebra::Z128 sample = algebra::Z128::zero();
        do
        {
            sample = z128_random_bits(sample_bits);
        } while (!z128_lt(sample, range));

        return sample - local_bound;
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

    void initialize_auth_keys()
    {
        for (uint64_t party = 1; party <= n_; ++party)
        {
            const uint64_t lo = mix64(
                (party << 16U) ^
                (n_ << 8U) ^
                t_ ^
                0x4e4f495345415554ULL);
            auth_keys_[party - 1] = lo;
        }
    }

    uint64_t generate_storage_auth_key() const
    {
        uint64_t key = 0;
        if (oe_random(&key, sizeof(key)) != OE_OK || key == 0)
        {
            return mix64(
                (id_ << 33U) ^
                (n_ << 17U) ^
                (t_ << 5U) ^
                prng_state_ ^
                0x53544f524147454bULL);
        }
        return key;
    }

    void generate_share_set(
        size_t batch_index,
        SharePackage* packages,
        RingElementRaw* sampled_secret,
        uint32_t noise_bound_bits)
    {
        RingElement secret = RingElement::from_scalar(sample_tuniform_z128(noise_bound_bits));
        const auto shares = algebra::ShamirRing::share(
            secret,
            static_cast<size_t>(n_),
            static_cast<size_t>(t_),
            [this, noise_bound_bits]() {
                return sample_tuniform_z128(noise_bound_bits);
            });

        last_secret_ = raw_from_ring(secret);
        *sampled_secret = last_secret_;

        for (size_t i = 0; i < n_; ++i)
        {
            const uint64_t receiver_id = static_cast<uint64_t>(i + 1);
            packages[i].round_id = active_round_ids_[batch_index];
            packages[i].sender_id = id_;
            packages[i].receiver_id = receiver_id;
            packages[i].share_x = receiver_id;
            packages[i].share_y = raw_from_ring(shares[i].value);
            packages[i].sigma = sign_share(active_round_ids_[batch_index], id_, receiver_id, packages[i].share_x, packages[i].share_y);
        }
    }

    uint64_t sign_share(uint64_t round_id, uint64_t sender_id, uint64_t receiver_id, uint64_t x, const RingElementRaw& y) const
    {
        const uint64_t h = hash_ring(y);
        const uint64_t auth_key = auth_keys_[sender_id - 1];
        return mix64(auth_key ^ round_id ^ sender_id ^ (receiver_id << 11U) ^ (x << 19U) ^ (h << 1U) ^ 0x5348415245ULL);
    }

    uint64_t sign_noise_output(uint64_t round_id, uint64_t sender_id, uint64_t x, const RingElementRaw& y) const
    {
        return mix64(storage_auth_key_ ^ round_id ^ (sender_id << 5U) ^ (x << 19U) ^ (hash_ring(y) << 1U) ^ 0x4e4f4953454f5554ULL);
    }

    static uint64_t sign_ack(uint64_t round_id, uint64_t acking_party, uint64_t for_sender)
    {
        return mix64(round_id ^ acking_party ^ (for_sender << 17U) ^ 0x41434bULL);
    }
};
} // namespace noise

#endif
