#ifndef NOISE_MPC_TRIPLES_H
#define NOISE_MPC_TRIPLES_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <mbedtls/aes.h>

#include "../../algebra/sharing/shamir_ring.hpp"
#include "../common/noise_types.h"
#include "../prss/state.h"

namespace noise
{
namespace mpc
{
class TripleHandler
{
public:
    int init(uint64_t party_id, uint64_t party_count, uint64_t threshold, prss::PRSSState* prss_state)
    {
        if (party_id == 0 || party_count == 0 || party_id > party_count || threshold >= party_count || prss_state == nullptr)
        {
            return kInvalidArgument;
        }

        id_ = party_id;
        n_ = party_count;
        t_ = threshold;
        prss_state_ = prss_state;
        initialize_auth_keys();
        clear_round();
        return kOk;
    }

    void set_storage_auth_key(uint64_t storage_auth_key)
    {
        storage_auth_key_ = storage_auth_key;
    }

    int generate_batch(
        const uint64_t* round_ids,
        size_t batch_count,
        TripleDPackage* packages,
        size_t package_count)
    {
        if (round_ids == nullptr || packages == nullptr || batch_count == 0 || batch_count > kMaxParallelBatch || package_count < batch_count)
        {
            return kInvalidArgument;
        }

        begin_batch(round_ids, batch_count);
        for (size_t i = 0; i < batch_count; ++i)
        {
            int status = generate_one(i, round_ids[i], &packages[i]);
            if (status != kOk)
            {
                return status;
            }
        }
        return kOk;
    }

    int store_batch(const TripleDPackage* packages, size_t batch_count)
    {
        if (packages == nullptr || batch_count == 0 || batch_count > active_batch_count_)
        {
            return kInvalidArgument;
        }

        for (size_t i = 0; i < batch_count; ++i)
        {
            const TripleDPackage& pkg = packages[i];
            if (pkg.round_id == 0 || pkg.round_id != active_round_ids_[i] || pkg.sender_id == 0 || pkg.sender_id > n_)
            {
                return kInvalidArgument;
            }

            if (corrupt_parties_[pkg.sender_id - 1])
            {
                continue;
            }

            if (pkg.sigma != sign_d(pkg.round_id, pkg.sender_id, pkg.d_share))
            {
                corrupt_parties_[pkg.sender_id - 1] = true;
                continue;
            }
            if (!received_mask_[i][pkg.sender_id - 1])
            {
                received_mask_[i][pkg.sender_id - 1] = true;
                d_shares_[i][pkg.sender_id - 1] = ring_from_raw(pkg.d_share);
                received_counts_[i] += 1;
            }
        }
        return kOk;
    }

    int done_batch(TripleShare* triples, size_t batch_count)
    {
        if (triples == nullptr || batch_count == 0 || batch_count > active_batch_count_)
        {
            return kInvalidArgument;
        }

        for (size_t i = 0; i < batch_count; ++i)
        {
            if (received_counts_[i] < (2 * t_ + 1))
            {
                return kNotReady;
            }

            std::vector<algebra::RingShare> recon_shares;
            recon_shares.reserve(static_cast<size_t>(2 * t_ + 1));
            for (size_t party_index = 0; party_index < n_ && recon_shares.size() < static_cast<size_t>(2 * t_ + 1); ++party_index)
            {
                if (received_mask_[i][party_index])
                {
                    recon_shares.push_back(algebra::RingShare{
                        static_cast<uint64_t>(party_index + 1),
                        d_shares_[i][party_index]
                    });
                }
            }

            RingElement d_open = RingElement::zero();
            if (!algebra::ShamirRing::reconstruct(recon_shares, &d_open))
            {
                return kVerificationFailed;
            }

            triples[i].round_id = active_round_ids_[i];
            triples[i].a = raw_from_ring(x_values_[i]);
            triples[i].b = raw_from_ring(y_values_[i]);
            triples[i].c = raw_from_ring(d_open - v_values_[i]);
            triples[i].sigma = sign_output(
                triples[i].round_id,
                id_,
                triples[i].a,
                triples[i].b,
                triples[i].c);
        }

        clear_round();
        return kOk;
    }

    int verify_output(const TripleShare* triple) const
    {
        if (triple == nullptr)
        {
            return kInvalidArgument;
        }
        return triple->sigma == sign_output(triple->round_id, id_, triple->a, triple->b, triple->c)
            ? kOk
            : kVerificationFailed;
    }

private:
    uint64_t id_ = 0;
    uint64_t n_ = 0;
    uint64_t t_ = 0;
    size_t active_batch_count_ = 0;
    prss::PRSSState* prss_state_ = nullptr;
    std::array<uint64_t, kMaxParties> auth_keys_{};
    uint64_t storage_auth_key_ = 0;
    std::array<bool, kMaxParties> corrupt_parties_{};
    std::array<uint64_t, kMaxParallelBatch> active_round_ids_{};
    std::array<RingElement, kMaxParallelBatch> x_values_{};
    std::array<RingElement, kMaxParallelBatch> y_values_{};
    std::array<RingElement, kMaxParallelBatch> v_values_{};
    std::array<std::array<RingElement, kMaxParties>, kMaxParallelBatch> d_shares_{};
    std::array<std::array<bool, kMaxParties>, kMaxParallelBatch> received_mask_{};
    std::array<uint64_t, kMaxParallelBatch> received_counts_{};

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
        received_counts_.fill(0);
        for (size_t i = 0; i < kMaxParallelBatch; ++i)
        {
            x_values_[i] = RingElement::zero();
            y_values_[i] = RingElement::zero();
            v_values_[i] = RingElement::zero();
            received_mask_[i].fill(false);
            for (size_t j = 0; j < kMaxParties; ++j)
            {
                d_shares_[i][j] = RingElement::zero();
            }
        }
    }

    void initialize_auth_keys()
    {
        corrupt_parties_.fill(false);

        constexpr std::array<uint8_t, 16> kAuthRoot{
            0x54, 0x45, 0x45, 0x2d, 0x54, 0x52, 0x49, 0x50,
            0x4c, 0x45, 0x2d, 0x41, 0x55, 0x54, 0x48, 0x21
        };

        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        mbedtls_aes_setkey_enc(&ctx, kAuthRoot.data(), 128);

        for (uint64_t party = 1; party <= n_ && party <= kMaxParties; ++party)
        {
            std::array<uint8_t, 16> block{};
            block[0] = static_cast<uint8_t>(party);
            block[1] = static_cast<uint8_t>(n_);
            block[2] = static_cast<uint8_t>(t_);
            block[3] = 0xa7;

            std::array<uint8_t, 16> out{};
            mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, block.data(), out.data());

            uint64_t lo = 0;
            for (size_t i = 0; i < 8; ++i)
            {
                lo |= static_cast<uint64_t>(out[i]) << (8U * i);
            }
            auth_keys_[party - 1] = lo;
        }

        mbedtls_aes_free(&ctx);
    }

    int generate_one(size_t index, uint64_t round_id, TripleDPackage* out)
    {
        if (round_id == 0 || out == nullptr)
        {
            return kInvalidArgument;
        }

        RingElement x = RingElement::zero();
        RingElement y = RingElement::zero();
        RingElement v = RingElement::zero();
        RingElement z2t = RingElement::zero();

        int status = prss_state_->prss_next(&x);
        if (status != kOk)
        {
            return status;
        }
        status = prss_state_->prss_next(&y);
        if (status != kOk)
        {
            return status;
        }
        status = prss_state_->prss_next(&v);
        if (status != kOk)
        {
            return status;
        }
        status = prss_state_->przs_next(&z2t);
        if (status != kOk)
        {
            return status;
        }

        x_values_[index] = x;
        y_values_[index] = y;
        v_values_[index] = v;

        const RingElement d_share = x * y + (v + z2t);
        d_shares_[index][id_ - 1] = d_share;
        received_mask_[index][id_ - 1] = true;
        received_counts_[index] = 1;

        out->round_id = round_id;
        out->sender_id = id_;
        out->d_share = raw_from_ring(d_share);
        out->sigma = sign_d(round_id, id_, out->d_share);
        return kOk;
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

    uint64_t sign_d(uint64_t round_id, uint64_t sender_id, const RingElementRaw& d_share) const
    {
        const uint64_t auth_key = auth_keys_[sender_id - 1];
        return mix64(auth_key ^ round_id ^ (sender_id << 9U) ^ (hash_ring(d_share) << 1U) ^ 0x445348415245ULL);
    }

    uint64_t sign_output(
        uint64_t round_id,
        uint64_t sender_id,
        const RingElementRaw& a,
        const RingElementRaw& b,
        const RingElementRaw& c) const
    {
        return mix64(
            storage_auth_key_ ^
            round_id ^
            (sender_id << 13U) ^
            (hash_ring(a) << 1U) ^
            (hash_ring(b) << 3U) ^
            (hash_ring(c) << 5U) ^
            0x545249504f555454ULL);
    }
};
} // namespace mpc
} // namespace noise

#endif
