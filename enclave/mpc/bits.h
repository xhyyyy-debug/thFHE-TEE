#ifndef NOISE_MPC_BITS_H
#define NOISE_MPC_BITS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

#include <mbedtls/aes.h>

#include "../../algebra/sharing/shamir_ring.hpp"
#include "../common/noise_types.h"
#include "../prss/state.h"

namespace noise
{
namespace mpc
{
class BitHandler
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
        BitVPackage* packages,
        size_t package_count)
    {
        if (round_ids == nullptr || packages == nullptr || batch_count == 0 || batch_count > kMaxParallelBatch || package_count < batch_count)
        {
            return kInvalidArgument;
        }

        begin_batch(round_ids, batch_count);
        for (size_t i = 0; i < batch_count; ++i)
        {
            const int status = generate_one(i, round_ids[i], &packages[i]);
            if (status != kOk)
            {
                return status;
            }
        }
        return kOk;
    }

    int store_batch(const BitVPackage* packages, size_t batch_count)
    {
        if (packages == nullptr || batch_count == 0 || batch_count > active_batch_count_)
        {
            std::printf(
                "[enclave][bit_store] invalid batch packages=%p batch_count=%zu active_batch_count=%zu\n",
                static_cast<const void*>(packages),
                batch_count,
                active_batch_count_);
            return kInvalidArgument;
        }

        for (size_t i = 0; i < batch_count; ++i)
        {
            const BitVPackage& pkg = packages[i];
            if (pkg.round_id == 0 || pkg.round_id != active_round_ids_[i] || pkg.sender_id == 0 || pkg.sender_id > n_)
            {
                std::printf(
                    "[enclave][bit_store] invalid package index=%zu round=%llu expected_round=%llu sender=%llu n=%llu\n",
                    i,
                    static_cast<unsigned long long>(pkg.round_id),
                    static_cast<unsigned long long>(active_round_ids_[i]),
                    static_cast<unsigned long long>(pkg.sender_id),
                    static_cast<unsigned long long>(n_));
                return kInvalidArgument;
            }

            if (corrupt_parties_[pkg.sender_id - 1])
            {
                continue;
            }

            if (pkg.sigma != sign_v(pkg.round_id, pkg.sender_id, pkg.v_share))
            {
                corrupt_parties_[pkg.sender_id - 1] = true;
                continue;
            }

            if (!received_mask_[i][pkg.sender_id - 1])
            {
                received_mask_[i][pkg.sender_id - 1] = true;
                v_shares_[i][pkg.sender_id - 1] = ring_from_raw(pkg.v_share);
                received_counts_[i] += 1;
            }
        }

        return kOk;
    }

    int done_batch(BitShare* bits, size_t batch_count)
    {
        if (bits == nullptr || batch_count == 0 || batch_count > active_batch_count_)
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
                        v_shares_[i][party_index]
                    });
                }
            }

            RingElement v_open = RingElement::zero();
            if (!algebra::ShamirRing::reconstruct(recon_shares, &v_open))
            {
                std::printf(
                    "[enclave][bit_done] reconstruct failed round=%llu index=%zu received=%llu threshold=%llu\n",
                    static_cast<unsigned long long>(active_round_ids_[i]),
                    i,
                    static_cast<unsigned long long>(received_counts_[i]),
                    static_cast<unsigned long long>(t_));
                return kVerificationFailed;
            }

            RingElement r = RingElement::zero();
            if (!RingElement::solve(v_open, &r))
            {
                const RingElementRaw v_raw = raw_from_ring(v_open);
                std::printf(
                    "[enclave][bit_done] solve failed round=%llu index=%zu received=%llu v=(%016llx.%016llx,%016llx.%016llx,%016llx.%016llx,%016llx.%016llx)\n",
                    static_cast<unsigned long long>(active_round_ids_[i]),
                    i,
                    static_cast<unsigned long long>(received_counts_[i]),
                    static_cast<unsigned long long>(v_raw.coeffs[0].lo),
                    static_cast<unsigned long long>(v_raw.coeffs[0].hi),
                    static_cast<unsigned long long>(v_raw.coeffs[1].lo),
                    static_cast<unsigned long long>(v_raw.coeffs[1].hi),
                    static_cast<unsigned long long>(v_raw.coeffs[2].lo),
                    static_cast<unsigned long long>(v_raw.coeffs[2].hi),
                    static_cast<unsigned long long>(v_raw.coeffs[3].lo),
                    static_cast<unsigned long long>(v_raw.coeffs[3].hi));
                return kVerificationFailed;
            }

            const RingElement d = -(RingElement::one() + (RingElement::two() * r));
            const RingElement b = (a_values_[i] - r) * d.invert();
            bits[i].round_id = active_round_ids_[i];
            bits[i].b = raw_from_ring(b);
            bits[i].sigma = sign_output(bits[i].round_id, id_, bits[i].b);
        }

        clear_round();
        return kOk;
    }

    int verify_output(const BitShare* bit) const
    {
        if (bit == nullptr)
        {
            return kInvalidArgument;
        }
        return bit->sigma == sign_output(bit->round_id, id_, bit->b)
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
    std::array<RingElement, kMaxParallelBatch> a_values_{};
    std::array<std::array<RingElement, kMaxParties>, kMaxParallelBatch> v_shares_{};
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
            a_values_[i] = RingElement::zero();
            received_mask_[i].fill(false);
            for (size_t j = 0; j < kMaxParties; ++j)
            {
                v_shares_[i][j] = RingElement::zero();
            }
        }
    }

    void initialize_auth_keys()
    {
        corrupt_parties_.fill(false);

        constexpr std::array<uint8_t, 16> kAuthRoot{
            0x54, 0x45, 0x45, 0x2d, 0x42, 0x49, 0x54, 0x2d,
            0x41, 0x55, 0x54, 0x48, 0x2d, 0x56, 0x31, 0x21
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
            block[3] = 0xb1;

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

    int generate_one(size_t index, uint64_t round_id, BitVPackage* out)
    {
        if (round_id == 0 || out == nullptr)
        {
            return kInvalidArgument;
        }

        RingElement a = RingElement::zero();
        const int status = prss_state_->prss_next(&a);
        if (status != kOk)
        {
            return status;
        }

        a_values_[index] = a;
        const RingElement s = a * a;
        const RingElement v_share = a + s;
        v_shares_[index][id_ - 1] = v_share;
        received_mask_[index][id_ - 1] = true;
        received_counts_[index] = 1;

        out->round_id = round_id;
        out->sender_id = id_;
        out->v_share = raw_from_ring(v_share);
        out->sigma = sign_v(round_id, id_, out->v_share);
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

    uint64_t sign_v(uint64_t round_id, uint64_t sender_id, const RingElementRaw& v_share) const
    {
        const uint64_t auth_key = auth_keys_[sender_id - 1];
        return mix64(auth_key ^ round_id ^ (sender_id << 7U) ^ (hash_ring(v_share) << 1U) ^ 0x4249545348415245ULL);
    }

    uint64_t sign_output(uint64_t round_id, uint64_t sender_id, const RingElementRaw& bit_share) const
    {
        return mix64(storage_auth_key_ ^ round_id ^ (sender_id << 11U) ^ (hash_ring(bit_share) << 1U) ^ 0x4249544f55545054ULL);
    }
};
} // namespace mpc
} // namespace noise

#endif
