#include "encryption.hpp"

#include <cstddef>

namespace host
{
namespace dkg
{
namespace
{
using algebra::RingShare;
using algebra::ResiduePolyF4Z128;
using algebra::Z128;

ResiduePolyF4Z128 ring_from_message(const noise::RingElementRaw& message)
{
    return noise::ring_from_raw(message);
}

noise::RingElementRaw deterministic_mask(const PublicSeed& seed, uint64_t domain, uint64_t index)
{
    noise::RingElementRaw out{};
    uint64_t state = noise::mix64(seed.low ^ (seed.high << 1U) ^ domain ^ (index << 9U));
    for (size_t i = 0; i < 4; ++i)
    {
        state = noise::mix64(state ^ (0x9e3779b97f4a7c15ULL + static_cast<uint64_t>(i)));
        out.coeffs[i].lo = state;
        state = noise::mix64(state ^ 0x243f6a8885a308d3ULL);
        out.coeffs[i].hi = state;
    }
    return out;
}

Z128 pow2_u128(size_t shift)
{
    if (shift >= 128)
    {
        return Z128::zero();
    }
    if (shift < 64)
    {
        return Z128(1ULL << shift, 0);
    }
    return Z128(0, 1ULL << (shift - 64));
}

noise::RingElementRaw scale_message(
    const noise::RingElementRaw& message,
    size_t base_log,
    size_t level_index)
{
    const size_t shift = base_log * (level_index + 1);
    return noise::raw_from_ring(
        ring_from_message(message) * ResiduePolyF4Z128::from_scalar(pow2_u128(shift)));
}

bool same_owner_vector(const std::vector<RingShare>& shares)
{
    if (shares.empty())
    {
        return false;
    }
    const uint64_t owner = shares.front().owner;
    for (const RingShare& share : shares)
    {
        if (share.owner != owner)
        {
            return false;
        }
    }
    return true;
}
} // namespace

bool DistributedEncryption::enc_lwe(
    const PublicSeed& seed,
    uint64_t seed_offset,
    const noise::RingElementRaw& message,
    const std::vector<RingShare>& lwe_secret,
    const RingShare& noise_share,
    size_t lwe_dimension,
    bool include_mask,
    SharedLweCiphertext* out)
{
    if (out == nullptr || lwe_secret.size() != lwe_dimension || !same_owner_vector(lwe_secret))
    {
        return false;
    }
    if (noise_share.owner != lwe_secret.front().owner)
    {
        return false;
    }

    out->a.clear();
    out->a.reserve(lwe_dimension);

    ResiduePolyF4Z128 b = ring_from_message(message) + noise_share.value;
    for (size_t i = 0; i < lwe_dimension; ++i)
    {
        const noise::RingElementRaw mask_raw = deterministic_mask(seed, 0x4c574500ULL + seed_offset, static_cast<uint64_t>(i));
        const ResiduePolyF4Z128 mask = noise::ring_from_raw(mask_raw);
        out->a.push_back(mask_raw);
        b += mask * lwe_secret[i].value;
    }

    out->b = RingShare{ noise_share.owner, b };
    if (!include_mask)
    {
        out->a.clear();
    }
    return true;
}

bool DistributedEncryption::enc_glwe(
    const PublicSeed& seed,
    uint64_t seed_offset,
    const noise::RingElementRaw& message,
    const std::vector<RingShare>& glwe_secret,
    const RingShare& noise_share,
    size_t glwe_dimension,
    bool include_mask,
    SharedGlweCiphertext* out)
{
    if (out == nullptr || glwe_secret.size() != glwe_dimension || !same_owner_vector(glwe_secret))
    {
        return false;
    }
    if (noise_share.owner != glwe_secret.front().owner)
    {
        return false;
    }

    out->a.clear();
    out->a.reserve(glwe_dimension);

    ResiduePolyF4Z128 b = ring_from_message(message) + noise_share.value;
    for (size_t i = 0; i < glwe_dimension; ++i)
    {
        const noise::RingElementRaw mask_raw = deterministic_mask(seed, 0x474c574500ULL + seed_offset, static_cast<uint64_t>(i));
        const ResiduePolyF4Z128 mask = noise::ring_from_raw(mask_raw);
        out->a.push_back(mask_raw);
        b -= mask * glwe_secret[i].value;
    }

    out->b = RingShare{ noise_share.owner, b };
    if (!include_mask)
    {
        out->a.clear();
    }
    return true;
}

bool DistributedEncryption::enc_lev(
    const PublicSeed& seed,
    uint64_t seed_offset,
    const noise::RingElementRaw& message,
    const std::vector<RingShare>& lwe_secret,
    const std::vector<RingShare>& noise_shares,
    size_t lwe_dimension,
    size_t base_log,
    size_t level_count,
    bool include_mask,
    SharedLevCiphertext* out)
{
    if (out == nullptr || noise_shares.size() != level_count)
    {
        return false;
    }

    out->levels.assign(level_count, SharedLweCiphertext{});
    for (size_t i = 0; i < level_count; ++i)
    {
        if (!enc_lwe(
                seed,
                seed_offset + static_cast<uint64_t>(i),
                scale_message(message, base_log, i),
                lwe_secret,
                noise_shares[i],
                lwe_dimension,
                include_mask,
                &out->levels[i]))
        {
            return false;
        }
    }
    return true;
}

bool DistributedEncryption::enc_glev(
    const PublicSeed& seed,
    uint64_t seed_offset,
    const noise::RingElementRaw& message,
    const std::vector<RingShare>& glwe_secret,
    const std::vector<RingShare>& noise_shares,
    size_t glwe_dimension,
    size_t base_log,
    size_t level_count,
    bool include_mask,
    SharedGlevCiphertext* out)
{
    if (out == nullptr || noise_shares.size() != level_count)
    {
        return false;
    }

    out->levels.assign(level_count, SharedGlweCiphertext{});
    for (size_t i = 0; i < level_count; ++i)
    {
        if (!enc_glwe(
                seed,
                seed_offset + static_cast<uint64_t>(i),
                scale_message(message, base_log, i),
                glwe_secret,
                noise_shares[i],
                glwe_dimension,
                include_mask,
                &out->levels[i]))
        {
            return false;
        }
    }
    return true;
}

bool DistributedEncryption::enc_ggsw(
    const PublicSeed& seed,
    uint64_t seed_offset,
    const noise::RingElementRaw& message,
    const std::vector<RingShare>& secret_bits,
    const std::vector<RingShare>& glwe_secret,
    const std::vector<RingShare>& multiplied_secret_messages,
    const std::vector<std::vector<RingShare>>& noise_shares_by_row,
    size_t glwe_dimension,
    size_t base_log,
    size_t level_count,
    bool include_mask,
    SharedGgswCiphertext* out)
{
    if (out == nullptr ||
        multiplied_secret_messages.size() != secret_bits.size() ||
        noise_shares_by_row.size() != secret_bits.size() + 1)
    {
        return false;
    }

    out->rows.clear();
    out->rows.reserve(secret_bits.size() + 1);

    for (size_t i = 0; i < secret_bits.size(); ++i)
    {
        if (noise_shares_by_row[i].size() != level_count)
        {
            return false;
        }

        SharedGlevCiphertext row;
        if (!enc_glev(
                seed,
                seed_offset + static_cast<uint64_t>(i * (level_count + 1)),
                noise::raw_from_ring(multiplied_secret_messages[i].value),
                glwe_secret,
                noise_shares_by_row[i],
                glwe_dimension,
                base_log,
                level_count,
                include_mask,
                &row))
        {
            return false;
        }
        out->rows.push_back(row);
    }

    SharedGlevCiphertext last_row;
    if (noise_shares_by_row.back().size() != level_count)
    {
        return false;
    }
    if (!enc_glev(
            seed,
            seed_offset + static_cast<uint64_t>(secret_bits.size() * (level_count + 1)),
            message,
            glwe_secret,
            noise_shares_by_row.back(),
            glwe_dimension,
            base_log,
            level_count,
            include_mask,
            &last_row))
    {
        return false;
    }
    out->rows.push_back(last_row);
    return true;
}
} // namespace dkg
} // namespace host
