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

// All encryption primitives in this file follow the KMS convention:
// they consume an already encoded plaintext element in the ciphertext domain.
ResiduePolyF4Z128 ring_from_encoded_message(const noise::RingElementRaw& encoded_message)
{
    return noise::ring_from_raw(encoded_message);
}

// Deterministically derive the public mask from the shared seed so we can keep
// the public-key representation in a seeded/compressed form.
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

// Apply the gadget/decomposition scaling used by Lev/GLev encryption levels.
// This is distinct from plaintext delta encoding.
noise::RingElementRaw scale_message(
    const noise::RingElementRaw& encoded_message,
    size_t base_log,
    size_t level_index)
{
    const size_t shift = base_log * (level_index + 1);
    return noise::raw_from_ring(
        ring_from_encoded_message(encoded_message) * ResiduePolyF4Z128::from_scalar(pow2_u128(shift)));
}

// Packing / key-switch style encryptions use the reverse level order expected
// by TFHE decomposition routines.
noise::RingElementRaw scale_decomposition_message(
    const noise::RingElementRaw& encoded_message,
    size_t base_log,
    size_t level_count,
    size_t level_index)
{
    if (level_index >= level_count)
    {
        return {};
    }
    const size_t level = level_count - level_index;
    const size_t shift = (base_log * level >= 128) ? 128 : (128 - base_log * level);
    return noise::raw_from_ring(
        ring_from_encoded_message(encoded_message) * ResiduePolyF4Z128::from_scalar(pow2_u128(shift)));
}

// Shares consumed by a single ciphertext must belong to the same local party.
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
}

bool DistributedEncryption::enc_lwe(
    const PublicSeed& seed,
    uint64_t seed_offset,
    const noise::RingElementRaw& encoded_message,
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

    // KMS-style LWE encryption: b = <a, s> + e + encoded.
    ResiduePolyF4Z128 b = ring_from_encoded_message(encoded_message) + noise_share.value;
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
    const noise::RingElementRaw& encoded_message,
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

    // KMS-style GLWE encryption: b = encoded + e - <a, s>.
    ResiduePolyF4Z128 b = ring_from_encoded_message(encoded_message) + noise_share.value;
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
    const noise::RingElementRaw& encoded_message,
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

    // A Lev ciphertext is an LWE ciphertext per decomposition level.
    out->levels.assign(level_count, SharedLweCiphertext{});
    for (size_t i = 0; i < level_count; ++i)
    {
        if (!enc_lwe(
                seed,
                seed_offset + static_cast<uint64_t>(i),
                scale_message(encoded_message, base_log, i),
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
    const noise::RingElementRaw& encoded_message,
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

    // A GLev ciphertext is a GLWE ciphertext per decomposition level.
    out->levels.assign(level_count, SharedGlweCiphertext{});
    for (size_t i = 0; i < level_count; ++i)
    {
        if (!enc_glwe(
                seed,
                seed_offset + static_cast<uint64_t>(i),
                scale_message(encoded_message, base_log, i),
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
    const noise::RingElementRaw& encoded_message,
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

    // The caller is expected to pass rows that are already MPC-encoded in the
    // same spirit as kms::ggsw_encode_messages.
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
            encoded_message,
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

bool DistributedEncryption::enc_lwe_packing_keyswitch_block(
    const PublicSeed& seed,
    uint64_t seed_offset,
    size_t input_index,
    const std::vector<RingShare>& input_lwe_secret,
    const std::vector<RingShare>& output_glwe_secret,
    const std::vector<RingShare>& noise_shares,
    size_t input_lwe_dimension,
    size_t output_glwe_dimension,
    size_t output_polynomial_size,
    size_t base_log,
    size_t level_count,
    bool include_mask,
    SharedPackingKeyswitchBlock* out)
{
    const size_t expected_noise = output_polynomial_size * level_count;
    if (out == nullptr ||
        input_index >= input_lwe_dimension ||
        input_lwe_secret.size() != input_lwe_dimension ||
        output_glwe_secret.size() != output_glwe_dimension ||
        noise_shares.size() != expected_noise ||
        !same_owner_vector(input_lwe_secret) ||
        !same_owner_vector(output_glwe_secret) ||
        input_lwe_secret.front().owner != output_glwe_secret.front().owner)
    {
        return false;
    }

    // Generate one input-key block of a packing keyswitch key. Each polynomial
    // entry contains one GLev encryption of the decomposed input coefficient.
    out->polynomial_entries.assign(output_polynomial_size, SharedGlevCiphertext{});
    size_t noise_offset = 0;
    for (size_t poly_idx = 0; poly_idx < output_polynomial_size; ++poly_idx)
    {
        SharedGlevCiphertext entry;
        entry.levels.assign(level_count, SharedGlweCiphertext{});
        for (size_t level_idx = 0; level_idx < level_count; ++level_idx)
        {
            const RingShare& noise_share = noise_shares[noise_offset++];
            if (noise_share.owner != input_lwe_secret.front().owner)
            {
                return false;
            }

            noise::RingElementRaw message{};
            if (poly_idx == 0)
            {
                // Only the first coefficient carries the decomposed input LWE key
                // term, matching TFHE packing key-switch layout.
                message = noise::raw_from_ring(input_lwe_secret[input_index].value);
            }

            const uint64_t mask_domain =
                seed_offset +
                static_cast<uint64_t>((input_index * output_polynomial_size + poly_idx) * level_count + level_idx);
            SharedGlweCiphertext& level = entry.levels[level_idx];
            ResiduePolyF4Z128 b =
                ring_from_encoded_message(scale_decomposition_message(message, base_log, level_count, level_idx)) +
                noise_share.value;

            level.a.clear();
            if (include_mask)
            {
                level.a.reserve(output_glwe_dimension);
            }
            for (size_t secret_idx = 0; secret_idx < output_glwe_dimension; ++secret_idx)
            {
                const noise::RingElementRaw mask_raw =
                    deterministic_mask(seed, 0x504b534b00ULL + mask_domain, static_cast<uint64_t>(secret_idx));
                if (include_mask)
                {
                    level.a.push_back(mask_raw);
                }
                b -= noise::ring_from_raw(mask_raw) * output_glwe_secret[secret_idx].value;
            }
            level.b = RingShare{ noise_share.owner, b };
        }
        out->polynomial_entries[poly_idx] = entry;
    }
    return true;
}

bool DistributedEncryption::enc_lwe_packing_keyswitch_key(
    const PublicSeed& seed,
    uint64_t seed_offset,
    const std::vector<RingShare>& input_lwe_secret,
    const std::vector<RingShare>& output_glwe_secret,
    const std::vector<RingShare>& noise_shares,
    size_t input_lwe_dimension,
    size_t output_glwe_dimension,
    size_t output_polynomial_size,
    size_t base_log,
    size_t level_count,
    bool include_mask,
    SharedLwePackingKeyswitchKey* out)
{
    const size_t expected_noise = input_lwe_dimension * output_polynomial_size * level_count;
    if (out == nullptr || noise_shares.size() != expected_noise)
    {
        return false;
    }

    out->input_lwe_dimension = input_lwe_dimension;
    out->output_glwe_dimension = output_glwe_dimension;
    out->output_polynomial_size = output_polynomial_size;
    out->base_log = base_log;
    out->level_count = level_count;
    // The full packing keyswitch key is streamed block-by-block by callers, but
    // this helper still supports whole-key generation for compatibility paths.
    out->blocks.assign(input_lwe_dimension, SharedPackingKeyswitchBlock{});

    const size_t block_noise_count = output_polynomial_size * level_count;
    for (size_t input_idx = 0; input_idx < input_lwe_dimension; ++input_idx)
    {
        const auto begin = noise_shares.begin() + static_cast<std::ptrdiff_t>(input_idx * block_noise_count);
        const auto end = begin + static_cast<std::ptrdiff_t>(block_noise_count);
        std::vector<RingShare> block_noise(begin, end);
        if (!enc_lwe_packing_keyswitch_block(
                seed,
                seed_offset,
                input_idx,
                input_lwe_secret,
                output_glwe_secret,
                block_noise,
                input_lwe_dimension,
                output_glwe_dimension,
                output_polynomial_size,
                base_log,
                level_count,
                include_mask,
                &out->blocks[input_idx]))
        {
            return false;
        }
    }
    return true;
}
} // namespace dkg
} // namespace host
