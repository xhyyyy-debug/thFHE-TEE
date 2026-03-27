#include "keygen.hpp"

#include <algorithm>
#include <deque>
#include <map>
#include <sstream>

#include "../../algebra/sharing/open.hpp"

namespace host
{
namespace dkg
{
namespace
{
using algebra::RingOpen;
using algebra::RingShare;
using algebra::ResiduePolyF4Z128;

bool set_error(std::string* error_message, const std::string& message)
{
    if (error_message != nullptr)
    {
        *error_message = message;
    }
    return false;
}

bool has_share_for_owner(const std::vector<RingShare>& shares, uint64_t owner)
{
    return std::any_of(
        shares.begin(),
        shares.end(),
        [owner](const RingShare& share) { return share.owner == owner; });
}

bool find_local_share(
    const std::vector<RingShare>& shares,
    uint64_t owner,
    RingShare* out)
{
    if (out == nullptr)
    {
        return false;
    }

    for (const RingShare& share : shares)
    {
        if (share.owner == owner)
        {
            *out = share;
            return true;
        }
    }
    return false;
}

size_t count_noise_by_kind(const PreprocessingRequirements& preprocessing, NoiseKind kind)
{
    size_t total = 0;
    for (const NoiseInfo& noise : preprocessing.noise_batches)
    {
        if (noise.kind == kind)
        {
            total += noise.amount;
        }
    }
    return total;
}

bool open_shared_value(
    const std::vector<RingShare>& shares,
    size_t degree,
    ResiduePolyF4Z128* out,
    std::string* error_message,
    const char* what)
{
    if (!RingOpen::robust_open(shares, degree, 0, out))
    {
        return set_error(error_message, std::string("Failed to open ") + what);
    }
    return true;
}

struct NoisePool
{
    std::map<NoiseKind, std::deque<SharedNoiseVector>> by_kind;
};

struct TriplePool
{
    std::deque<SharedTripleVector> triples;
};

NoisePool build_noise_pool(const std::vector<SharedNoiseVector>& noises)
{
    NoisePool pool;
    for (const SharedNoiseVector& noise : noises)
    {
        pool.by_kind[noise.kind].push_back(noise);
    }
    return pool;
}

TriplePool build_triple_pool(const std::vector<SharedTripleVector>& triples)
{
    TriplePool pool;
    for (const SharedTripleVector& triple : triples)
    {
        pool.triples.push_back(triple);
    }
    return pool;
}

bool pop_noise_share(
    NoisePool* pool,
    NoiseKind kind,
    uint64_t owner,
    RingShare* out,
    std::string* error_message,
    const char* label)
{
    if (pool == nullptr || out == nullptr)
    {
        return false;
    }

    auto it = pool->by_kind.find(kind);
    if (it == pool->by_kind.end() || it->second.empty())
    {
        return set_error(error_message, std::string("Exhausted noise pool for ") + label);
    }

    SharedNoiseVector current = it->second.front();
    it->second.pop_front();
    if (!find_local_share(current.shares, owner, out))
    {
        return set_error(error_message, std::string("Missing local noise share for ") + label);
    }
    return true;
}

bool pop_noise_share_vector(
    NoisePool* pool,
    NoiseKind kind,
    uint64_t owner,
    size_t amount,
    std::vector<RingShare>* out,
    std::string* error_message,
    const char* label)
{
    if (out == nullptr)
    {
        return false;
    }

    out->clear();
    out->reserve(amount);
    for (size_t i = 0; i < amount; ++i)
    {
        RingShare share{};
        if (!pop_noise_share(pool, kind, owner, &share, error_message, label))
        {
            return false;
        }
        out->push_back(share);
    }
    return true;
}

bool pop_triple_vector(
    TriplePool* pool,
    std::vector<algebra::RingTripleShare>* out,
    std::string* error_message,
    const char* label)
{
    if (pool == nullptr || out == nullptr)
    {
        return false;
    }

    if (pool->triples.empty())
    {
        return set_error(error_message, std::string("Exhausted triple pool for ") + label);
    }

    *out = pool->triples.front().triples;
    pool->triples.pop_front();
    return true;
}

std::vector<RingShare> extract_secret_segment(
    const std::vector<SharedBitVector>& raw_bits,
    size_t start,
    size_t count,
    uint64_t my_party_id,
    std::string* error_message,
    const char* label)
{
    std::vector<RingShare> out;
    out.reserve(count);

    for (size_t i = 0; i < count; ++i)
    {
        if (start + i >= raw_bits.size())
        {
            set_error(error_message, std::string("Insufficient raw bit material for ") + label);
            return {};
        }

        RingShare local_share{};
        if (!find_local_share(raw_bits[start + i].shares, my_party_id, &local_share))
        {
            set_error(error_message, std::string("Missing local share for ") + label);
            return {};
        }
        out.push_back(local_share);
    }

    return out;
}

noise::RingElementRaw raw_from_share(const RingShare& share)
{
    return noise::raw_from_ring(share.value);
}

std::vector<RingShare> extract_local_products(
    const std::vector<std::vector<RingShare>>& lhs_rows,
    const std::vector<RingShare>& rhs_shares,
    uint64_t my_party_id,
    TriplePool* triple_pool,
    size_t degree,
    std::string* error_message,
    const char* label)
{
    std::vector<RingShare> local_products;
    local_products.reserve(lhs_rows.size());

    for (size_t row = 0; row < lhs_rows.size(); ++row)
    {
        std::vector<algebra::RingTripleShare> triple_shares;
        if (!pop_triple_vector(triple_pool, &triple_shares, error_message, label))
        {
            return {};
        }

        std::vector<RingShare> product_shares;
        if (!algebra::RingMul::mult(
                lhs_rows[row],
                rhs_shares,
                triple_shares,
                degree,
                0,
                &product_shares))
        {
            set_error(error_message, std::string("MPC multiplication failed for ") + label);
            return {};
        }

        RingShare local{};
        if (!find_local_share(product_shares, my_party_id, &local))
        {
            set_error(error_message, std::string("Missing local multiplication share for ") + label);
            return {};
        }
        local_products.push_back(local);
    }
    return local_products;
}
} // namespace

bool DistributedKeyGen::validate_preprocessing(
    const DkgPlan& plan,
    const PreprocessedKeygenMaterial& material,
    std::string* error_message)
{
    if (material.raw_bits.size() < plan.preprocessing.raw_secret_bits)
    {
        std::ostringstream message;
        message << "Not enough raw shared bits: expected at least "
                << plan.preprocessing.raw_secret_bits
                << ", got " << material.raw_bits.size();
        return set_error(error_message, message.str());
    }

    std::map<NoiseKind, size_t> actual_noise_counts;
    for (const SharedNoiseVector& noise : material.noises)
    {
        actual_noise_counts[noise.kind] += 1;
        if (noise.shares.empty())
        {
            return set_error(error_message, "Noise batch contains an empty share vector");
        }
    }

    for (const NoiseInfo& expected : plan.preprocessing.noise_batches)
    {
        const size_t actual = actual_noise_counts[expected.kind];
        if (actual != expected.amount)
        {
            std::ostringstream message;
            message << "Noise batch mismatch for kind " << to_string(expected.kind)
                    << ": expected " << expected.amount
                    << ", got " << actual;
            return set_error(error_message, message.str());
        }
    }

    if (material.triples.size() < plan.preprocessing.total_triples)
    {
        std::ostringstream message;
        message << "Not enough triples: expected at least "
                << plan.preprocessing.total_triples
                << ", got " << material.triples.size();
        return set_error(error_message, message.str());
    }

    return true;
}

bool DistributedKeyGen::keygen(
    const RuntimeConfig& config,
    uint64_t my_party_id,
    const PreprocessedKeygenMaterial& material,
    KeygenOutput* out,
    std::string* error_message)
{
    if (out == nullptr)
    {
        return set_error(error_message, "Keygen output pointer is null");
    }

    const DkgPlan plan = build_plan(config);
    if (!validate_preprocessing(plan, material, error_message))
    {
        return false;
    }

    const size_t degree = static_cast<size_t>(config.threshold);
    KeygenOutput result;
    result.plan = plan;
    result.public_seed = material.seed;
    TriplePool triple_pool = build_triple_pool(material.triples);

    std::vector<std::vector<RingShare>> lwe_full_shares;
    std::vector<std::vector<RingShare>> lwe_hat_full_shares;
    std::vector<std::vector<RingShare>> glwe_full_shares;
    std::vector<std::vector<RingShare>> compression_full_shares;
    std::vector<std::vector<RingShare>> sns_glwe_full_shares;
    std::vector<std::vector<RingShare>> sns_compression_full_shares;

    size_t raw_offset = 0;
    lwe_full_shares.reserve(plan.shape.lwe_secret_bits);
    result.secret_shares.lwe = extract_secret_segment(
        material.raw_bits,
        raw_offset,
        plan.shape.lwe_secret_bits,
        my_party_id,
        error_message,
        "lwe secret");
    if (result.secret_shares.lwe.size() != plan.shape.lwe_secret_bits)
    {
        return false;
    }
    for (size_t i = 0; i < plan.shape.lwe_secret_bits; ++i)
    {
        lwe_full_shares.push_back(material.raw_bits[raw_offset + i].shares);
    }
    raw_offset += plan.shape.lwe_secret_bits;

    lwe_hat_full_shares.reserve(plan.shape.lwe_hat_secret_bits);
    result.secret_shares.lwe_hat = extract_secret_segment(
        material.raw_bits,
        raw_offset,
        plan.shape.lwe_hat_secret_bits,
        my_party_id,
        error_message,
        "lwe_hat secret");
    if (result.secret_shares.lwe_hat.size() != plan.shape.lwe_hat_secret_bits)
    {
        return false;
    }
    for (size_t i = 0; i < plan.shape.lwe_hat_secret_bits; ++i)
    {
        lwe_hat_full_shares.push_back(material.raw_bits[raw_offset + i].shares);
    }
    raw_offset += plan.shape.lwe_hat_secret_bits;

    glwe_full_shares.reserve(plan.shape.glwe_secret_bits);
    result.secret_shares.glwe = extract_secret_segment(
        material.raw_bits,
        raw_offset,
        plan.shape.glwe_secret_bits,
        my_party_id,
        error_message,
        "glwe secret");
    if (result.secret_shares.glwe.size() != plan.shape.glwe_secret_bits)
    {
        return false;
    }
    for (size_t i = 0; i < plan.shape.glwe_secret_bits; ++i)
    {
        glwe_full_shares.push_back(material.raw_bits[raw_offset + i].shares);
    }
    raw_offset += plan.shape.glwe_secret_bits;

    compression_full_shares.reserve(plan.shape.compression_secret_bits);
    result.secret_shares.compression_glwe = extract_secret_segment(
        material.raw_bits,
        raw_offset,
        plan.shape.compression_secret_bits,
        my_party_id,
        error_message,
        "compression secret");
    if (result.secret_shares.compression_glwe.size() != plan.shape.compression_secret_bits)
    {
        return false;
    }
    for (size_t i = 0; i < plan.shape.compression_secret_bits; ++i)
    {
        compression_full_shares.push_back(material.raw_bits[raw_offset + i].shares);
    }
    raw_offset += plan.shape.compression_secret_bits;

    sns_glwe_full_shares.reserve(plan.shape.sns_glwe_secret_bits);
    result.secret_shares.sns_glwe = extract_secret_segment(
        material.raw_bits,
        raw_offset,
        plan.shape.sns_glwe_secret_bits,
        my_party_id,
        error_message,
        "sns glwe secret");
    if (result.secret_shares.sns_glwe.size() != plan.shape.sns_glwe_secret_bits)
    {
        return false;
    }
    for (size_t i = 0; i < plan.shape.sns_glwe_secret_bits; ++i)
    {
        sns_glwe_full_shares.push_back(material.raw_bits[raw_offset + i].shares);
    }
    raw_offset += plan.shape.sns_glwe_secret_bits;

    sns_compression_full_shares.reserve(plan.shape.sns_compression_secret_bits);
    result.secret_shares.sns_compression_glwe = extract_secret_segment(
        material.raw_bits,
        raw_offset,
        plan.shape.sns_compression_secret_bits,
        my_party_id,
        error_message,
        "sns compression secret");
    if (result.secret_shares.sns_compression_glwe.size() != plan.shape.sns_compression_secret_bits)
    {
        return false;
    }
    for (size_t i = 0; i < plan.shape.sns_compression_secret_bits; ++i)
    {
        sns_compression_full_shares.push_back(material.raw_bits[raw_offset + i].shares);
    }

    NoisePool pool = build_noise_pool(material.noises);

    result.public_material.pk.reserve(plan.shape.public_key_ciphertexts);
    for (size_t i = 0; i < plan.shape.public_key_ciphertexts; ++i)
    {
        RingShare noise_share{};
        if (!pop_noise_share(&pool, NoiseKind::kLweHat, my_party_id, &noise_share, error_message, "pk"))
        {
            return false;
        }
        SharedLweCiphertext ctxt;
        if (!DistributedEncryption::enc_lwe(
                material.seed,
                static_cast<uint64_t>(i),
                noise::RingElementRaw{},
                result.secret_shares.lwe,
                noise_share,
                result.secret_shares.lwe.size(),
                true,
                &ctxt))
        {
            return set_error(error_message, "Failed to encrypt compact public key sample");
        }
        result.public_material.pk.push_back(ctxt);
    }

    result.public_material.ksk.reserve(result.secret_shares.glwe.size());
    for (size_t i = 0; i < result.secret_shares.glwe.size(); ++i)
    {
        std::vector<RingShare> level_noise;
        if (!pop_noise_share_vector(
                &pool,
                NoiseKind::kLwe,
                my_party_id,
                plan.params.regular.ks_level,
                &level_noise,
                error_message,
                "ksk"))
        {
            return false;
        }

        SharedLevCiphertext ctxt;
        if (!DistributedEncryption::enc_lev(
                material.seed,
                0x100000ULL + static_cast<uint64_t>(i * plan.params.regular.ks_level),
                raw_from_share(result.secret_shares.glwe[i]),
                result.secret_shares.lwe,
                level_noise,
                result.secret_shares.lwe.size(),
                plan.params.regular.ks_base_log,
                plan.params.regular.ks_level,
                true,
                &ctxt))
        {
            return set_error(error_message, "Failed to encrypt KSK entry");
        }
        result.public_material.ksk.push_back(ctxt);
    }

    if (plan.params.regular.pksk_destination == PkskDestination::kSmall)
    {
        result.public_material.pksk_lwe.reserve(result.secret_shares.lwe_hat.size());
        for (size_t i = 0; i < result.secret_shares.lwe_hat.size(); ++i)
        {
            std::vector<RingShare> level_noise;
            if (!pop_noise_share_vector(
                    &pool,
                    NoiseKind::kLwe,
                    my_party_id,
                    plan.params.regular.pksk_level,
                    &level_noise,
                    error_message,
                    "pksk_lwe"))
            {
                return false;
            }

            SharedLevCiphertext ctxt;
            if (!DistributedEncryption::enc_lev(
                    material.seed,
                    0x200000ULL + static_cast<uint64_t>(i * plan.params.regular.pksk_level),
                    raw_from_share(result.secret_shares.lwe_hat[i]),
                    result.secret_shares.lwe,
                    level_noise,
                    result.secret_shares.lwe.size(),
                    plan.params.regular.pksk_base_log,
                    plan.params.regular.pksk_level,
                    true,
                    &ctxt))
            {
                return set_error(error_message, "Failed to encrypt PKSK entry");
            }
            result.public_material.pksk_lwe.push_back(ctxt);
        }
    }
    else if (plan.params.regular.pksk_destination == PkskDestination::kBig)
    {
        result.public_material.pksk_glwe.reserve(result.secret_shares.lwe_hat.size());
        for (size_t i = 0; i < result.secret_shares.lwe_hat.size(); ++i)
        {
            std::vector<RingShare> level_noise;
            if (!pop_noise_share_vector(
                    &pool,
                    NoiseKind::kGlwe,
                    my_party_id,
                    plan.params.regular.pksk_level,
                    &level_noise,
                    error_message,
                    "pksk_glwe"))
            {
                return false;
            }

            SharedGlevCiphertext ctxt;
            if (!DistributedEncryption::enc_glev(
                    material.seed,
                    0x300000ULL + static_cast<uint64_t>(i * plan.params.regular.pksk_level),
                    raw_from_share(result.secret_shares.lwe_hat[i]),
                    result.secret_shares.glwe,
                    level_noise,
                    result.secret_shares.glwe.size(),
                    plan.params.regular.pksk_base_log,
                    plan.params.regular.pksk_level,
                    true,
                    &ctxt))
            {
                return set_error(error_message, "Failed to encrypt GLWE PKSK entry");
            }
            result.public_material.pksk_glwe.push_back(ctxt);
        }
    }

    result.public_material.bk.reserve(result.secret_shares.lwe.size());
    for (size_t i = 0; i < result.secret_shares.lwe.size(); ++i)
    {
        std::vector<std::vector<RingShare>> row_noise(result.secret_shares.glwe.size() + 1);
        for (size_t row = 0; row < row_noise.size(); ++row)
        {
            if (!pop_noise_share_vector(
                    &pool,
                    NoiseKind::kGlwe,
                    my_party_id,
                    plan.params.regular.bk_level,
                    &row_noise[row],
                    error_message,
                    "bk"))
            {
                return false;
            }
        }

            SharedGgswCiphertext ctxt;
            const std::vector<RingShare> multiplied_rows = extract_local_products(
                glwe_full_shares,
                lwe_full_shares[i],
                my_party_id,
                &triple_pool,
                degree,
                error_message,
                "bk");
            if (multiplied_rows.size() != glwe_full_shares.size())
            {
                return false;
            }
            if (!DistributedEncryption::enc_ggsw(
                    material.seed,
                    0x400000ULL + static_cast<uint64_t>(i * row_noise.size() * plan.params.regular.bk_level),
                    raw_from_share(result.secret_shares.lwe[i]),
                    result.secret_shares.glwe,
                    result.secret_shares.glwe,
                    multiplied_rows,
                    row_noise,
                    result.secret_shares.glwe.size(),
                    plan.params.regular.bk_base_log,
                plan.params.regular.bk_level,
                true,
                &ctxt))
        {
            return set_error(error_message, "Failed to encrypt BK entry");
        }
        result.public_material.bk.push_back(ctxt);
    }

    if (!result.secret_shares.sns_glwe.empty())
    {
        result.public_material.bk_sns.reserve(result.secret_shares.lwe.size());
        for (size_t i = 0; i < result.secret_shares.lwe.size(); ++i)
        {
            std::vector<std::vector<RingShare>> row_noise(result.secret_shares.sns_glwe.size() + 1);
            for (size_t row = 0; row < row_noise.size(); ++row)
            {
                if (!pop_noise_share_vector(
                        &pool,
                        NoiseKind::kGlweSns,
                        my_party_id,
                        plan.params.sns.bk_level,
                        &row_noise[row],
                        error_message,
                        "bk_sns"))
                {
                    return false;
                }
            }

            SharedGgswCiphertext ctxt;
            const std::vector<RingShare> multiplied_rows = extract_local_products(
                sns_glwe_full_shares,
                lwe_full_shares[i],
                my_party_id,
                &triple_pool,
                degree,
                error_message,
                "bk_sns");
            if (multiplied_rows.size() != sns_glwe_full_shares.size())
            {
                return false;
            }
            if (!DistributedEncryption::enc_ggsw(
                    material.seed,
                    0x500000ULL + static_cast<uint64_t>(i * row_noise.size() * plan.params.sns.bk_level),
                    raw_from_share(result.secret_shares.lwe[i]),
                    result.secret_shares.sns_glwe,
                    result.secret_shares.sns_glwe,
                    multiplied_rows,
                    row_noise,
                    result.secret_shares.sns_glwe.size(),
                    plan.params.sns.bk_base_log,
                    plan.params.sns.bk_level,
                    true,
                    &ctxt))
            {
                return set_error(error_message, "Failed to encrypt BK_SNS entry");
            }
            result.public_material.bk_sns.push_back(ctxt);
        }
    }

    if (!result.secret_shares.compression_glwe.empty())
    {
        result.public_material.compression_key.reserve(result.secret_shares.glwe.size());
        for (size_t i = 0; i < result.secret_shares.glwe.size(); ++i)
        {
            std::vector<std::vector<RingShare>> row_noise(result.secret_shares.compression_glwe.size() + 1);
            for (size_t row = 0; row < row_noise.size(); ++row)
            {
                if (!pop_noise_share_vector(
                        &pool,
                        NoiseKind::kCompressionKsk,
                        my_party_id,
                        plan.params.regular.compression.packing_ks_level,
                        &row_noise[row],
                        error_message,
                        "compression_key"))
                {
                    return false;
                }
            }

            SharedGgswCiphertext ctxt;
            const std::vector<RingShare> multiplied_rows = extract_local_products(
                compression_full_shares,
                glwe_full_shares[i],
                my_party_id,
                &triple_pool,
                degree,
                error_message,
                "compression_key");
            if (multiplied_rows.size() != compression_full_shares.size())
            {
                return false;
            }
            if (!DistributedEncryption::enc_ggsw(
                    material.seed,
                    0x600000ULL + static_cast<uint64_t>(i * row_noise.size() * plan.params.regular.compression.packing_ks_level),
                    raw_from_share(result.secret_shares.glwe[i]),
                    result.secret_shares.compression_glwe,
                    result.secret_shares.compression_glwe,
                    multiplied_rows,
                    row_noise,
                    result.secret_shares.compression_glwe.size(),
                    plan.params.regular.compression.packing_ks_base_log,
                    plan.params.regular.compression.packing_ks_level,
                    true,
                    &ctxt))
            {
                return set_error(error_message, "Failed to encrypt compression key entry");
            }
            result.public_material.compression_key.push_back(ctxt);
        }

        result.public_material.decompression_key.reserve(result.secret_shares.compression_glwe.size());
        for (size_t i = 0; i < result.secret_shares.compression_glwe.size(); ++i)
        {
            std::vector<RingShare> level_noise;
            if (!pop_noise_share_vector(
                    &pool,
                    NoiseKind::kGlwe,
                    my_party_id,
                    plan.params.regular.compression.br_level,
                    &level_noise,
                    error_message,
                    "decompression_key"))
            {
                return false;
            }

            SharedGlevCiphertext ctxt;
            if (!DistributedEncryption::enc_glev(
                    material.seed,
                    0x700000ULL + static_cast<uint64_t>(i * plan.params.regular.compression.br_level),
                    raw_from_share(result.secret_shares.compression_glwe[i]),
                    result.secret_shares.glwe,
                    level_noise,
                    result.secret_shares.glwe.size(),
                    plan.params.regular.compression.br_base_log,
                    plan.params.regular.compression.br_level,
                    true,
                    &ctxt))
            {
                return set_error(error_message, "Failed to encrypt decompression key entry");
            }
            result.public_material.decompression_key.push_back(ctxt);
        }
    }

    if (!result.secret_shares.sns_compression_glwe.empty())
    {
        result.public_material.sns_compression_key.reserve(result.secret_shares.sns_glwe.size());
        for (size_t i = 0; i < result.secret_shares.sns_glwe.size(); ++i)
        {
            std::vector<std::vector<RingShare>> row_noise(result.secret_shares.sns_compression_glwe.size() + 1);
            for (size_t row = 0; row < row_noise.size(); ++row)
            {
                if (!pop_noise_share_vector(
                        &pool,
                        NoiseKind::kSnsCompressionKsk,
                        my_party_id,
                        plan.params.sns.compression.packing_ks_level,
                        &row_noise[row],
                        error_message,
                        "sns_compression_key"))
                {
                    return false;
                }
            }

            SharedGgswCiphertext ctxt;
            const std::vector<RingShare> multiplied_rows = extract_local_products(
                sns_compression_full_shares,
                sns_glwe_full_shares[i],
                my_party_id,
                &triple_pool,
                degree,
                error_message,
                "sns_compression_key");
            if (multiplied_rows.size() != sns_compression_full_shares.size())
            {
                return false;
            }
            if (!DistributedEncryption::enc_ggsw(
                    material.seed,
                    0x800000ULL + static_cast<uint64_t>(i * row_noise.size() * plan.params.sns.compression.packing_ks_level),
                    raw_from_share(result.secret_shares.sns_glwe[i]),
                    result.secret_shares.sns_compression_glwe,
                    result.secret_shares.sns_compression_glwe,
                    multiplied_rows,
                    row_noise,
                    result.secret_shares.sns_compression_glwe.size(),
                    plan.params.sns.compression.packing_ks_base_log,
                    plan.params.sns.compression.packing_ks_level,
                    true,
                    &ctxt))
            {
                return set_error(error_message, "Failed to encrypt sns compression key entry");
            }
            result.public_material.sns_compression_key.push_back(ctxt);
        }
    }

    *out = result;
    return true;
}
} // namespace dkg
} // namespace host
