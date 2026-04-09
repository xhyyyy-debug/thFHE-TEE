#include "params.hpp"

#include <stdexcept>

namespace host
{
namespace dkg
{
namespace
{
KeysetMode parse_keyset_mode(const std::string& value)
{
    if (value == "standard")
    {
        return KeysetMode::kStandard;
    }
    if (value == "decompression_only")
    {
        return KeysetMode::kDecompressionOnly;
    }
    if (value == "sns_compression_only")
    {
        return KeysetMode::kAddSnsCompressionKey;
    }
    throw std::runtime_error("Unsupported dkg_keyset_mode: " + value);
}

PkskDestination parse_pksk_destination(const std::string& value)
{
    if (value == "none")
    {
        return PkskDestination::kNone;
    }
    if (value == "big" || value == "fglwe")
    {
        return PkskDestination::kBig;
    }
    if (value == "small" || value == "lwe")
    {
        return PkskDestination::kSmall;
    }
    throw std::runtime_error("Unsupported dkg_pksk_destination: " + value);
}

EncryptionKeyChoice parse_encryption_key_choice(const std::string& value)
{
    if (value == "big")
    {
        return EncryptionKeyChoice::kBig;
    }
    if (value == "small")
    {
        return EncryptionKeyChoice::kSmall;
    }
    throw std::runtime_error("Unsupported dkg_encryption_key_choice: " + value);
}

NoiseInfo make_noise(NoiseKind kind, size_t amount, uint32_t bound_bits)
{
    NoiseInfo info;
    info.kind = kind;
    info.amount = amount;
    info.bound_bits = bound_bits;
    return info;
}

size_t compression_sk_num_bits(const CompressionParams& params)
{
    if (!params.enabled)
    {
        return 0;
    }
    return params.packing_ks_glwe_dimension * params.packing_ks_polynomial_size;
}

NoiseInfo regular_pk_noise(const RegularParams& params)
{
    return make_noise(NoiseKind::kLweHat, params.lwe_hat_dimension, params.lwe_hat_noise_bound_bits);
}

NoiseInfo regular_ksk_noise(const RegularParams& params)
{
    return make_noise(
        NoiseKind::kLwe,
        params.glwe_dimension * params.polynomial_size * params.ks_level,
        params.lwe_noise_bound_bits);
}

NoiseInfo regular_pksk_noise(const RegularParams& params)
{
    NoiseKind kind = NoiseKind::kLwe;
    if (params.pksk_destination == PkskDestination::kBig)
    {
        kind = NoiseKind::kGlwe;
    }
    const uint32_t bound = params.pksk_destination == PkskDestination::kBig ?
        params.glwe_noise_bound_bits :
        params.lwe_noise_bound_bits;
    const size_t amount = params.pksk_destination == PkskDestination::kNone ? 0 : params.lwe_hat_dimension * params.pksk_level;
    return make_noise(kind, amount, bound);
}

NoiseInfo regular_bk_noise(const RegularParams& params)
{
    return make_noise(
        NoiseKind::kGlwe,
        params.lwe_dimension * ((params.glwe_dimension * params.polynomial_size) + 1) * params.bk_level,
        params.glwe_noise_bound_bits);
}

NoiseInfo regular_compression_noise(const RegularParams& params)
{
    if (!params.compression.enabled)
    {
        return make_noise(NoiseKind::kCompressionKsk, 0, 0);
    }

    return make_noise(
        NoiseKind::kCompressionKsk,
        (params.glwe_dimension * params.polynomial_size) *
            (compression_sk_num_bits(params.compression) + 1) *
            params.compression.packing_ks_level,
        params.compression.noise_bound_bits);
}

NoiseInfo regular_decompression_noise(const RegularParams& params)
{
    if (!params.compression.enabled)
    {
        return make_noise(NoiseKind::kGlwe, 0, params.glwe_noise_bound_bits);
    }

    return make_noise(
        NoiseKind::kGlwe,
        compression_sk_num_bits(params.compression) * params.compression.br_level,
        params.glwe_noise_bound_bits);
}

NoiseInfo sns_bk_noise(const DkgParams& params)
{
    if (!params.sns.enabled)
    {
        return make_noise(NoiseKind::kGlweSns, 0, 0);
    }

    return make_noise(
        NoiseKind::kGlweSns,
        params.regular.lwe_dimension *
            ((params.sns.glwe_dimension * params.sns.polynomial_size) + 1) *
            params.sns.bk_level,
        params.sns.glwe_noise_bound_bits);
}

NoiseInfo sns_compression_noise(const DkgParams& params)
{
    if (!params.sns.enabled || !params.sns.compression.enabled)
    {
        return make_noise(NoiseKind::kSnsCompressionKsk, 0, 0);
    }

    return make_noise(
        NoiseKind::kSnsCompressionKsk,
        (params.sns.glwe_dimension * params.sns.polynomial_size) *
            params.sns.compression.packing_ks_polynomial_size *
            params.sns.compression.packing_ks_level,
        params.sns.compression.noise_bound_bits);
}

size_t raw_secret_bits(const DkgParams& params)
{
    switch (params.keyset_mode)
    {
    case KeysetMode::kStandard:
        return params.regular.lwe_dimension +
            params.regular.lwe_hat_dimension +
            (params.regular.glwe_dimension * params.regular.polynomial_size) +
            compression_sk_num_bits(params.regular.compression) +
            (params.sns.enabled ? params.sns.glwe_dimension * params.sns.polynomial_size : 0) +
            compression_sk_num_bits(params.sns.compression);
    case KeysetMode::kDecompressionOnly:
        return 0;
    case KeysetMode::kAddSnsCompressionKey:
        return compression_sk_num_bits(params.sns.compression);
    }
    return 0;
}
} // namespace

DkgParams params_test_bk_sns()
{
    DkgParams params;
    params.preset_name = "params_test_bk_sns";
    params.keyset_mode = KeysetMode::kStandard;
    params.regular.sec = 128;
    params.regular.lwe_dimension = 1;
    params.regular.lwe_hat_dimension = 512;
    params.regular.glwe_dimension = 1;
    params.regular.polynomial_size = 256;
    params.regular.lwe_noise_bound_bits = 0;
    params.regular.lwe_hat_noise_bound_bits = 0;
    params.regular.glwe_noise_bound_bits = 0;
    params.regular.ks_base_log = 37;
    params.regular.ks_level = 1;
    params.regular.pksk_base_log = 37;
    params.regular.pksk_level = 1;
    params.regular.bk_base_log = 24;
    params.regular.bk_level = 1;
    params.regular.message_modulus = 4;
    params.regular.carry_modulus = 4;
    params.regular.log2_p_fail = -64.0;
    params.regular.encryption_key_choice = EncryptionKeyChoice::kBig;
    params.regular.has_dedicated_pk = true;
    params.regular.pksk_destination = PkskDestination::kSmall;
    params.regular.compression.enabled = true;
    params.regular.compression.br_level = 1;
    params.regular.compression.br_base_log = 24;
    params.regular.compression.packing_ks_level = 1;
    params.regular.compression.packing_ks_base_log = 27;
    params.regular.compression.packing_ks_glwe_dimension = 1;
    params.regular.compression.packing_ks_polynomial_size = 256;
    params.regular.compression.noise_bound_bits = 0;

    params.sns.enabled = true;
    params.sns.glwe_dimension = 1;
    params.sns.polynomial_size = 256;
    params.sns.glwe_noise_bound_bits = 0;
    params.sns.bk_base_log = 33;
    params.sns.bk_level = 2;
    params.sns.message_modulus = 4;
    params.sns.carry_modulus = 4;
    params.sns.compression.enabled = true;
    params.sns.compression.packing_ks_level = 1;
    params.sns.compression.packing_ks_base_log = 61;
    params.sns.compression.packing_ks_glwe_dimension = 1;
    params.sns.compression.packing_ks_polynomial_size = 128;
    params.sns.compression.noise_bound_bits = 3;
    return params;
}

DkgParams bc_params_sns()
{
    DkgParams params;
    params.preset_name = "bc_params_sns";
    params.keyset_mode = KeysetMode::kStandard;

    params.regular.sec = 128;
    params.regular.lwe_dimension = 918;
    params.regular.lwe_hat_dimension = 2048;
    params.regular.glwe_dimension = 1;
    params.regular.polynomial_size = 2048;
    params.regular.lwe_noise_bound_bits = 45;
    params.regular.lwe_hat_noise_bound_bits = 17;
    params.regular.glwe_noise_bound_bits = 17;
    params.regular.ks_base_log = 4;
    params.regular.ks_level = 4;
    params.regular.pksk_base_log = 4;
    params.regular.pksk_level = 4;
    params.regular.bk_base_log = 23;
    params.regular.bk_level = 1;
    params.regular.msnrk_zeros_count = 1449;
    params.regular.message_modulus = 4;
    params.regular.carry_modulus = 4;
    params.regular.log2_p_fail = -129.15284804376165;
    params.regular.encryption_key_choice = EncryptionKeyChoice::kBig;
    params.regular.has_dedicated_pk = true;
    params.regular.pksk_destination = PkskDestination::kSmall;

    params.regular.compression.enabled = true;
    params.regular.compression.br_level = 1;
    params.regular.compression.br_base_log = 23;
    params.regular.compression.packing_ks_level = 3;
    params.regular.compression.packing_ks_base_log = 4;
    params.regular.compression.packing_ks_glwe_dimension = 4;
    params.regular.compression.packing_ks_polynomial_size = 256;
    params.regular.compression.noise_bound_bits = 43;

    params.sns.enabled = true;
    params.sns.glwe_dimension = 2;
    params.sns.polynomial_size = 2048;
    params.sns.glwe_noise_bound_bits = 30;
    params.sns.bk_base_log = 24;
    params.sns.bk_level = 3;
    params.sns.message_modulus = 4;
    params.sns.carry_modulus = 4;

    params.sns.compression.enabled = true;
    params.sns.compression.packing_ks_level = 1;
    params.sns.compression.packing_ks_base_log = 61;
    params.sns.compression.packing_ks_glwe_dimension = 6;
    params.sns.compression.packing_ks_polynomial_size = 1024;
    params.sns.compression.noise_bound_bits = 3;
    return params;
}

DkgParams from_runtime_config(const RuntimeConfig& config)
{
    DkgParams params;
    if (config.dkg.preset == "params_test_bk_sns")
    {
        params = params_test_bk_sns();
    }
    else if (config.dkg.preset == "bc_params_sns")
    {
        params = bc_params_sns();
    }
    else
    {
        params.preset_name = config.dkg.preset;
    }

    params.keyset_mode = parse_keyset_mode(config.dkg.keyset_mode);
    if (config.dkg.regular.sec != 0)
    {
        params.regular.sec = config.dkg.regular.sec;
    }
    if (config.dkg.regular.lwe_dimension != 0)
    {
        params.regular.lwe_dimension = static_cast<size_t>(config.dkg.regular.lwe_dimension);
    }
    if (config.dkg.regular.lwe_hat_dimension != 0)
    {
        params.regular.lwe_hat_dimension = static_cast<size_t>(config.dkg.regular.lwe_hat_dimension);
    }
    if (config.dkg.regular.glwe_dimension != 0)
    {
        params.regular.glwe_dimension = static_cast<size_t>(config.dkg.regular.glwe_dimension);
    }
    if (config.dkg.regular.polynomial_size != 0)
    {
        params.regular.polynomial_size = static_cast<size_t>(config.dkg.regular.polynomial_size);
    }
    if (config.dkg.regular.lwe_noise_bound_bits != 0)
    {
        params.regular.lwe_noise_bound_bits = config.dkg.regular.lwe_noise_bound_bits;
    }
    if (config.dkg.regular.lwe_hat_noise_bound_bits != 0)
    {
        params.regular.lwe_hat_noise_bound_bits = config.dkg.regular.lwe_hat_noise_bound_bits;
    }
    if (config.dkg.regular.glwe_noise_bound_bits != 0)
    {
        params.regular.glwe_noise_bound_bits = config.dkg.regular.glwe_noise_bound_bits;
    }
    if (config.dkg.regular.ks_level != 0)
    {
        params.regular.ks_level = static_cast<size_t>(config.dkg.regular.ks_level);
    }
    if (config.dkg.regular.ks_base_log != 0)
    {
        params.regular.ks_base_log = static_cast<size_t>(config.dkg.regular.ks_base_log);
    }
    if (config.dkg.regular.pksk_level != 0)
    {
        params.regular.pksk_level = static_cast<size_t>(config.dkg.regular.pksk_level);
    }
    if (config.dkg.regular.pksk_base_log != 0)
    {
        params.regular.pksk_base_log = static_cast<size_t>(config.dkg.regular.pksk_base_log);
    }
    if (config.dkg.regular.bk_level != 0)
    {
        params.regular.bk_level = static_cast<size_t>(config.dkg.regular.bk_level);
    }
    if (config.dkg.regular.bk_base_log != 0)
    {
        params.regular.bk_base_log = static_cast<size_t>(config.dkg.regular.bk_base_log);
    }
    params.regular.msnrk_zeros_count = static_cast<size_t>(config.dkg.regular.msnrk_zeros_count);
    if (config.dkg.regular.message_modulus != 0)
    {
        params.regular.message_modulus = static_cast<size_t>(config.dkg.regular.message_modulus);
    }
    if (config.dkg.regular.carry_modulus != 0)
    {
        params.regular.carry_modulus = static_cast<size_t>(config.dkg.regular.carry_modulus);
    }
    if (config.dkg.regular.log2_p_fail != 0.0)
    {
        params.regular.log2_p_fail = config.dkg.regular.log2_p_fail;
    }
    params.regular.encryption_key_choice =
        parse_encryption_key_choice(config.dkg.regular.encryption_key_choice);
    params.regular.has_dedicated_pk = config.dkg.regular.has_dedicated_pk;
    params.regular.pksk_destination = parse_pksk_destination(config.dkg.regular.pksk_destination);

    params.regular.compression.enabled = config.dkg.regular.compression.enabled;
    params.regular.compression.br_level = static_cast<size_t>(config.dkg.regular.compression.br_level);
    params.regular.compression.br_base_log = static_cast<size_t>(config.dkg.regular.compression.br_base_log);
    params.regular.compression.packing_ks_level = static_cast<size_t>(config.dkg.regular.compression.packing_ks_level);
    params.regular.compression.packing_ks_base_log = static_cast<size_t>(config.dkg.regular.compression.packing_ks_base_log);
    params.regular.compression.packing_ks_glwe_dimension =
        static_cast<size_t>(config.dkg.regular.compression.packing_ks_glwe_dimension);
    params.regular.compression.packing_ks_polynomial_size =
        static_cast<size_t>(config.dkg.regular.compression.packing_ks_polynomial_size);
    params.regular.compression.noise_bound_bits = config.dkg.regular.compression.noise_bound_bits;

    params.sns.enabled = config.dkg.sns.enabled || params.sns.enabled;
    if (config.dkg.sns.glwe_dimension != 0)
    {
        params.sns.glwe_dimension = static_cast<size_t>(config.dkg.sns.glwe_dimension);
    }
    if (config.dkg.sns.polynomial_size != 0)
    {
        params.sns.polynomial_size = static_cast<size_t>(config.dkg.sns.polynomial_size);
    }
    if (config.dkg.sns.glwe_noise_bound_bits != 0)
    {
        params.sns.glwe_noise_bound_bits = config.dkg.sns.glwe_noise_bound_bits;
    }
    if (config.dkg.sns.bk_level != 0)
    {
        params.sns.bk_level = static_cast<size_t>(config.dkg.sns.bk_level);
    }
    if (config.dkg.sns.bk_base_log != 0)
    {
        params.sns.bk_base_log = static_cast<size_t>(config.dkg.sns.bk_base_log);
    }
    if (config.dkg.sns.message_modulus != 0)
    {
        params.sns.message_modulus = static_cast<size_t>(config.dkg.sns.message_modulus);
    }
    if (config.dkg.sns.carry_modulus != 0)
    {
        params.sns.carry_modulus = static_cast<size_t>(config.dkg.sns.carry_modulus);
    }
    params.sns.compression.enabled = config.dkg.sns.compression.enabled || params.sns.compression.enabled;
    params.sns.compression.br_base_log = static_cast<size_t>(config.dkg.sns.compression.br_base_log);
    params.sns.compression.packing_ks_level =
        static_cast<size_t>(config.dkg.sns.compression.packing_ks_level == 0 ?
            params.sns.compression.packing_ks_level :
            config.dkg.sns.compression.packing_ks_level);
    params.sns.compression.packing_ks_base_log =
        static_cast<size_t>(config.dkg.sns.compression.packing_ks_base_log == 0 ?
            params.sns.compression.packing_ks_base_log :
            config.dkg.sns.compression.packing_ks_base_log);
    params.sns.compression.packing_ks_glwe_dimension =
        static_cast<size_t>(config.dkg.sns.compression.packing_ks_glwe_dimension == 0 ?
            params.sns.compression.packing_ks_glwe_dimension :
            config.dkg.sns.compression.packing_ks_glwe_dimension);
    params.sns.compression.packing_ks_polynomial_size =
        static_cast<size_t>(config.dkg.sns.compression.packing_ks_polynomial_size == 0 ?
            params.sns.compression.packing_ks_polynomial_size :
            config.dkg.sns.compression.packing_ks_polynomial_size);
    if (config.dkg.sns.compression.noise_bound_bits != 0)
    {
        params.sns.compression.noise_bound_bits = config.dkg.sns.compression.noise_bound_bits;
    }

    if (params.regular.lwe_dimension == 0 ||
        params.regular.lwe_hat_dimension == 0 ||
        params.regular.glwe_dimension == 0 ||
        params.regular.polynomial_size == 0)
    {
        throw std::runtime_error(
            "DKG parameters are incomplete. Use dkg_preset=params_test_bk_sns or provide explicit dkg_* numeric fields.");
    }

    return params;
}

PreprocessingRequirements compute_preprocessing_requirements(const DkgParams& params)
{
    PreprocessingRequirements out;
    out.raw_secret_bits = raw_secret_bits(params);
    out.total_bits = out.raw_secret_bits;
    out.total_randomness = 1;

    switch (params.keyset_mode)
    {
    case KeysetMode::kStandard:
    {
        out.noise_batches.push_back(regular_pk_noise(params.regular));
        out.noise_batches.push_back(regular_ksk_noise(params.regular));
        out.noise_batches.push_back(regular_pksk_noise(params.regular));
        out.noise_batches.push_back(regular_bk_noise(params.regular));
        out.noise_batches.push_back(regular_compression_noise(params.regular));
        out.noise_batches.push_back(regular_decompression_noise(params.regular));
        if (params.sns.enabled)
        {
            out.noise_batches.push_back(sns_bk_noise(params));
            out.noise_batches.push_back(sns_compression_noise(params));
        }

        const size_t glwe_sk_bits =
            params.regular.glwe_dimension * params.regular.polynomial_size;
        const size_t compression_sk_bits =
            compression_sk_num_bits(params.regular.compression);
        const size_t sns_glwe_sk_bits =
            params.sns.enabled ? params.sns.glwe_dimension * params.sns.polynomial_size : 0;
        out.total_triples =
            params.regular.lwe_dimension * glwe_sk_bits;
        if (params.sns.enabled)
        {
            out.total_triples += params.regular.lwe_dimension * sns_glwe_sk_bits;
        }
        if (params.regular.compression.enabled)
        {
            out.total_triples += glwe_sk_bits * compression_sk_bits;
        }
        break;
    }
    case KeysetMode::kDecompressionOnly:
        out.noise_batches.push_back(regular_decompression_noise(params.regular));
        out.total_triples = 0;
        out.raw_secret_bits = 0;
        out.total_bits = 0;
        break;
    case KeysetMode::kAddSnsCompressionKey:
        if (params.sns.enabled)
        {
            out.noise_batches.push_back(sns_compression_noise(params));
        }
        out.total_triples = 0;
        break;
    }

    return out;
}

std::string to_string(KeysetMode mode)
{
    switch (mode)
    {
    case KeysetMode::kStandard:
        return "standard";
    case KeysetMode::kDecompressionOnly:
        return "decompression_only";
    case KeysetMode::kAddSnsCompressionKey:
        return "sns_compression_only";
    }
    return "standard";
}

std::string to_string(NoiseKind kind)
{
    switch (kind)
    {
    case NoiseKind::kLwe:
        return "lwe";
    case NoiseKind::kLweHat:
        return "lwe_hat";
    case NoiseKind::kGlwe:
        return "glwe";
    case NoiseKind::kGlweSns:
        return "glwe_sns";
    case NoiseKind::kCompressionKsk:
        return "compression_ksk";
    case NoiseKind::kSnsCompressionKsk:
        return "sns_compression_ksk";
    }
    return "unknown";
}

std::string to_string(EncryptionKeyChoice choice)
{
    switch (choice)
    {
    case EncryptionKeyChoice::kBig:
        return "big";
    case EncryptionKeyChoice::kSmall:
        return "small";
    }
    return "big";
}
} // namespace dkg
} // namespace host
