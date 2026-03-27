#ifndef HOST_DKG_PARAMS_HPP
#define HOST_DKG_PARAMS_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "../config/config.hpp"

namespace host
{
namespace dkg
{
enum class KeysetMode
{
    kStandard,
    kDecompressionOnly,
    kAddSnsCompressionKey,
};

enum class PkskDestination
{
    kNone,
    kBig,
    kSmall,
};

enum class EncryptionKeyChoice
{
    kBig,
    kSmall,
};

enum class NoiseKind
{
    kLwe,
    kLweHat,
    kGlwe,
    kGlweSns,
    kCompressionKsk,
    kSnsCompressionKsk,
};

struct NoiseInfo
{
    NoiseKind kind = NoiseKind::kLwe;
    size_t amount = 0;
    uint32_t bound_bits = 0;

    size_t num_bits_needed() const
    {
        return amount * static_cast<size_t>(bound_bits + 2U);
    }
};

struct CompressionParams
{
    bool enabled = false;
    size_t br_level = 0;
    size_t br_base_log = 0;
    size_t packing_ks_level = 0;
    size_t packing_ks_base_log = 0;
    size_t packing_ks_glwe_dimension = 0;
    size_t packing_ks_polynomial_size = 0;
    uint32_t noise_bound_bits = 0;
};

struct RegularParams
{
    uint64_t sec = 128;
    size_t lwe_dimension = 0;
    size_t lwe_hat_dimension = 0;
    size_t glwe_dimension = 0;
    size_t polynomial_size = 0;
    uint32_t lwe_noise_bound_bits = 0;
    uint32_t lwe_hat_noise_bound_bits = 0;
    uint32_t glwe_noise_bound_bits = 0;
    size_t ks_base_log = 0;
    size_t ks_level = 0;
    size_t pksk_base_log = 0;
    size_t pksk_level = 0;
    size_t bk_base_log = 0;
    size_t bk_level = 0;
    size_t msnrk_zeros_count = 0;
    size_t message_modulus = 0;
    size_t carry_modulus = 0;
    double log2_p_fail = 0.0;
    EncryptionKeyChoice encryption_key_choice = EncryptionKeyChoice::kBig;
    bool has_dedicated_pk = false;
    PkskDestination pksk_destination = PkskDestination::kNone;
    CompressionParams compression;
};

struct SnsParams
{
    bool enabled = false;
    size_t glwe_dimension = 0;
    size_t polynomial_size = 0;
    uint32_t glwe_noise_bound_bits = 0;
    size_t bk_base_log = 0;
    size_t bk_level = 0;
    size_t message_modulus = 0;
    size_t carry_modulus = 0;
    CompressionParams compression;
};

struct DkgParams
{
    std::string preset_name;
    KeysetMode keyset_mode = KeysetMode::kStandard;
    RegularParams regular;
    SnsParams sns;
};

struct PreprocessingRequirements
{
    size_t total_bits = 0;
    size_t total_triples = 0;
    size_t total_randomness = 0;
    size_t raw_secret_bits = 0;
    std::vector<NoiseInfo> noise_batches;
};

DkgParams params_test_bk_sns();
DkgParams bc_params_sns();
DkgParams from_runtime_config(const RuntimeConfig& config);
PreprocessingRequirements compute_preprocessing_requirements(const DkgParams& params);

std::string to_string(KeysetMode mode);
std::string to_string(NoiseKind kind);
std::string to_string(EncryptionKeyChoice choice);
} // namespace dkg
} // namespace host

#endif
