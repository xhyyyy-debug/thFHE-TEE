#ifndef HOST_CONFIG_HPP
#define HOST_CONFIG_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "../transport/network.hpp"

namespace host
{
struct PartyConfig
{
    std::string name;
    uint64_t id = 0;
    Endpoint endpoint;
};

struct RuntimeConfig
{
    struct DkgCompressionConfig
    {
        bool enabled = false;
        uint64_t br_level = 0;
        uint64_t br_base_log = 0;
        uint64_t packing_ks_level = 0;
        uint64_t packing_ks_base_log = 0;
        uint64_t packing_ks_glwe_dimension = 0;
        uint64_t packing_ks_polynomial_size = 0;
        uint32_t noise_bound_bits = 0;
    };

    struct DkgRegularConfig
    {
        uint64_t sec = 128;
        uint64_t lwe_dimension = 0;
        uint64_t lwe_hat_dimension = 0;
        uint64_t glwe_dimension = 0;
        uint64_t polynomial_size = 0;
        uint32_t lwe_noise_bound_bits = 0;
        uint32_t lwe_hat_noise_bound_bits = 0;
        uint32_t glwe_noise_bound_bits = 0;
        uint64_t ks_base_log = 0;
        uint64_t ks_level = 0;
        uint64_t pksk_base_log = 0;
        uint64_t pksk_level = 0;
        uint64_t bk_base_log = 0;
        uint64_t bk_level = 0;
        uint64_t msnrk_zeros_count = 0;
        uint64_t message_modulus = 0;
        uint64_t carry_modulus = 0;
        double log2_p_fail = 0.0;
        std::string encryption_key_choice = "big";
        std::string pksk_destination = "none";
        bool has_dedicated_pk = false;
        DkgCompressionConfig compression;
    };

    struct DkgSnsConfig
    {
        bool enabled = false;
        uint64_t glwe_dimension = 0;
        uint64_t polynomial_size = 0;
        uint32_t glwe_noise_bound_bits = 0;
        uint64_t bk_base_log = 0;
        uint64_t bk_level = 0;
        uint64_t message_modulus = 0;
        uint64_t carry_modulus = 0;
        DkgCompressionConfig compression;
    };

    struct DkgConfig
    {
        std::string preset = "params_test_bk_sns";
        std::string keyset_mode = "standard";
        DkgRegularConfig regular;
        DkgSnsConfig sns;
    };

    uint64_t party_count = 0;
    uint64_t threshold = 0;
    uint64_t noise_degree = 1;
    uint32_t noise_bound_bits = 8;
    DkgConfig dkg;
    std::vector<PartyConfig> parties;
};

RuntimeConfig load_runtime_config(const std::string& path);
const PartyConfig& find_party_config(const RuntimeConfig& config, const std::string& name);
std::vector<Endpoint> endpoints_from_config(const RuntimeConfig& config);
} // namespace host

#endif
