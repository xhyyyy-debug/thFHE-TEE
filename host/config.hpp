#ifndef HOST_CONFIG_HPP
#define HOST_CONFIG_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "network.hpp"

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
    uint64_t party_count = 0;
    uint64_t threshold = 0;
    uint64_t noise_degree = 1;
    uint32_t noise_bound_bits = 8;
    std::vector<PartyConfig> parties;
};

RuntimeConfig load_runtime_config(const std::string& path);
const PartyConfig& find_party_config(const RuntimeConfig& config, const std::string& name);
std::vector<Endpoint> endpoints_from_config(const RuntimeConfig& config);
} // namespace host

#endif
