#include "config.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "../../enclave/common/noise_types.h"

namespace host
{
namespace
{
std::string trim(const std::string& value)
{
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
    {
        return "";
    }

    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

std::vector<std::string> split(const std::string& text, char separator)
{
    std::vector<std::string> parts;
    std::string current;
    std::istringstream input(text);

    while (std::getline(input, current, separator))
    {
        parts.push_back(trim(current));
    }

    return parts;
}
} // namespace

RuntimeConfig load_runtime_config(const std::string& path)
{
    std::ifstream input(path);
    if (!input)
    {
        throw std::runtime_error("Failed to open config file: " + path);
    }

    RuntimeConfig config;
    std::string line;
    size_t line_number = 0;

    while (std::getline(input, line))
    {
        ++line_number;
        line = trim(line);
        if (line.empty() || line[0] == '#')
        {
            continue;
        }

        const auto pos = line.find('=');
        if (pos == std::string::npos)
        {
            throw std::runtime_error("Invalid config line " + std::to_string(line_number) + ": " + line);
        }

        const std::string key = trim(line.substr(0, pos));
        const std::string value = trim(line.substr(pos + 1));

        if (key == "party_count")
        {
            config.party_count = std::stoull(value);
            continue;
        }

        if (key == "threshold")
        {
            config.threshold = std::stoull(value);
            continue;
        }

        if (key == "noise_degree")
        {
            config.noise_degree = std::stoull(value);
            continue;
        }

        if (key == "noise_bound_bits")
        {
            config.noise_bound_bits = static_cast<uint32_t>(std::stoul(value));
            continue;
        }

        if (key == "dkg_preset")
        {
            config.dkg.preset = value;
            continue;
        }

        if (key == "dkg_keyset_mode")
        {
            config.dkg.keyset_mode = value;
            continue;
        }

        if (key == "dkg_sec")
        {
            config.dkg.regular.sec = std::stoull(value);
            continue;
        }

        if (key == "dkg_lwe_dimension")
        {
            config.dkg.regular.lwe_dimension = std::stoull(value);
            continue;
        }

        if (key == "dkg_lwe_hat_dimension")
        {
            config.dkg.regular.lwe_hat_dimension = std::stoull(value);
            continue;
        }

        if (key == "dkg_glwe_dimension")
        {
            config.dkg.regular.glwe_dimension = std::stoull(value);
            continue;
        }

        if (key == "dkg_polynomial_size")
        {
            config.dkg.regular.polynomial_size = std::stoull(value);
            continue;
        }

        if (key == "dkg_lwe_noise_bound_bits")
        {
            config.dkg.regular.lwe_noise_bound_bits = static_cast<uint32_t>(std::stoul(value));
            continue;
        }

        if (key == "dkg_lwe_hat_noise_bound_bits")
        {
            config.dkg.regular.lwe_hat_noise_bound_bits = static_cast<uint32_t>(std::stoul(value));
            continue;
        }

        if (key == "dkg_glwe_noise_bound_bits")
        {
            config.dkg.regular.glwe_noise_bound_bits = static_cast<uint32_t>(std::stoul(value));
            continue;
        }

        if (key == "dkg_ks_level")
        {
            config.dkg.regular.ks_level = std::stoull(value);
            continue;
        }

        if (key == "dkg_ks_base_log")
        {
            config.dkg.regular.ks_base_log = std::stoull(value);
            continue;
        }

        if (key == "dkg_pksk_level")
        {
            config.dkg.regular.pksk_level = std::stoull(value);
            continue;
        }

        if (key == "dkg_pksk_base_log")
        {
            config.dkg.regular.pksk_base_log = std::stoull(value);
            continue;
        }

        if (key == "dkg_bk_level")
        {
            config.dkg.regular.bk_level = std::stoull(value);
            continue;
        }

        if (key == "dkg_bk_base_log")
        {
            config.dkg.regular.bk_base_log = std::stoull(value);
            continue;
        }

        if (key == "dkg_msnrk_zeros_count")
        {
            config.dkg.regular.msnrk_zeros_count = std::stoull(value);
            continue;
        }

        if (key == "dkg_pksk_destination")
        {
            config.dkg.regular.pksk_destination = value;
            continue;
        }

        if (key == "dkg_has_dedicated_pk")
        {
            config.dkg.regular.has_dedicated_pk = (value == "1" || value == "true");
            continue;
        }

        if (key == "dkg_message_modulus")
        {
            config.dkg.regular.message_modulus = std::stoull(value);
            continue;
        }

        if (key == "dkg_carry_modulus")
        {
            config.dkg.regular.carry_modulus = std::stoull(value);
            continue;
        }

        if (key == "dkg_log2_p_fail")
        {
            config.dkg.regular.log2_p_fail = std::stod(value);
            continue;
        }

        if (key == "dkg_encryption_key_choice")
        {
            config.dkg.regular.encryption_key_choice = value;
            continue;
        }

        if (key == "dkg_comp_enabled")
        {
            config.dkg.regular.compression.enabled = (value == "1" || value == "true");
            continue;
        }

        if (key == "dkg_comp_br_level")
        {
            config.dkg.regular.compression.br_level = std::stoull(value);
            continue;
        }

        if (key == "dkg_comp_br_base_log")
        {
            config.dkg.regular.compression.br_base_log = std::stoull(value);
            continue;
        }

        if (key == "dkg_comp_ks_level")
        {
            config.dkg.regular.compression.packing_ks_level = std::stoull(value);
            continue;
        }

        if (key == "dkg_comp_ks_base_log")
        {
            config.dkg.regular.compression.packing_ks_base_log = std::stoull(value);
            continue;
        }

        if (key == "dkg_comp_glwe_dimension")
        {
            config.dkg.regular.compression.packing_ks_glwe_dimension = std::stoull(value);
            continue;
        }

        if (key == "dkg_comp_polynomial_size")
        {
            config.dkg.regular.compression.packing_ks_polynomial_size = std::stoull(value);
            continue;
        }

        if (key == "dkg_comp_noise_bound_bits")
        {
            config.dkg.regular.compression.noise_bound_bits = static_cast<uint32_t>(std::stoul(value));
            continue;
        }

        if (key == "dkg_sns_enabled")
        {
            config.dkg.sns.enabled = (value == "1" || value == "true");
            continue;
        }

        if (key == "dkg_sns_glwe_dimension")
        {
            config.dkg.sns.glwe_dimension = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_polynomial_size")
        {
            config.dkg.sns.polynomial_size = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_glwe_noise_bound_bits")
        {
            config.dkg.sns.glwe_noise_bound_bits = static_cast<uint32_t>(std::stoul(value));
            continue;
        }

        if (key == "dkg_sns_bk_level")
        {
            config.dkg.sns.bk_level = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_bk_base_log")
        {
            config.dkg.sns.bk_base_log = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_message_modulus")
        {
            config.dkg.sns.message_modulus = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_carry_modulus")
        {
            config.dkg.sns.carry_modulus = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_comp_enabled")
        {
            config.dkg.sns.compression.enabled = (value == "1" || value == "true");
            continue;
        }

        if (key == "dkg_sns_comp_br_base_log")
        {
            config.dkg.sns.compression.br_base_log = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_comp_ks_level")
        {
            config.dkg.sns.compression.packing_ks_level = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_comp_ks_base_log")
        {
            config.dkg.sns.compression.packing_ks_base_log = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_comp_glwe_dimension")
        {
            config.dkg.sns.compression.packing_ks_glwe_dimension = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_comp_polynomial_size")
        {
            config.dkg.sns.compression.packing_ks_polynomial_size = std::stoull(value);
            continue;
        }

        if (key == "dkg_sns_comp_noise_bound_bits")
        {
            config.dkg.sns.compression.noise_bound_bits = static_cast<uint32_t>(std::stoul(value));
            continue;
        }

        if (key == "party")
        {
            const auto parts = split(value, ',');
            if (parts.size() != 4)
            {
                throw std::runtime_error("Invalid party entry on line " + std::to_string(line_number));
            }

            PartyConfig party;
            party.name = parts[0];
            party.id = std::stoull(parts[1]);
            party.endpoint.host = parts[2];
            party.endpoint.port = static_cast<uint16_t>(std::stoul(parts[3]));
            config.parties.push_back(party);
            continue;
        }

        throw std::runtime_error("Unknown config key on line " + std::to_string(line_number) + ": " + key);
    }

    if (config.party_count == 0)
    {
        config.party_count = config.parties.size();
    }

    if (config.party_count == 0 || config.parties.size() != config.party_count)
    {
        throw std::runtime_error("Config party_count does not match number of party entries");
    }

    if (config.threshold >= config.party_count)
    {
        throw std::runtime_error("Config threshold must be smaller than party_count");
    }

    if (config.noise_degree == 0)
    {
        throw std::runtime_error("Config noise_degree must be positive");
    }

    if (config.noise_degree > noise::kMaxParallelBatch)
    {
        throw std::runtime_error("Config noise_degree exceeds max batch size: " + std::to_string(noise::kMaxParallelBatch));
    }

    if (config.noise_bound_bits == 0 || config.noise_bound_bits > 126)
    {
        throw std::runtime_error("Config noise_bound_bits must be in [1, 126]");
    }

    std::vector<uint64_t> ids;
    std::vector<std::string> names;
    for (const auto& party : config.parties)
    {
        if (party.id == 0)
        {
            throw std::runtime_error("Party id must be non-zero");
        }

        if (std::find(ids.begin(), ids.end(), party.id) != ids.end())
        {
            throw std::runtime_error("Duplicate party id in config: " + std::to_string(party.id));
        }

        if (std::find(names.begin(), names.end(), party.name) != names.end())
        {
            throw std::runtime_error("Duplicate party name in config: " + party.name);
        }

        ids.push_back(party.id);
        names.push_back(party.name);
    }

    return config;
}

const PartyConfig& find_party_config(const RuntimeConfig& config, const std::string& name)
{
    for (const auto& party : config.parties)
    {
        if (party.name == name)
        {
            return party;
        }
    }

    throw std::runtime_error("Party name not found in config: " + name);
}

std::vector<Endpoint> endpoints_from_config(const RuntimeConfig& config)
{
    std::vector<Endpoint> endpoints(config.party_count);

    for (const auto& party : config.parties)
    {
        if (party.id == 0 || party.id > config.party_count)
        {
            throw std::runtime_error("Party id out of range in config: " + std::to_string(party.id));
        }

        endpoints[party.id - 1] = party.endpoint;
    }

    return endpoints;
}
} // namespace host
