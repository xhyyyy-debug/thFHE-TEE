#include "preprocessing_store.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

#include "serialization.hpp"
#include "../protocol/control_protocol.hpp"

namespace host
{
namespace dkg
{
namespace
{
bool set_error(std::string* error_message, const std::string& message)
{
    if (error_message != nullptr)
    {
        *error_message = message;
    }
    return false;
}

std::string encode_share(const algebra::RingShare& share)
{
    return std::to_string(share.owner) + "," + host::encode_ring(noise::raw_from_ring(share.value));
}

bool decode_share(const std::string& text, algebra::RingShare* out)
{
    if (out == nullptr)
    {
        return false;
    }

    const auto pos = text.find(',');
    if (pos == std::string::npos)
    {
        return false;
    }

    noise::RingElementRaw raw{};
    if (!host::decode_ring(text.substr(pos + 1), &raw))
    {
        return false;
    }

    out->owner = std::stoull(text.substr(0, pos));
    out->value = noise::ring_from_raw(raw);
    return true;
}
} // namespace

std::string PreprocessingStore::session_dir(const std::string& root_dir, const std::string& session_id)
{
    return (std::filesystem::path(root_dir) / session_id).string();
}

bool PreprocessingStore::save(
    const std::string& root_dir,
    const std::string& session_id,
    const DkgPlan& plan,
    const PreprocessedKeygenMaterial& material,
    std::string* error_message)
{
    const std::filesystem::path dir = session_dir(root_dir, session_id);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec)
    {
        return set_error(error_message, "Failed to create preprocessing session directory");
    }

    {
        std::ofstream meta(dir / "meta.txt");
        if (!meta)
        {
            return set_error(error_message, "Failed to write meta.txt");
        }
        meta << "preset=" << plan.params.preset_name << "\n";
        meta << "keyset_mode=" << to_string(plan.params.keyset_mode) << "\n";
        meta << "seed_low=" << material.seed.low << "\n";
        meta << "seed_high=" << material.seed.high << "\n";
        meta << "raw_secret_bits=" << plan.preprocessing.raw_secret_bits << "\n";
        meta << "total_triples=" << plan.preprocessing.total_triples << "\n";
    }
    return save_preprocessing_bundle((dir / "preprocessing.bin").string(), plan, material, error_message);
}

bool PreprocessingStore::load(
    const std::string& root_dir,
    const std::string& session_id,
    DkgPlan* plan,
    PreprocessedKeygenMaterial* material,
    std::string* error_message)
{
    if (plan == nullptr || material == nullptr)
    {
        return set_error(error_message, "Null output passed to preprocessing load");
    }

    const std::filesystem::path dir = session_dir(root_dir, session_id);
    if (!load_preprocessing_bundle((dir / "preprocessing.bin").string(), plan, material, error_message))
    {
        return false;
    }

    {
        std::ifstream meta(dir / "meta.txt");
        if (!meta)
        {
            return true;
        }

        std::string line;
        while (std::getline(meta, line))
        {
            const auto pos = line.find('=');
            if (pos == std::string::npos)
            {
                continue;
            }
            const std::string key = line.substr(0, pos);
            const std::string value = line.substr(pos + 1);
            if (key == "seed_low")
            {
                material->seed.low = std::stoull(value);
            }
            else if (key == "seed_high")
            {
                material->seed.high = std::stoull(value);
            }
        }
    }
    return true;
}
} // namespace dkg
} // namespace host
