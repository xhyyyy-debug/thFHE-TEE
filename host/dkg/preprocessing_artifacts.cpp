#include "preprocessing_artifacts.hpp"

#include <filesystem>

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
} // namespace

std::string PreprocessingArtifactStore::session_dir(const std::string& root_dir, const std::string& session_id)
{
    return (std::filesystem::path(root_dir) / session_id).string();
}

bool PreprocessingArtifactStore::open_reader(
    const std::string& root_dir,
    const std::string& session_id,
    PreprocessingStreamReader* reader,
    std::string* error_message)
{
    if (reader == nullptr)
    {
        return set_error(error_message, "Null reader passed to preprocessing open_reader");
    }
    const std::filesystem::path dir = session_dir(root_dir, session_id);
    return reader->open((dir / "preprocessing.bin").string(), error_message);
}
} // namespace dkg
} // namespace host
