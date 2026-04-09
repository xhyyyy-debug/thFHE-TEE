#ifndef HOST_DKG_PREPROCESSING_ARTIFACTS_HPP
#define HOST_DKG_PREPROCESSING_ARTIFACTS_HPP

#include <string>

#include "dkg_artifacts.hpp"
#include "artifact_serialization.hpp"

namespace host
{
namespace dkg
{
class PreprocessingArtifactStore
{
public:
    // Session directories are party-local and hold the signed preprocessing
    // artifacts that keygen will later stream back into the enclave for checks.
    static std::string session_dir(const std::string& root_dir, const std::string& session_id);

    static bool open_reader(
        const std::string& root_dir,
        const std::string& session_id,
        PreprocessingStreamReader* reader,
        std::string* error_message = nullptr);
};
} // namespace dkg
} // namespace host

#endif
