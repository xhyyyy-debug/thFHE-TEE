#ifndef HOST_DKG_PREPROCESSING_STORE_HPP
#define HOST_DKG_PREPROCESSING_STORE_HPP

#include <string>

#include "keygen.hpp"

namespace host
{
namespace dkg
{
class PreprocessingStore
{
public:
    static std::string session_dir(const std::string& root_dir, const std::string& session_id);

    static bool save(
        const std::string& root_dir,
        const std::string& session_id,
        const DkgPlan& plan,
        const PreprocessedKeygenMaterial& material,
        std::string* error_message = nullptr);

    static bool load(
        const std::string& root_dir,
        const std::string& session_id,
        DkgPlan* plan,
        PreprocessedKeygenMaterial* material,
        std::string* error_message = nullptr);
};
} // namespace dkg
} // namespace host

#endif
