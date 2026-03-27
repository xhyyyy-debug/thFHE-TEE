#ifndef HOST_DKG_SERIALIZATION_HPP
#define HOST_DKG_SERIALIZATION_HPP

#include <string>

#include "keygen.hpp"

namespace host
{
namespace dkg
{
bool save_preprocessing_bundle(
    const std::string& path,
    const DkgPlan& plan,
    const PreprocessedKeygenMaterial& material,
    std::string* error_message = nullptr);

bool load_preprocessing_bundle(
    const std::string& path,
    DkgPlan* plan,
    PreprocessedKeygenMaterial* material,
    std::string* error_message = nullptr);

bool save_keygen_output_file(
    const std::string& path,
    const KeygenOutput& output,
    std::string* error_message = nullptr);

bool load_keygen_output_file(
    const std::string& path,
    KeygenOutput* output,
    std::string* error_message = nullptr);

bool save_secret_key_file(
    const std::string& path,
    const SecretKeyBundle& bundle,
    std::string* error_message = nullptr);

bool load_secret_key_file(
    const std::string& path,
    SecretKeyBundle* bundle,
    std::string* error_message = nullptr);

bool save_public_key_file(
    const std::string& path,
    const PublicKeyBundle& bundle,
    std::string* error_message = nullptr);

bool load_public_key_file(
    const std::string& path,
    PublicKeyBundle* bundle,
    std::string* error_message = nullptr);
} // namespace dkg
} // namespace host

#endif
