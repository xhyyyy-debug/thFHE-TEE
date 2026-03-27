#ifndef HOST_DKG_PLANNER_HPP
#define HOST_DKG_PLANNER_HPP

#include <string>
#include <vector>

#include "params.hpp"

namespace host
{
namespace dkg
{
struct KeyMaterialShape
{
    size_t lwe_secret_bits = 0;
    size_t lwe_hat_secret_bits = 0;
    size_t glwe_secret_bits = 0;
    size_t compression_secret_bits = 0;
    size_t sns_glwe_secret_bits = 0;
    size_t sns_compression_secret_bits = 0;
    size_t bootstrap_ciphertexts = 0;
    size_t keyswitch_ciphertexts = 0;
    size_t public_key_ciphertexts = 0;
};

struct DkgPlan
{
    DkgParams params;
    PreprocessingRequirements preprocessing;
    KeyMaterialShape shape;
};

DkgPlan build_plan(const RuntimeConfig& config);
std::vector<std::string> format_plan_report(const DkgPlan& plan);
} // namespace dkg
} // namespace host

#endif
