#ifndef HOST_DKG_PLANNER_HPP
#define HOST_DKG_PLANNER_HPP

#include <string>
#include <vector>

#include "params.hpp"

namespace host
{
namespace dkg
{
// Counts the logical shape of the secret vectors and output key material for a
// given DKG parameter set. This is the bridge between parameters and workflow.
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

// A DKG plan is the canonical "execution contract" shared by preprocessing and
// keygen: it fixes parameters, expected preprocessing counts, and key shapes.
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
