#include "planner.hpp"

#include <sstream>

namespace host
{
namespace dkg
{
DkgPlan build_plan(const RuntimeConfig& config)
{
    DkgPlan plan;
    plan.params = from_runtime_config(config);
    plan.preprocessing = compute_preprocessing_requirements(plan.params);

    plan.shape.lwe_secret_bits = plan.params.regular.lwe_dimension;
    plan.shape.lwe_hat_secret_bits = plan.params.regular.lwe_hat_dimension;
    plan.shape.glwe_secret_bits = plan.params.regular.glwe_dimension * plan.params.regular.polynomial_size;
    plan.shape.compression_secret_bits = plan.params.regular.compression.enabled ?
        plan.params.regular.compression.packing_ks_glwe_dimension * plan.params.regular.compression.packing_ks_polynomial_size :
        0;
    plan.shape.sns_glwe_secret_bits = plan.params.sns.enabled ?
        plan.params.sns.glwe_dimension * plan.params.sns.polynomial_size :
        0;
    plan.shape.sns_compression_secret_bits = plan.params.sns.compression.enabled ?
        plan.params.sns.compression.packing_ks_glwe_dimension * plan.params.sns.compression.packing_ks_polynomial_size :
        0;
    plan.shape.bootstrap_ciphertexts =
        plan.params.regular.lwe_dimension *
        (plan.params.regular.glwe_dimension + 1) *
        plan.params.regular.bk_level *
        plan.params.regular.polynomial_size;
    plan.shape.keyswitch_ciphertexts =
        plan.shape.glwe_secret_bits * plan.params.regular.ks_level;
    plan.shape.public_key_ciphertexts = plan.params.regular.lwe_hat_dimension;
    return plan;
}

std::vector<std::string> format_plan_report(const DkgPlan& plan)
{
    std::vector<std::string> lines;

    {
        std::ostringstream out;
        out << "preset=" << plan.params.preset_name
            << " keyset_mode=" << to_string(plan.params.keyset_mode)
            << " msg_mod=" << plan.params.regular.message_modulus
            << " carry_mod=" << plan.params.regular.carry_modulus
            << " enc_key=" << to_string(plan.params.regular.encryption_key_choice)
            << " log2_p_fail=" << plan.params.regular.log2_p_fail;
        lines.push_back(out.str());
    }

    {
        std::ostringstream out;
        out << "raw_secret_bits=" << plan.preprocessing.raw_secret_bits
            << " total_bits=" << plan.preprocessing.total_bits
            << " total_triples=" << plan.preprocessing.total_triples
            << " total_randomness=" << plan.preprocessing.total_randomness;
        lines.push_back(out.str());
    }

    {
        std::ostringstream out;
        out << "shape lwe_sk=" << plan.shape.lwe_secret_bits
            << " lwe_hat_sk=" << plan.shape.lwe_hat_secret_bits
            << " glwe_sk=" << plan.shape.glwe_secret_bits
            << " comp_sk=" << plan.shape.compression_secret_bits
            << " sns_glwe_sk=" << plan.shape.sns_glwe_secret_bits
            << " sns_comp_sk=" << plan.shape.sns_compression_secret_bits;
        lines.push_back(out.str());
    }

    {
        std::ostringstream out;
        out << "ciphertexts pk=" << plan.shape.public_key_ciphertexts
            << " ksk=" << plan.shape.keyswitch_ciphertexts
            << " bk=" << plan.shape.bootstrap_ciphertexts;
        lines.push_back(out.str());
    }

    for (const NoiseInfo& noise : plan.preprocessing.noise_batches)
    {
        if (noise.amount == 0)
        {
            continue;
        }
        std::ostringstream out;
        out << "noise kind=" << to_string(noise.kind)
            << " amount=" << noise.amount
            << " bound_bits=" << noise.bound_bits;
        lines.push_back(out.str());
    }

    return lines;
}
} // namespace dkg
} // namespace host
