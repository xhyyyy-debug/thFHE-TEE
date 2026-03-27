#ifndef HOST_DKG_KEYGEN_HPP
#define HOST_DKG_KEYGEN_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "../../algebra/sharing/mul.hpp"
#include "../../enclave/common/noise_types.h"
#include "../config/config.hpp"
#include "encryption.hpp"
#include "planner.hpp"

namespace host
{
namespace dkg
{
struct PublicSeed
{
    uint64_t low = 0;
    uint64_t high = 0;
};

struct SharedBitVector
{
    uint64_t round_id = 0;
    uint64_t sigma = 0;
    std::vector<algebra::RingShare> shares;
};

struct SharedNoiseVector
{
    NoiseKind kind = NoiseKind::kLwe;
    uint32_t bound_bits = 0;
    uint64_t round_id = 0;
    uint64_t sigma = 0;
    std::vector<algebra::RingShare> shares;
};

struct SharedTripleVector
{
    uint64_t round_id = 0;
    uint64_t sigma = 0;
    std::vector<algebra::RingTripleShare> triples;
};

struct PreprocessedKeygenMaterial
{
    PublicSeed seed;
    std::vector<SharedBitVector> raw_bits;
    std::vector<SharedNoiseVector> noises;
    std::vector<SharedTripleVector> triples;
};

struct SecretKeyShares
{
    std::vector<algebra::RingShare> lwe;
    std::vector<algebra::RingShare> lwe_hat;
    std::vector<algebra::RingShare> glwe;
    std::vector<algebra::RingShare> compression_glwe;
    std::vector<algebra::RingShare> sns_glwe;
    std::vector<algebra::RingShare> sns_compression_glwe;
};

struct PublicKeyMaterial
{
    std::vector<SharedLweCiphertext> pk;
    std::vector<SharedLevCiphertext> pksk_lwe;
    std::vector<SharedGlevCiphertext> pksk_glwe;
    std::vector<SharedLevCiphertext> ksk;
    std::vector<SharedGgswCiphertext> bk;
    std::vector<SharedGgswCiphertext> bk_sns;
    std::vector<SharedGgswCiphertext> compression_key;
    std::vector<SharedGlevCiphertext> decompression_key;
    std::vector<SharedGgswCiphertext> sns_compression_key;
};

struct KeygenOutput
{
    DkgPlan plan;
    PublicSeed public_seed;
    SecretKeyShares secret_shares;
    PublicKeyMaterial public_material;
};

struct SecretKeyBundle
{
    DkgPlan plan;
    PublicSeed public_seed;
    SecretKeyShares secret_shares;
};

struct PublicKeyBundle
{
    DkgPlan plan;
    PublicSeed public_seed;
    PublicKeyMaterial public_material;
};

class DistributedKeyGen
{
public:
    static DkgPlan make_plan(const RuntimeConfig& config)
    {
        return build_plan(config);
    }

    static bool validate_preprocessing(
        const DkgPlan& plan,
        const PreprocessedKeygenMaterial& material,
        std::string* error_message = nullptr);

    static bool keygen(
        const RuntimeConfig& config,
        uint64_t my_party_id,
        const PreprocessedKeygenMaterial& material,
        KeygenOutput* out,
        std::string* error_message = nullptr);
};
} // namespace dkg
} // namespace host

#endif
