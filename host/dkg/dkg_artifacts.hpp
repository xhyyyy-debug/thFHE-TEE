#ifndef HOST_DKG_DKG_ARTIFACTS_HPP
#define HOST_DKG_DKG_ARTIFACTS_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "../../algebra/sharing/mul.hpp"
#include "../../enclave/common/noise_types.h"
#include "encryption.hpp"
#include "planner.hpp"

namespace host
{
namespace dkg
{
// Preprocessing records are stored as party-local signed vectors. Even when the
// runtime consumes them in streaming form, these types remain the canonical schema.
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

// Secret shares that remain private to one party after key generation.
struct SecretKeyShares
{
    std::vector<algebra::RingShare> lwe;
    std::vector<algebra::RingShare> lwe_hat;
    std::vector<algebra::RingShare> glwe;
    std::vector<algebra::RingShare> compression_glwe;
    std::vector<algebra::RingShare> sns_glwe;
    std::vector<algebra::RingShare> sns_compression_glwe;
};

// Public key material produced by the DKG. Large online paths now stream this
// directly to disk, but the structure is still useful as a serialization schema.
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
    SharedLwePackingKeyswitchKey sns_compression_key;
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
} // namespace dkg
} // namespace host

#endif
