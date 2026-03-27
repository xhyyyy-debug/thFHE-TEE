#ifndef HOST_DKG_ENCRYPTION_HPP
#define HOST_DKG_ENCRYPTION_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#include "../../algebra/sharing/mul.hpp"
#include "../../enclave/common/noise_types.h"
#include "params.hpp"

namespace host
{
namespace dkg
{
struct PublicSeed
{
    uint64_t low = 0;
    uint64_t high = 0;
};

struct SharedLweCiphertext
{
    std::vector<noise::RingElementRaw> a;
    algebra::RingShare b;
};

struct SharedGlweCiphertext
{
    std::vector<noise::RingElementRaw> a;
    algebra::RingShare b;
};

struct SharedLevCiphertext
{
    std::vector<SharedLweCiphertext> levels;
};

struct SharedGlevCiphertext
{
    std::vector<SharedGlweCiphertext> levels;
};

struct SharedGgswCiphertext
{
    std::vector<SharedGlevCiphertext> rows;
};

class DistributedEncryption
{
public:
    static bool enc_lwe(
        const PublicSeed& seed,
        uint64_t seed_offset,
        const noise::RingElementRaw& message,
        const std::vector<algebra::RingShare>& lwe_secret,
        const algebra::RingShare& noise_share,
        size_t lwe_dimension,
        bool include_mask,
        SharedLweCiphertext* out);

    static bool enc_glwe(
        const PublicSeed& seed,
        uint64_t seed_offset,
        const noise::RingElementRaw& message,
        const std::vector<algebra::RingShare>& glwe_secret,
        const algebra::RingShare& noise_share,
        size_t glwe_dimension,
        bool include_mask,
        SharedGlweCiphertext* out);

    static bool enc_lev(
        const PublicSeed& seed,
        uint64_t seed_offset,
        const noise::RingElementRaw& message,
        const std::vector<algebra::RingShare>& lwe_secret,
        const std::vector<algebra::RingShare>& noise_shares,
        size_t lwe_dimension,
        size_t base_log,
        size_t level_count,
        bool include_mask,
        SharedLevCiphertext* out);

    static bool enc_glev(
        const PublicSeed& seed,
        uint64_t seed_offset,
        const noise::RingElementRaw& message,
        const std::vector<algebra::RingShare>& glwe_secret,
        const std::vector<algebra::RingShare>& noise_shares,
        size_t glwe_dimension,
        size_t base_log,
        size_t level_count,
        bool include_mask,
        SharedGlevCiphertext* out);

    static bool enc_ggsw(
        const PublicSeed& seed,
        uint64_t seed_offset,
        const noise::RingElementRaw& message,
        const std::vector<algebra::RingShare>& secret_bits,
        const std::vector<algebra::RingShare>& glwe_secret,
        const std::vector<algebra::RingShare>& multiplied_secret_messages,
        const std::vector<std::vector<algebra::RingShare>>& noise_shares_by_row,
        size_t glwe_dimension,
        size_t base_log,
        size_t level_count,
        bool include_mask,
        SharedGgswCiphertext* out);
};
} // namespace dkg
} // namespace host

#endif
