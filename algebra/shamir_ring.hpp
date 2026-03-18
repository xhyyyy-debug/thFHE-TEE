#ifndef ALGEBRA_SHAMIR_RING_HPP
#define ALGEBRA_SHAMIR_RING_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#include "galois_ring.hpp"

namespace algebra
{
struct RingShare
{
    uint64_t owner = 0;
    ResiduePolyF4Z128 value = ResiduePolyF4Z128::zero();
};

class ShamirRing
{
public:
    template<typename RandomFn>
    static std::vector<RingShare> share(
        const ResiduePolyF4Z128& secret,
        size_t num_parties,
        size_t threshold,
        RandomFn&& random_fn)
    {
        if (threshold >= num_parties)
        {
            return {};
        }

        std::vector<ResiduePolyF4Z128> poly(threshold + 1);
        poly[0] = secret;
        for (size_t i = 1; i <= threshold; ++i)
        {
            poly[i] = ResiduePolyF4Z128::sample(random_fn);
        }

        std::vector<RingShare> shares;
        shares.reserve(num_parties);

        for (size_t i = 0; i < num_parties; ++i)
        {
            const uint64_t role_id = static_cast<uint64_t>(i + 1);
            const ResiduePolyF4Z128 x =
                ResiduePolyF4Z128::embed_role_to_exceptional_sequence(role_id);

            ResiduePolyF4Z128 y = poly[threshold];
            for (size_t j = threshold; j-- > 0;)
            {
                y = y * x + poly[j];
            }

            shares.push_back(RingShare{role_id, y});
        }

        return shares;
    }

    static bool reconstruct(
        const std::vector<RingShare>& shares,
        ResiduePolyF4Z128* out_secret)
    {
        if (out_secret == nullptr || shares.empty())
        {
            return false;
        }

        ResiduePolyF4Z128 secret = ResiduePolyF4Z128::zero();

        for (size_t i = 0; i < shares.size(); ++i)
        {
            const ResiduePolyF4Z128 xi =
                ResiduePolyF4Z128::embed_role_to_exceptional_sequence(shares[i].owner);
            ResiduePolyF4Z128 numerator = ResiduePolyF4Z128::one();
            ResiduePolyF4Z128 denominator = ResiduePolyF4Z128::one();

            for (size_t j = 0; j < shares.size(); ++j)
            {
                if (i == j)
                {
                    continue;
                }

                const ResiduePolyF4Z128 xj =
                    ResiduePolyF4Z128::embed_role_to_exceptional_sequence(shares[j].owner);
                numerator = numerator * (-xj);
                denominator = denominator * (xi - xj);
            }

            const ResiduePolyF4Z128 basis = numerator * denominator.invert();
            secret += shares[i].value * basis;
        }

        *out_secret = secret;
        return true;
    }
};
} // namespace algebra

#endif
