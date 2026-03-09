#ifndef ALGEBRA_SHAMIR_HPP
#define ALGEBRA_SHAMIR_HPP

#include <array>
#include <cstddef>

#include "common.hpp"
#include "fields.hpp"
#include "polynomial.hpp"

namespace algebra
{
template<size_t MaxParties, size_t MaxDegree>
class ShamirSecretSharing
{
public:
    struct Share
    {
        Num x;
        Num y;
    };

    template<typename RandomFn>
    static std::array<Share, MaxParties> split(
        const RuntimePrimeField& field,
        Num secret,
        size_t threshold,
        size_t party_count,
        RandomFn&& random_fn)
    {
        Polynomial<MaxDegree> polynomial;
        polynomial.set_degree(threshold);
        polynomial.set_coefficient(0, field.mod(secret));

        for (size_t i = 1; i <= threshold; ++i)
        {
            polynomial.set_coefficient(i, field.mod(random_fn()));
        }

        std::array<Share, MaxParties> shares{};
        for (size_t i = 0; i < party_count; ++i)
        {
            const Num x = static_cast<Num>(i + 1);
            shares[i] = {x, polynomial.evaluate(field, x)};
        }

        return shares;
    }

    static Num reconstruct(
        const RuntimePrimeField& field,
        const Share* shares,
        size_t share_count)
    {
        Num secret = 0;

        for (size_t i = 0; i < share_count; ++i)
        {
            Num numerator = 1;
            Num denominator = 1;

            for (size_t j = 0; j < share_count; ++j)
            {
                if (i == j)
                {
                    continue;
                }

                numerator = field.mul(numerator, field.sub(0, shares[j].x));
                denominator = field.mul(denominator, field.sub(shares[i].x, shares[j].x));
            }

            const Num basis = field.mul(numerator, field.inv(denominator));
            secret = field.add(secret, field.mul(shares[i].y, basis));
        }

        return secret;
    }
};
} // namespace algebra

#endif
