#ifndef ALGEBRA_RINGS_HPP
#define ALGEBRA_RINGS_HPP

#include <array>
#include <cassert>
#include <cstddef>

#include "common.hpp"

namespace algebra
{
template<Num Degree, Num Modulus>
class Ring
{
public:
    std::array<Num, Degree> coeffs{};

    Ring()
    {
        coeffs.fill(0);
    }

    void mod_q()
    {
        for (size_t i = 0; i < Degree; ++i)
        {
            coeffs[i] %= Modulus;
        }
    }

    Ring add(const Ring& other) const
    {
        Ring result;
        for (size_t i = 0; i < Degree; ++i)
        {
            result.coeffs[i] = (coeffs[i] + other.coeffs[i]) % Modulus;
        }

        return result;
    }

    Ring sub(const Ring& other) const
    {
        Ring result;
        for (size_t i = 0; i < Degree; ++i)
        {
            result.coeffs[i] = (coeffs[i] + Modulus - other.coeffs[i] % Modulus) % Modulus;
        }

        return result;
    }

    Ring mul(const Ring& other) const
    {
        Ring result;

        for (size_t i = 0; i < Degree; ++i)
        {
            for (size_t j = 0; j < Degree; ++j)
            {
                const size_t index = (i + j) % Degree;
                const Num value = static_cast<Num>((static_cast<__uint128_t>(coeffs[i]) * other.coeffs[j]) % Modulus);

                if (i + j >= Degree)
                {
                    result.coeffs[index] = (result.coeffs[index] + Modulus - value) % Modulus;
                }
                else
                {
                    result.coeffs[index] = (result.coeffs[index] + value) % Modulus;
                }
            }
        }

        return result;
    }
};
} // namespace algebra

#endif
