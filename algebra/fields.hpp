#ifndef ALGEBRA_FIELDS_HPP
#define ALGEBRA_FIELDS_HPP

#include <cassert>
#include <cstdint>

#include "common.hpp"

namespace algebra
{
template<Num Modulus>
class PrimeField
{
public:
    static constexpr Num modulus = Modulus;

    static Num mod(Num value)
    {
        return value % modulus;
    }

    static Num add(Num lhs, Num rhs)
    {
        return (lhs + rhs) % modulus;
    }

    static Num sub(Num lhs, Num rhs)
    {
        return (lhs + modulus - (rhs % modulus)) % modulus;
    }

    static Num mul(Num lhs, Num rhs)
    {
        return static_cast<Num>((static_cast<__uint128_t>(lhs) * rhs) % modulus);
    }

    static Num pow(Num base, Num exponent)
    {
        Num result = 1;
        base %= modulus;

        while (exponent != 0)
        {
            if ((exponent & 1U) != 0)
            {
                result = mul(result, base);
            }

            base = mul(base, base);
            exponent >>= 1U;
        }

        return result;
    }

    static Num inv(Num value)
    {
        assert(value % modulus != 0);
        return pow(value, modulus - 2);
    }
};

class RuntimePrimeField
{
public:
    explicit RuntimePrimeField(Num modulus) : modulus_(modulus)
    {
        assert(modulus_ > 2);
    }

    Num modulus() const
    {
        return modulus_;
    }

    Num mod(Num value) const
    {
        return value % modulus_;
    }

    Num add(Num lhs, Num rhs) const
    {
        return (lhs + rhs) % modulus_;
    }

    Num sub(Num lhs, Num rhs) const
    {
        return (lhs + modulus_ - (rhs % modulus_)) % modulus_;
    }

    Num mul(Num lhs, Num rhs) const
    {
        return static_cast<Num>((static_cast<__uint128_t>(lhs) * rhs) % modulus_);
    }

    Num pow(Num base, Num exponent) const
    {
        Num result = 1;
        base %= modulus_;

        while (exponent != 0)
        {
            if ((exponent & 1U) != 0)
            {
                result = mul(result, base);
            }

            base = mul(base, base);
            exponent >>= 1U;
        }

        return result;
    }

    Num inv(Num value) const
    {
        assert(value % modulus_ != 0);
        return pow(value, modulus_ - 2);
    }

private:
    Num modulus_;
};
} // namespace algebra

#endif
