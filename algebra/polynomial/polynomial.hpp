#ifndef ALGEBRA_POLYNOMIAL_HPP
#define ALGEBRA_POLYNOMIAL_HPP

#include <array>
#include <cstddef>

#include "../base/common.hpp"
#include "../base/fields.hpp"

namespace algebra
{
template<size_t MaxDegree>
class Polynomial
{
public:
    Polynomial()
    {
        coeffs_.fill(0);
    }

    void set_degree(size_t degree)
    {
        degree_ = degree;
    }

    size_t degree() const
    {
        return degree_;
    }

    void set_coefficient(size_t index, Num value)
    {
        coeffs_[index] = value;
        if (index > degree_)
        {
            degree_ = index;
        }
    }

    Num coefficient(size_t index) const
    {
        return coeffs_[index];
    }

    Num evaluate(const RuntimePrimeField& field, Num x) const
    {
        Num result = 0;
        Num power = 1;

        for (size_t i = 0; i <= degree_; ++i)
        {
            result = field.add(result, field.mul(coeffs_[i], power));
            power = field.mul(power, x);
        }

        return result;
    }

private:
    size_t degree_ = 0;
    std::array<Num, MaxDegree + 1> coeffs_{};
};
} // namespace algebra

#endif
