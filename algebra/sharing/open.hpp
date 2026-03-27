#ifndef ALGEBRA_OPEN_HPP
#define ALGEBRA_OPEN_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#include "shamir_ring.hpp"

namespace algebra
{
namespace detail
{
inline std::vector<ResiduePolyF4Z128> poly_add(
    const std::vector<ResiduePolyF4Z128>& lhs,
    const std::vector<ResiduePolyF4Z128>& rhs)
{
    const size_t size = lhs.size() > rhs.size() ? lhs.size() : rhs.size();
    std::vector<ResiduePolyF4Z128> out(size, ResiduePolyF4Z128::zero());
    for (size_t i = 0; i < lhs.size(); ++i)
    {
        out[i] += lhs[i];
    }
    for (size_t i = 0; i < rhs.size(); ++i)
    {
        out[i] += rhs[i];
    }
    return out;
}

inline std::vector<ResiduePolyF4Z128> poly_mul(
    const std::vector<ResiduePolyF4Z128>& lhs,
    const std::vector<ResiduePolyF4Z128>& rhs)
{
    std::vector<ResiduePolyF4Z128> out(lhs.size() + rhs.size() - 1, ResiduePolyF4Z128::zero());
    for (size_t i = 0; i < lhs.size(); ++i)
    {
        for (size_t j = 0; j < rhs.size(); ++j)
        {
            out[i + j] += lhs[i] * rhs[j];
        }
    }
    return out;
}

inline std::vector<ResiduePolyF4Z128> scalar_mul(
    const std::vector<ResiduePolyF4Z128>& poly,
    const ResiduePolyF4Z128& scalar)
{
    std::vector<ResiduePolyF4Z128> out(poly.size(), ResiduePolyF4Z128::zero());
    for (size_t i = 0; i < poly.size(); ++i)
    {
        out[i] = poly[i] * scalar;
    }
    return out;
}

inline ResiduePolyF4Z128 evaluate_poly(
    const std::vector<ResiduePolyF4Z128>& poly,
    const ResiduePolyF4Z128& x)
{
    ResiduePolyF4Z128 out = ResiduePolyF4Z128::zero();
    for (size_t i = poly.size(); i-- > 0;)
    {
        out = out * x + poly[i];
    }
    return out;
}

inline bool interpolate_poly(
    const std::vector<RingShare>& shares,
    std::vector<ResiduePolyF4Z128>* out_poly)
{
    if (out_poly == nullptr || shares.empty())
    {
        return false;
    }

    std::vector<ResiduePolyF4Z128> poly(shares.size(), ResiduePolyF4Z128::zero());
    for (size_t i = 0; i < shares.size(); ++i)
    {
        const ResiduePolyF4Z128 xi =
            ResiduePolyF4Z128::embed_role_to_exceptional_sequence(shares[i].owner);
        std::vector<ResiduePolyF4Z128> basis{ResiduePolyF4Z128::one()};
        ResiduePolyF4Z128 denom = ResiduePolyF4Z128::one();

        for (size_t j = 0; j < shares.size(); ++j)
        {
            if (i == j)
            {
                continue;
            }
            const ResiduePolyF4Z128 xj =
                ResiduePolyF4Z128::embed_role_to_exceptional_sequence(shares[j].owner);
            basis = poly_mul(
                basis,
                std::vector<ResiduePolyF4Z128>{-xj, ResiduePolyF4Z128::one()});
            denom *= (xi - xj);
        }

        poly = poly_add(poly, scalar_mul(basis, shares[i].value * denom.invert()));
    }

    *out_poly = poly;
    return true;
}

inline void choose_subsets_rec(
    size_t start,
    size_t need,
    std::vector<size_t>* current,
    std::vector<std::vector<size_t>>* out,
    size_t total)
{
    if (need == 0)
    {
        out->push_back(*current);
        return;
    }

    for (size_t i = start; i + need <= total; ++i)
    {
        current->push_back(i);
        choose_subsets_rec(i + 1, need - 1, current, out, total);
        current->pop_back();
    }
}
} // namespace detail

class RingOpen
{
public:
    static bool open(
        const std::vector<RingShare>& shares,
        ResiduePolyF4Z128* out_secret)
    {
        return ShamirRing::reconstruct(shares, out_secret);
    }

    static bool robust_open(
        const std::vector<RingShare>& shares,
        size_t degree,
        size_t max_errors,
        ResiduePolyF4Z128* out_secret)
    {
        if (out_secret == nullptr || shares.size() < degree + 1)
        {
            return false;
        }

        std::vector<std::vector<size_t>> subsets;
        std::vector<size_t> current;
        detail::choose_subsets_rec(0, degree + 1, &current, &subsets, shares.size());

        for (const auto& subset : subsets)
        {
            std::vector<RingShare> chosen;
            chosen.reserve(subset.size());
            for (size_t idx : subset)
            {
                chosen.push_back(shares[idx]);
            }

            std::vector<ResiduePolyF4Z128> poly;
            if (!detail::interpolate_poly(chosen, &poly))
            {
                continue;
            }

            size_t mismatches = 0;
            for (const RingShare& share : shares)
            {
                const ResiduePolyF4Z128 x =
                    ResiduePolyF4Z128::embed_role_to_exceptional_sequence(share.owner);
                if (detail::evaluate_poly(poly, x) != share.value)
                {
                    ++mismatches;
                    if (mismatches > max_errors)
                    {
                        break;
                    }
                }
            }

            if (mismatches <= max_errors)
            {
                *out_secret = poly[0];
                return true;
            }
        }

        return false;
    }
};
} // namespace algebra

#endif
