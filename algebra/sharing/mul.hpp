#ifndef ALGEBRA_MUL_HPP
#define ALGEBRA_MUL_HPP

#include <cstddef>
#include <vector>

#include "open.hpp"

namespace algebra
{
struct RingTripleShare
{
    RingShare a;
    RingShare b;
    RingShare c;
};

class RingMul
{
public:
    static bool mult(
        const std::vector<RingShare>& x_shares,
        const std::vector<RingShare>& y_shares,
        const std::vector<RingTripleShare>& triple_shares,
        size_t degree,
        size_t max_errors,
        std::vector<RingShare>* out_product_shares,
        ResiduePolyF4Z128* out_epsilon = nullptr,
        ResiduePolyF4Z128* out_rho = nullptr)
    {
        if (out_product_shares == nullptr)
        {
            return false;
        }

        const size_t share_count = x_shares.size();
        if (share_count == 0 || share_count != y_shares.size() || share_count != triple_shares.size())
        {
            return false;
        }

        std::vector<RingShare> epsilon_shares;
        std::vector<RingShare> rho_shares;
        epsilon_shares.reserve(share_count);
        rho_shares.reserve(share_count);

        for (size_t i = 0; i < share_count; ++i)
        {
            const RingShare& x = x_shares[i];
            const RingShare& y = y_shares[i];
            const RingTripleShare& triple = triple_shares[i];
            if (x.owner == 0 ||
                x.owner != y.owner ||
                x.owner != triple.a.owner ||
                x.owner != triple.b.owner ||
                x.owner != triple.c.owner)
            {
                return false;
            }

            epsilon_shares.push_back(RingShare{ x.owner, triple.a.value + x.value });
            rho_shares.push_back(RingShare{ x.owner, triple.b.value + y.value });
        }

        ResiduePolyF4Z128 epsilon = ResiduePolyF4Z128::zero();
        ResiduePolyF4Z128 rho = ResiduePolyF4Z128::zero();
        if (!RingOpen::robust_open(epsilon_shares, degree, max_errors, &epsilon) ||
            !RingOpen::robust_open(rho_shares, degree, max_errors, &rho))
        {
            return false;
        }

        std::vector<RingShare> result;
        result.reserve(share_count);
        for (size_t i = 0; i < share_count; ++i)
        {
            const RingShare& y = y_shares[i];
            const RingTripleShare& triple = triple_shares[i];
            result.push_back(RingShare{
                y.owner,
                (y.value * epsilon) - (triple.a.value * rho) + triple.c.value
            });
        }

        if (out_epsilon != nullptr)
        {
            *out_epsilon = epsilon;
        }
        if (out_rho != nullptr)
        {
            *out_rho = rho;
        }

        *out_product_shares = result;
        return true;
    }

    static bool mult_list(
        const std::vector<std::vector<RingShare>>& x_share_lists,
        const std::vector<std::vector<RingShare>>& y_share_lists,
        const std::vector<std::vector<RingTripleShare>>& triple_share_lists,
        size_t degree,
        size_t max_errors,
        std::vector<std::vector<RingShare>>* out_product_share_lists)
    {
        if (out_product_share_lists == nullptr)
        {
            return false;
        }

        const size_t amount = x_share_lists.size();
        if (amount != y_share_lists.size() || amount != triple_share_lists.size())
        {
            return false;
        }

        std::vector<std::vector<RingShare>> result;
        result.reserve(amount);
        for (size_t i = 0; i < amount; ++i)
        {
            std::vector<RingShare> cur_result;
            if (!mult(
                    x_share_lists[i],
                    y_share_lists[i],
                    triple_share_lists[i],
                    degree,
                    max_errors,
                    &cur_result))
            {
                return false;
            }
            result.push_back(cur_result);
        }

        *out_product_share_lists = result;
        return true;
    }
};
} // namespace algebra

#endif
