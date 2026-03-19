#ifndef ALGEBRA_GALOIS_RING_HPP
#define ALGEBRA_GALOIS_RING_HPP

#include <array>
#include <cassert>
#include <cstdint>

namespace algebra
{
struct Z128
{
    uint64_t lo = 0;
    uint64_t hi = 0;

    constexpr Z128() = default;
    constexpr Z128(uint64_t lo_, uint64_t hi_) : lo(lo_), hi(hi_) {}

    static constexpr Z128 zero()
    {
        return Z128(0, 0);
    }

    static constexpr Z128 one()
    {
        return Z128(1, 0);
    }

    static constexpr Z128 two()
    {
        return Z128(2, 0);
    }

    static constexpr Z128 three()
    {
        return Z128(3, 0);
    }

    static constexpr Z128 max()
    {
        return Z128(~0ULL, ~0ULL);
    }

    static constexpr Z128 from_u64(uint64_t value)
    {
        return Z128(value, 0);
    }

    bool is_zero() const
    {
        return lo == 0 && hi == 0;
    }
};

inline Z128 operator+(Z128 lhs, Z128 rhs)
{
    const uint64_t lo = lhs.lo + rhs.lo;
    const uint64_t carry = (lo < lhs.lo) ? 1ULL : 0ULL;
    const uint64_t hi = lhs.hi + rhs.hi + carry;
    return Z128(lo, hi);
}

inline Z128 operator-(Z128 lhs, Z128 rhs)
{
    const uint64_t borrow = (lhs.lo < rhs.lo) ? 1ULL : 0ULL;
    const uint64_t lo = lhs.lo - rhs.lo;
    const uint64_t hi = lhs.hi - rhs.hi - borrow;
    return Z128(lo, hi);
}

inline Z128& operator+=(Z128& lhs, Z128 rhs)
{
    lhs = lhs + rhs;
    return lhs;
}

inline Z128& operator-=(Z128& lhs, Z128 rhs)
{
    lhs = lhs - rhs;
    return lhs;
}

inline Z128 operator-(Z128 value)
{
    return Z128::zero() - value;
}

inline bool operator==(Z128 lhs, Z128 rhs)
{
    return lhs.lo == rhs.lo && lhs.hi == rhs.hi;
}

inline bool operator!=(Z128 lhs, Z128 rhs)
{
    return !(lhs == rhs);
}

#if defined(_MSC_VER)
#include <intrin.h>
#endif

inline void mul64wide(uint64_t a, uint64_t b, uint64_t* lo, uint64_t* hi)
{
#if defined(_MSC_VER)
    *lo = _umul128(a, b, hi);
#else
    const unsigned __int128 prod = static_cast<unsigned __int128>(a) * b;
    *lo = static_cast<uint64_t>(prod);
    *hi = static_cast<uint64_t>(prod >> 64U);
#endif
}

inline Z128 operator*(Z128 lhs, Z128 rhs)
{
    uint64_t lo0 = 0;
    uint64_t hi0 = 0;
    uint64_t lo1 = 0;
    uint64_t hi1 = 0;
    uint64_t lo2 = 0;
    uint64_t hi2 = 0;

    mul64wide(lhs.lo, rhs.lo, &lo0, &hi0);
    mul64wide(lhs.lo, rhs.hi, &lo1, &hi1);
    mul64wide(lhs.hi, rhs.lo, &lo2, &hi2);

    const uint64_t hi = hi0 + lo1 + lo2;
    (void)hi1;
    (void)hi2;
    return Z128(lo0, hi);
}

inline Z128& operator*=(Z128& lhs, Z128 rhs)
{
    lhs = lhs * rhs;
    return lhs;
}

inline uint8_t extract_bit(Z128 value, size_t bit_idx)
{
    if (bit_idx < 64)
    {
        return static_cast<uint8_t>((value.lo >> bit_idx) & 1ULL);
    }
    const size_t shift = bit_idx - 64;
    return static_cast<uint8_t>((value.hi >> shift) & 1ULL);
}

inline uint8_t gf16_mul(uint8_t a, uint8_t b)
{
    uint8_t res = 0;
    uint8_t tmp = a;
    for (int i = 0; i < 4; ++i)
    {
        if ((b >> i) & 1U)
        {
            res ^= tmp;
        }
        const bool carry = (tmp & 0x8U) != 0;
        tmp <<= 1U;
        if (carry)
        {
            tmp ^= 0x3U;
        }
        tmp &= 0xFU;
    }
    return res & 0xFU;
}

inline uint8_t gf16_pow(uint8_t a, uint8_t exp)
{
    uint8_t res = 1;
    uint8_t base = a & 0xFU;
    while (exp > 0)
    {
        if (exp & 1U)
        {
            res = gf16_mul(res, base);
        }
        base = gf16_mul(base, base);
        exp >>= 1U;
    }
    return res & 0xFU;
}

inline uint8_t gf16_inv(uint8_t a)
{
    assert(a != 0);
    return gf16_pow(a, 14);
}

struct ResiduePolyF4Z128;

inline ResiduePolyF4Z128 operator+(ResiduePolyF4Z128 lhs, ResiduePolyF4Z128 rhs);
inline ResiduePolyF4Z128 operator-(ResiduePolyF4Z128 lhs, ResiduePolyF4Z128 rhs);
inline ResiduePolyF4Z128 operator-(ResiduePolyF4Z128 value);
inline ResiduePolyF4Z128 operator*(ResiduePolyF4Z128 lhs, ResiduePolyF4Z128 rhs);

struct ResiduePolyF4Z128
{
    std::array<Z128, 4> coefs{};

    static ResiduePolyF4Z128 zero()
    {
        return ResiduePolyF4Z128{ { Z128::zero(), Z128::zero(), Z128::zero(), Z128::zero() } };
    }

    static ResiduePolyF4Z128 one()
    {
        return ResiduePolyF4Z128{ { Z128::one(), Z128::zero(), Z128::zero(), Z128::zero() } };
    }

    static ResiduePolyF4Z128 two()
    {
        return ResiduePolyF4Z128{ { Z128::two(), Z128::zero(), Z128::zero(), Z128::zero() } };
    }

    static ResiduePolyF4Z128 three()
    {
        return ResiduePolyF4Z128{ { Z128::three(), Z128::zero(), Z128::zero(), Z128::zero() } };
    }

    static ResiduePolyF4Z128 from_scalar(Z128 value)
    {
        return ResiduePolyF4Z128{ { value, Z128::zero(), Z128::zero(), Z128::zero() } };
    }

    static ResiduePolyF4Z128 from_exceptional_sequence(size_t idx)
    {
        assert(idx < 16);
        ResiduePolyF4Z128 out = zero();
        for (size_t i = 0; i < 4; ++i)
        {
            if ((idx >> i) & 1U)
            {
                out.coefs[i] = Z128::one();
            }
        }
        return out;
    }

    static ResiduePolyF4Z128 embed_role_to_exceptional_sequence(uint64_t role_id)
    {
        return from_exceptional_sequence(static_cast<size_t>(role_id));
    }

    template<typename RandomFn>
    static ResiduePolyF4Z128 sample(RandomFn&& random_fn)
    {
        ResiduePolyF4Z128 out{};
        for (size_t i = 0; i < 4; ++i)
        {
            out.coefs[i] = random_fn();
        }
        return out;
    }

    bool is_zero() const
    {
        for (const auto& c : coefs)
        {
            if (!c.is_zero())
            {
                return false;
            }
        }
        return true;
    }

    uint8_t bit_compose(size_t bit_idx) const
    {
        uint8_t x = 0;
        for (size_t i = 0; i < 4; ++i)
        {
            const uint8_t bit = extract_bit(coefs[i], bit_idx);
            x |= static_cast<uint8_t>(bit << i);
        }
        return x & 0xFU;
    }

    ResiduePolyF4Z128 invert() const
    {
        assert(!is_zero());
        const uint8_t alpha = bit_compose(0);
        const uint8_t ainv = gf16_inv(alpha);
        ResiduePolyF4Z128 x0 = from_exceptional_sequence(ainv);
        const ResiduePolyF4Z128 two_val = two();

        for (size_t i = 0; i < 7; ++i)
        {
            x0 = x0 * (two_val - (*this * x0));
        }

        return x0;
    }

    void mul_by_x()
    {
        const Z128 last = coefs[3];
        for (size_t i = 3; i > 0; --i)
        {
            coefs[i] = coefs[i - 1];
        }
        coefs[0] = -last;
        coefs[1] -= last;
    }
};

inline ResiduePolyF4Z128 operator+(ResiduePolyF4Z128 lhs, ResiduePolyF4Z128 rhs)
{
    for (size_t i = 0; i < 4; ++i)
    {
        lhs.coefs[i] += rhs.coefs[i];
    }
    return lhs;
}

inline ResiduePolyF4Z128 operator-(ResiduePolyF4Z128 lhs, ResiduePolyF4Z128 rhs)
{
    for (size_t i = 0; i < 4; ++i)
    {
        lhs.coefs[i] -= rhs.coefs[i];
    }
    return lhs;
}

inline ResiduePolyF4Z128 operator-(ResiduePolyF4Z128 value)
{
    for (size_t i = 0; i < 4; ++i)
    {
        value.coefs[i] = -value.coefs[i];
    }
    return value;
}

inline ResiduePolyF4Z128& operator+=(ResiduePolyF4Z128& lhs, ResiduePolyF4Z128 rhs)
{
    lhs = lhs + rhs;
    return lhs;
}

inline ResiduePolyF4Z128& operator-=(ResiduePolyF4Z128& lhs, ResiduePolyF4Z128 rhs)
{
    lhs = lhs - rhs;
    return lhs;
}

inline std::array<Z128, 3> karatsuba_2(const std::array<Z128, 2>& a, const std::array<Z128, 2>& b)
{
    const Z128 z0 = a[1] * b[1];
    const Z128 z2 = a[0] * b[0];
    const Z128 z3 = (a[0] + a[1]) * (b[0] + b[1]);
    const Z128 z1 = z3 - z2 - z0;
    return { z2, z1, z0 };
}

inline std::array<Z128, 7> karatsuba_4(const std::array<Z128, 4>& a, const std::array<Z128, 4>& b)
{
    const std::array<Z128, 2> a_hi{ { a[2], a[3] } };
    const std::array<Z128, 2> b_hi{ { b[2], b[3] } };
    const std::array<Z128, 2> a_lo{ { a[0], a[1] } };
    const std::array<Z128, 2> b_lo{ { b[0], b[1] } };
    const std::array<Z128, 2> a_sum{ { a[0] + a[2], a[1] + a[3] } };
    const std::array<Z128, 2> b_sum{ { b[0] + b[2], b[1] + b[3] } };

    const auto z0 = karatsuba_2(a_hi, b_hi);
    const auto z2 = karatsuba_2(a_lo, b_lo);
    const auto z3 = karatsuba_2(a_sum, b_sum);
    const std::array<Z128, 3> z1{ { z3[0] - z2[0] - z0[0],
                                    z3[1] - z2[1] - z0[1],
                                    z3[2] - z2[2] - z0[2] } };

    return { z2[0],
             z2[1],
             z2[2] + z1[0],
             z1[1],
             z1[2] + z0[0],
             z0[1],
             z0[2] };
}

inline ResiduePolyF4Z128 reduce_mul(const std::array<Z128, 7>& coefs)
{
    ResiduePolyF4Z128 res = ResiduePolyF4Z128::zero();
    res.coefs[0] = coefs[0];
    res.coefs[1] = coefs[1];
    res.coefs[2] = coefs[2];
    res.coefs[3] = coefs[3];

    const std::array<std::array<Z128, 4>, 3> table{ {
        { Z128::max(), Z128::max(), Z128::zero(), Z128::zero() },
        { Z128::zero(), Z128::max(), Z128::max(), Z128::zero() },
        { Z128::zero(), Z128::zero(), Z128::max(), Z128::max() },
    } };

    for (size_t i = 4; i < 7; ++i)
    {
        const size_t idx = i - 4;
        for (size_t j = 0; j < 4; ++j)
        {
            res.coefs[j] += table[idx][j] * coefs[i];
        }
    }

    return res;
}

inline ResiduePolyF4Z128 operator*(ResiduePolyF4Z128 lhs, ResiduePolyF4Z128 rhs)
{
    const auto extended = karatsuba_4(lhs.coefs, rhs.coefs);
    return reduce_mul(extended);
}

inline ResiduePolyF4Z128& operator*=(ResiduePolyF4Z128& lhs, ResiduePolyF4Z128 rhs)
{
    lhs = lhs * rhs;
    return lhs;
}
} // namespace algebra

#endif
