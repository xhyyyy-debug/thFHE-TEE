#ifndef NOISE_PRSS_PRF_H
#define NOISE_PRSS_PRF_H

#include <array>
#include <cstdint>
#include <vector>

#include <mbedtls/aes.h>

#include "../common/noise_types.h"

namespace noise
{
namespace prss
{
constexpr uint8_t kPhiXorConstant = 2;
constexpr uint8_t kChiXorConstant = 1;

struct SessionId128
{
    uint64_t lo = 0;
    uint64_t hi = 0;
};

struct PrfKey
{
    std::array<uint8_t, 16> bytes{};
};

inline void store_u64_le(uint64_t value, uint8_t* out)
{
    for (size_t i = 0; i < 8; ++i)
    {
        out[i] = static_cast<uint8_t>((value >> (8U * i)) & 0xffU);
    }
}

inline std::array<uint8_t, 16> session_id_to_bytes(SessionId128 sid)
{
    std::array<uint8_t, 16> out{};
    store_u64_le(sid.lo, out.data());
    store_u64_le(sid.hi, out.data() + 8);
    return out;
}

inline void xor_16(std::array<uint8_t, 16>* lhs, const std::array<uint8_t, 16>& rhs)
{
    for (size_t i = 0; i < lhs->size(); ++i)
    {
        (*lhs)[i] ^= rhs[i];
    }
}

class Aes128Ecb
{
public:
    Aes128Ecb()
    {
        mbedtls_aes_init(&ctx_);
    }

    explicit Aes128Ecb(const std::array<uint8_t, 16>& key)
        : Aes128Ecb()
    {
        set_key(key);
    }

    Aes128Ecb(const Aes128Ecb& other)
        : Aes128Ecb(other.key_)
    {
    }

    Aes128Ecb& operator=(const Aes128Ecb& other)
    {
        if (this != &other)
        {
            set_key(other.key_);
        }
        return *this;
    }

    ~Aes128Ecb()
    {
        mbedtls_aes_free(&ctx_);
    }

    void set_key(const std::array<uint8_t, 16>& key)
    {
        key_ = key;
        mbedtls_aes_free(&ctx_);
        mbedtls_aes_init(&ctx_);
        mbedtls_aes_setkey_enc(&ctx_, key_.data(), 128);
    }

    std::array<uint8_t, 16> encrypt_block(const std::array<uint8_t, 16>& block) const
    {
        std::array<uint8_t, 16> out{};
        mbedtls_aes_context copy;
        mbedtls_aes_init(&copy);
        mbedtls_aes_setkey_enc(&copy, key_.data(), 128);
        mbedtls_aes_crypt_ecb(&copy, MBEDTLS_AES_ENCRYPT, block.data(), out.data());
        mbedtls_aes_free(&copy);
        return out;
    }

private:
    std::array<uint8_t, 16> key_{};
    mutable mbedtls_aes_context ctx_{};
};

inline algebra::Z128 load_z128_le(const std::array<uint8_t, 16>& bytes)
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    for (size_t i = 0; i < 8; ++i)
    {
        lo |= static_cast<uint64_t>(bytes[i]) << (8U * i);
        hi |= static_cast<uint64_t>(bytes[8 + i]) << (8U * i);
    }
    return algebra::Z128(lo, hi);
}

inline std::array<uint8_t, 16> make_ctr_bytes(uint64_t lo, uint64_t hi)
{
    std::array<uint8_t, 16> out{};
    store_u64_le(lo, out.data());
    store_u64_le(hi, out.data() + 8);
    return out;
}

inline std::array<uint8_t, 16> tweak_key(
    const PrfKey& key,
    SessionId128 sid,
    uint8_t xor_constant)
{
    std::array<uint8_t, 16> out = key.bytes;
    out[0] ^= xor_constant;
    xor_16(&out, session_id_to_bytes(sid));
    return out;
}

class PhiAes
{
public:
    PhiAes() = default;
    PhiAes(const PrfKey& key, SessionId128 sid)
        : aes_(tweak_key(key, sid, kPhiXorConstant))
    {
    }

    int sample(uint64_t ctr_lo, uint64_t ctr_hi, uint64_t bd1, int64_t* out) const
    {
        if (out == nullptr || bd1 == 0 || ctr_hi >= (1ULL << 56U))
        {
            return kInvalidArgument;
        }

        std::array<uint8_t, 16> block = make_ctr_bytes(ctr_lo, ctr_hi);
        block[15] = 0;
        const std::array<uint8_t, 16> enc = aes_.encrypt_block(block);
        const algebra::Z128 z = load_z128_le(enc);
        const uint64_t mod = bd1 * 2;
        const uint64_t sample = z.lo % mod;
        *out = -static_cast<int64_t>(bd1) + static_cast<int64_t>(sample);
        return kOk;
    }

private:
    Aes128Ecb aes_;
};

class PsiAes
{
public:
    PsiAes() = default;
    PsiAes(const PrfKey& key, SessionId128 sid)
        : aes_(tweak_key(key, sid, 0))
    {
    }

    int sample(uint64_t ctr_lo, uint64_t ctr_hi, RingElement* out) const
    {
        if (out == nullptr || ctr_hi >= (1ULL << 48U))
        {
            return kInvalidArgument;
        }

        RingElement value = RingElement::zero();
        for (uint8_t i = 0; i < 4; ++i)
        {
            std::array<uint8_t, 16> block = make_ctr_bytes(ctr_lo, ctr_hi);
            block[15] = 0;
            block[14] = i;
            value.coefs[i] = load_z128_le(aes_.encrypt_block(block));
        }

        *out = value;
        return kOk;
    }

private:
    Aes128Ecb aes_;
};

class ChiAes
{
public:
    ChiAes() = default;
    ChiAes(const PrfKey& key, SessionId128 sid)
        : aes_(tweak_key(key, sid, kChiXorConstant))
    {
    }

    int sample(uint64_t ctr_lo, uint64_t ctr_hi, uint8_t j, RingElement* out) const
    {
        if (out == nullptr || ctr_hi >= (1ULL << 40U) || j == 0)
        {
            return kInvalidArgument;
        }

        RingElement value = RingElement::zero();
        for (uint8_t i = 0; i < 4; ++i)
        {
            std::array<uint8_t, 16> block = make_ctr_bytes(ctr_lo, ctr_hi);
            block[15] = 0;
            block[14] = i;
            block[13] = j;
            value.coefs[i] = load_z128_le(aes_.encrypt_block(block));
        }

        *out = value;
        return kOk;
    }

private:
    Aes128Ecb aes_;
};

struct PrfBundle
{
    PhiAes phi;
    PsiAes psi;
    ChiAes chi;
};
} // namespace prss
} // namespace noise

#endif
