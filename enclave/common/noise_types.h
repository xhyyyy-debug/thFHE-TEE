#ifndef NOISE_COMMON_NOISE_TYPES_H
#define NOISE_COMMON_NOISE_TYPES_H

#include <cstddef>
#include <cstdint>

#include "../../algebra/rings/galois_ring.hpp"

namespace noise
{
constexpr size_t kMaxParties = 16;
constexpr size_t kMaxParallelBatch = 2048;
constexpr uint32_t kDefaultNoiseBoundBits = 8;

using RingElement = algebra::ResiduePolyF4Z128;

struct Z128Raw
{
    uint64_t lo;
    uint64_t hi;
};

struct RingElementRaw
{
    Z128Raw coeffs[4];
};

enum StatusCode : int32_t
{
    kOk = 0,
    kInvalidArgument = 1,
    kVerificationFailed = 2,
    kInsufficientShares = 3,
    kNotReady = 4
};

struct SharePackage
{
    uint64_t round_id;
    uint64_t sender_id;
    uint64_t receiver_id;
    uint64_t share_x;
    RingElementRaw share_y;
    uint64_t sigma;
};

struct AckMessage
{
    uint64_t round_id;
    uint64_t acking_party;
    uint64_t for_sender;
    uint64_t sigma;
    uint64_t accepted;
};

struct SharePoint
{
    uint64_t round_id;
    uint64_t x;
    RingElementRaw y;
    uint64_t sigma;
};

struct TripleDPackage
{
    uint64_t round_id;
    uint64_t sender_id;
    RingElementRaw d_share;
    uint64_t sigma;
};

struct TripleShare
{
    uint64_t round_id;
    RingElementRaw a;
    RingElementRaw b;
    RingElementRaw c;
    uint64_t sigma;
};

struct BitVPackage
{
    uint64_t round_id;
    uint64_t sender_id;
    RingElementRaw v_share;
    uint64_t sigma;
};

struct BitShare
{
    uint64_t round_id;
    RingElementRaw b;
    uint64_t sigma;
};

inline uint64_t mix64(uint64_t value)
{
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31U;
    return value;
}

inline uint64_t sign_ack(uint64_t round_id, uint64_t acking_party, uint64_t for_sender)
{
    return mix64(round_id ^ acking_party ^ (for_sender << 17U) ^ 0x41434bULL);
}

inline bool verify_ack(const AckMessage& ack)
{
    return ack.accepted == 1 && ack.sigma == sign_ack(ack.round_id, ack.acking_party, ack.for_sender);
}

inline RingElement ring_from_raw(const RingElementRaw& raw)
{
    RingElement value{};
    for (size_t i = 0; i < 4; ++i)
    {
        value.coefs[i] = algebra::Z128(raw.coeffs[i].lo, raw.coeffs[i].hi);
    }
    return value;
}

inline RingElementRaw raw_from_ring(const RingElement& value)
{
    RingElementRaw raw{};
    for (size_t i = 0; i < 4; ++i)
    {
        raw.coeffs[i].lo = value.coefs[i].lo;
        raw.coeffs[i].hi = value.coefs[i].hi;
    }
    return raw;
}

inline RingElementRaw ring_add(const RingElementRaw& lhs, const RingElementRaw& rhs)
{
    return raw_from_ring(ring_from_raw(lhs) + ring_from_raw(rhs));
}

inline bool ring_equal(const RingElementRaw& lhs, const RingElementRaw& rhs)
{
    for (size_t i = 0; i < 4; ++i)
    {
        if (lhs.coeffs[i].lo != rhs.coeffs[i].lo || lhs.coeffs[i].hi != rhs.coeffs[i].hi)
        {
            return false;
        }
    }
    return true;
}
} // namespace noise

#endif
