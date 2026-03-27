#ifndef NOISE_PRSS_STATE_H
#define NOISE_PRSS_STATE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "prf.h"

namespace noise
{
namespace prss
{
using PartySet = std::vector<uint64_t>;

struct PrssSet
{
    PartySet parties;
    PrfKey set_key;
    std::vector<RingElement> f_a_points;
};

struct PRSSSetup
{
    std::vector<PrssSet> sets;
    std::vector<std::vector<RingElement>> alpha_powers;
};

struct PRSSCounters
{
    uint64_t mask_ctr_lo = 0;
    uint64_t mask_ctr_hi = 0;
    uint64_t prss_ctr_lo = 0;
    uint64_t prss_ctr_hi = 0;
    uint64_t przs_ctr_lo = 0;
    uint64_t przs_ctr_hi = 0;
};

inline void increment_counter(uint64_t* lo, uint64_t* hi, uint64_t delta)
{
    const uint64_t old_lo = *lo;
    *lo += delta;
    if (*lo < old_lo)
    {
        *hi += 1;
    }
}

inline std::vector<PartySet> create_sets_rec(
    const std::vector<uint64_t>& roles,
    size_t start,
    size_t needed)
{
    if (needed == 0)
    {
        return { PartySet{} };
    }

    std::vector<PartySet> out;
    for (size_t i = start; i + needed <= roles.size(); ++i)
    {
        std::vector<PartySet> tails = create_sets_rec(roles, i + 1, needed - 1);
        for (auto& tail : tails)
        {
            PartySet set;
            set.reserve(needed);
            set.push_back(roles[i]);
            set.insert(set.end(), tail.begin(), tail.end());
            out.push_back(set);
        }
    }
    return out;
}

inline std::vector<PartySet> create_sets(uint64_t party_count, uint64_t threshold)
{
    std::vector<uint64_t> roles;
    roles.reserve(static_cast<size_t>(party_count));
    for (uint64_t role = 1; role <= party_count; ++role)
    {
        roles.push_back(role);
    }
    return create_sets_rec(roles, 0, static_cast<size_t>(party_count - threshold));
}

inline std::vector<RingElement> multiply_poly_by_linear(
    const std::vector<RingElement>& poly,
    const RingElement& root)
{
    std::vector<RingElement> out(poly.size() + 1, RingElement::zero());
    for (size_t i = 0; i < poly.size(); ++i)
    {
        out[i] += poly[i];
        out[i + 1] -= poly[i] * root;
    }
    return out;
}

inline RingElement evaluate_poly(
    const std::vector<RingElement>& poly,
    const RingElement& x)
{
    RingElement out = RingElement::zero();
    for (size_t i = poly.size(); i-- > 0;)
    {
        out = out * x + poly[i];
    }
    return out;
}

inline std::vector<RingElement> compute_f_a_points(
    uint64_t party_count,
    const PartySet& party_set)
{
    std::vector<RingElement> poly(1, RingElement::one());
    for (uint64_t role = 1; role <= party_count; ++role)
    {
        bool contained = false;
        for (uint64_t party : party_set)
        {
            if (party == role)
            {
                contained = true;
                break;
            }
        }
        if (!contained)
        {
            const RingElement alpha = RingElement::embed_role_to_exceptional_sequence(role);
            poly = multiply_poly_by_linear(poly, alpha.invert());
        }
    }

    std::vector<RingElement> points;
    points.reserve(static_cast<size_t>(party_count));
    for (uint64_t role = 1; role <= party_count; ++role)
    {
        points.push_back(evaluate_poly(poly, RingElement::embed_role_to_exceptional_sequence(role)));
    }
    return points;
}

inline std::vector<std::vector<RingElement>> compute_alpha_powers(
    uint64_t party_count,
    uint64_t threshold)
{
    std::vector<std::vector<RingElement>> out(static_cast<size_t>(party_count));
    for (uint64_t role = 1; role <= party_count; ++role)
    {
        const RingElement alpha = RingElement::embed_role_to_exceptional_sequence(role);
        out[role - 1].resize(static_cast<size_t>(threshold + 1), RingElement::one());
        for (uint64_t power = 1; power <= threshold; ++power)
        {
            out[role - 1][power] = out[role - 1][power - 1] * alpha;
        }
    }
    return out;
}

inline PrfKey derive_fixed_set_key(
    const PartySet& parties,
    uint64_t party_count,
    uint64_t threshold)
{
    // Development-only shortcut for bypassing PRSS.Init:
    // every party deterministically derives the same set key from the subset descriptor.
    constexpr std::array<uint8_t, 16> kMasterKey{
        0x50, 0x52, 0x53, 0x53, 0x2d, 0x46, 0x49, 0x58,
        0x45, 0x44, 0x2d, 0x53, 0x45, 0x45, 0x44, 0x21
    };

    std::array<uint8_t, 16> block{};
    block[0] = static_cast<uint8_t>(party_count);
    block[1] = static_cast<uint8_t>(threshold);
    block[2] = static_cast<uint8_t>(parties.size());
    block[3] = 0xa5;
    for (size_t i = 0; i < parties.size() && 4 + i < block.size(); ++i)
    {
        block[4 + i] = static_cast<uint8_t>(parties[i]);
    }

    Aes128Ecb kdf(kMasterKey);
    PrfKey key;
    key.bytes = kdf.encrypt_block(block);
    return key;
}

inline PRSSSetup build_fixed_setup(
    uint64_t party_id,
    uint64_t party_count,
    uint64_t threshold)
{
    PRSSSetup setup;
    setup.alpha_powers = compute_alpha_powers(party_count, threshold);

    const std::vector<PartySet> all_sets = create_sets(party_count, threshold);
    for (const PartySet& set : all_sets)
    {
        bool contained = false;
        for (uint64_t party : set)
        {
            if (party == party_id)
            {
                contained = true;
                break;
            }
        }
        if (!contained)
        {
            continue;
        }

        PrssSet prss_set;
        prss_set.parties = set;
        prss_set.set_key = derive_fixed_set_key(set, party_count, threshold);
        prss_set.f_a_points = compute_f_a_points(party_count, set);
        setup.sets.push_back(prss_set);
    }

    return setup;
}

class PRSSState
{
public:
    int init_fixed(
        uint64_t party_id,
        uint64_t party_count,
        uint64_t threshold,
        SessionId128 sid)
    {
        // This intentionally skips the interactive Init phase and should only be
        // used while we are bringing the enclave-side PRSS/PRZS machinery online.
        if (party_id == 0 || party_count == 0 || party_id > party_count || threshold >= party_count)
        {
            return kInvalidArgument;
        }

        own_party_id_ = party_id;
        threshold_ = threshold;
        session_id_ = sid;
        counters_ = PRSSCounters{};
        setup_ = build_fixed_setup(party_id, party_count, threshold);
        prfs_.clear();
        prfs_.reserve(setup_.sets.size());

        for (const PrssSet& set : setup_.sets)
        {
            prfs_.push_back(PrfBundle{
                PhiAes(set.set_key, session_id_),
                PsiAes(set.set_key, session_id_),
                ChiAes(set.set_key, session_id_)
            });
        }

        initialized_ = true;
        return kOk;
    }

    int prss_next(RingElement* out)
    {
        if (!initialized_ || out == nullptr)
        {
            return kInvalidArgument;
        }

        RingElement res = RingElement::zero();
        for (size_t i = 0; i < setup_.sets.size(); ++i)
        {
            RingElement psi_val = RingElement::zero();
            const int status = prfs_[i].psi.sample(
                counters_.prss_ctr_lo,
                counters_.prss_ctr_hi,
                &psi_val);
            if (status != kOk)
            {
                return status;
            }

            const RingElement& f_a = setup_.sets[i].f_a_points[own_party_id_ - 1];
            res += f_a * psi_val;
        }

        increment_counter(&counters_.prss_ctr_lo, &counters_.prss_ctr_hi, 1);
        *out = res;
        return kOk;
    }

    int przs_next(RingElement* out)
    {
        if (!initialized_ || out == nullptr)
        {
            return kInvalidArgument;
        }

        RingElement res = RingElement::zero();
        for (size_t i = 0; i < setup_.sets.size(); ++i)
        {
            const RingElement& f_a = setup_.sets[i].f_a_points[own_party_id_ - 1];
            for (uint64_t j = 1; j <= threshold_; ++j)
            {
                RingElement chi_val = RingElement::zero();
                const int status = prfs_[i].chi.sample(
                    counters_.przs_ctr_lo,
                    counters_.przs_ctr_hi,
                    static_cast<uint8_t>(j),
                    &chi_val);
                if (status != kOk)
                {
                    return status;
                }

                const RingElement& alpha_power = setup_.alpha_powers[own_party_id_ - 1][j];
                res += f_a * alpha_power * chi_val;
            }
        }

        increment_counter(&counters_.przs_ctr_lo, &counters_.przs_ctr_hi, 1);
        *out = res;
        return kOk;
    }

    const PRSSCounters& counters() const
    {
        return counters_;
    }

private:
    bool initialized_ = false;
    uint64_t own_party_id_ = 0;
    uint64_t threshold_ = 0;
    SessionId128 session_id_{};
    PRSSSetup setup_{};
    PRSSCounters counters_{};
    std::vector<PrfBundle> prfs_{};
};
} // namespace prss
} // namespace noise

#endif
