#ifndef HOST_GRPC_UTILS_HPP
#define HOST_GRPC_UTILS_HPP

#include <string>
#include <vector>

#include "../../enclave/common/noise_types.h"
#include "../config/config.hpp"
#include "control_protocol.hpp"

#include "noise.grpc.pb.h"

namespace host
{
inline std::string endpoint_to_target(const Endpoint& endpoint)
{
    return endpoint.host + ":" + std::to_string(endpoint.port);
}

inline void fill_ring_proto(const noise::RingElementRaw& value, noise_rpc::RingElementRaw* out)
{
    out->clear_coeffs();
    for (size_t i = 0; i < 4; ++i)
    {
        auto* coeff = out->add_coeffs();
        coeff->set_lo(value.coeffs[i].lo);
        coeff->set_hi(value.coeffs[i].hi);
    }
}

inline noise::RingElementRaw parse_ring_proto(const noise_rpc::RingElementRaw& value)
{
    noise::RingElementRaw out{};
    const int count = value.coeffs_size();
    for (int i = 0; i < count && i < 4; ++i)
    {
        out.coeffs[i].lo = value.coeffs(i).lo();
        out.coeffs[i].hi = value.coeffs(i).hi();
    }
    return out;
}

inline void fill_share_package_proto(const noise::SharePackage& in, noise_rpc::SharePackage* out)
{
    out->set_round_id(in.round_id);
    out->set_sender_id(in.sender_id);
    out->set_receiver_id(in.receiver_id);
    out->set_share_x(in.share_x);
    out->set_sigma(in.sigma);
    fill_ring_proto(in.share_y, out->mutable_share_y());
}

inline noise::SharePackage parse_share_package_proto(const noise_rpc::SharePackage& in)
{
    noise::SharePackage out{};
    out.round_id = in.round_id();
    out.sender_id = in.sender_id();
    out.receiver_id = in.receiver_id();
    out.share_x = in.share_x();
    out.share_y = parse_ring_proto(in.share_y());
    out.sigma = in.sigma();
    return out;
}

inline void fill_ack_message_proto(const noise::AckMessage& in, noise_rpc::AckMessage* out)
{
    out->set_round_id(in.round_id);
    out->set_acking_party(in.acking_party);
    out->set_for_sender(in.for_sender);
    out->set_sigma(in.sigma);
    out->set_accepted(in.accepted);
}

inline noise::AckMessage parse_ack_message_proto(const noise_rpc::AckMessage& in)
{
    noise::AckMessage out{};
    out.round_id = in.round_id();
    out.acking_party = in.acking_party();
    out.for_sender = in.for_sender();
    out.sigma = in.sigma();
    out.accepted = in.accepted();
    return out;
}

inline void fill_share_point_proto(const noise::SharePoint& in, noise_rpc::SharePoint* out)
{
    out->set_round_id(in.round_id);
    out->set_x(in.x);
    out->set_sigma(in.sigma);
    fill_ring_proto(in.y, out->mutable_y());
}

inline noise::SharePoint parse_share_point_proto(const noise_rpc::SharePoint& in)
{
    noise::SharePoint out{};
    out.round_id = in.round_id();
    out.x = in.x();
    out.y = parse_ring_proto(in.y());
    out.sigma = in.sigma();
    return out;
}

inline void fill_triple_d_package_proto(const noise::TripleDPackage& in, noise_rpc::TripleDPackage* out)
{
    out->set_round_id(in.round_id);
    out->set_sender_id(in.sender_id);
    out->set_sigma(in.sigma);
    fill_ring_proto(in.d_share, out->mutable_d_share());
}

inline noise::TripleDPackage parse_triple_d_package_proto(const noise_rpc::TripleDPackage& in)
{
    noise::TripleDPackage out{};
    out.round_id = in.round_id();
    out.sender_id = in.sender_id();
    out.d_share = parse_ring_proto(in.d_share());
    out.sigma = in.sigma();
    return out;
}

inline void fill_triple_share_proto(const noise::TripleShare& in, noise_rpc::TripleShare* out)
{
    out->set_round_id(in.round_id);
    out->set_sigma(in.sigma);
    fill_ring_proto(in.a, out->mutable_a());
    fill_ring_proto(in.b, out->mutable_b());
    fill_ring_proto(in.c, out->mutable_c());
}

inline noise::TripleShare parse_triple_share_proto(const noise_rpc::TripleShare& in)
{
    noise::TripleShare out{};
    out.round_id = in.round_id();
    out.a = parse_ring_proto(in.a());
    out.b = parse_ring_proto(in.b());
    out.c = parse_ring_proto(in.c());
    out.sigma = in.sigma();
    return out;
}

inline void fill_bit_v_package_proto(const noise::BitVPackage& in, noise_rpc::BitVPackage* out)
{
    out->set_round_id(in.round_id);
    out->set_sender_id(in.sender_id);
    out->set_sigma(in.sigma);
    fill_ring_proto(in.v_share, out->mutable_v_share());
}

inline noise::BitVPackage parse_bit_v_package_proto(const noise_rpc::BitVPackage& in)
{
    noise::BitVPackage out{};
    out.round_id = in.round_id();
    out.sender_id = in.sender_id();
    out.v_share = parse_ring_proto(in.v_share());
    out.sigma = in.sigma();
    return out;
}

inline void fill_bit_share_proto(const noise::BitShare& in, noise_rpc::BitShare* out)
{
    out->set_round_id(in.round_id);
    out->set_sigma(in.sigma);
    fill_ring_proto(in.b, out->mutable_b());
}

inline noise::BitShare parse_bit_share_proto(const noise_rpc::BitShare& in)
{
    noise::BitShare out{};
    out.round_id = in.round_id();
    out.b = parse_ring_proto(in.b());
    out.sigma = in.sigma();
    return out;
}

inline void fill_keygen_open_share_proto(
    uint64_t round_id,
    uint64_t sender_id,
    const noise::RingElementRaw& share,
    noise_rpc::KeygenOpenSharePackage* out)
{
    out->set_round_id(round_id);
    out->set_sender_id(sender_id);
    fill_ring_proto(share, out->mutable_share());
}

inline noise::RingElementRaw parse_keygen_open_share_proto(
    const noise_rpc::KeygenOpenSharePackage& in,
    uint64_t* round_id,
    uint64_t* sender_id)
{
    if (round_id != nullptr)
    {
        *round_id = in.round_id();
    }
    if (sender_id != nullptr)
    {
        *sender_id = in.sender_id();
    }
    return parse_ring_proto(in.share());
}

inline void fill_status_proto(const StatusSnapshot& in, noise_rpc::StatusReply* out, bool full)
{
    out->set_party_id(in.party_id);
    out->set_round_id(in.round_id);
    out->set_batch_size(in.batch_size);
    out->set_state(in.state);
    out->set_current_item(in.current_item);
    out->set_completed_items(in.completed_items);
    out->set_received_shares(in.received_shares);
    out->set_ack_count(in.ack_count);
    out->set_expected_shares(in.expected_shares);
    out->set_success(in.success);
    out->clear_local_secrets();
    out->clear_aggregates();
    out->clear_triples();
    out->clear_bits();

    if (full)
    {
        for (const auto& secret : in.local_secrets)
        {
            auto* entry = out->add_local_secrets();
            fill_ring_proto(secret, entry);
        }
        for (const auto& point : in.aggregates)
        {
            auto* entry = out->add_aggregates();
            fill_share_point_proto(point, entry);
        }
        for (const auto& triple : in.triples)
        {
            auto* entry = out->add_triples();
            fill_triple_share_proto(triple, entry);
        }
        for (const auto& bit : in.bits)
        {
            auto* entry = out->add_bits();
            fill_bit_share_proto(bit, entry);
        }
    }
}

inline StatusSnapshot parse_status_proto(const noise_rpc::StatusReply& in)
{
    StatusSnapshot out;
    out.party_id = in.party_id();
    out.round_id = in.round_id();
    out.batch_size = in.batch_size();
    out.state = in.state();
    out.current_item = in.current_item();
    out.completed_items = in.completed_items();
    out.received_shares = in.received_shares();
    out.ack_count = in.ack_count();
    out.expected_shares = in.expected_shares();
    out.success = in.success();

    out.local_secrets.clear();
    out.aggregates.clear();
    out.triples.clear();
    out.bits.clear();
    out.local_secrets.reserve(in.local_secrets_size());
    for (const auto& secret : in.local_secrets())
    {
        out.local_secrets.push_back(parse_ring_proto(secret));
    }
    out.aggregates.reserve(in.aggregates_size());
    for (const auto& point : in.aggregates())
    {
        out.aggregates.push_back(parse_share_point_proto(point));
    }
    out.triples.reserve(in.triples_size());
    for (const auto& triple : in.triples())
    {
        out.triples.push_back(parse_triple_share_proto(triple));
    }
    out.bits.reserve(in.bits_size());
    for (const auto& bit : in.bits())
    {
        out.bits.push_back(parse_bit_share_proto(bit));
    }
    return out;
}
} // namespace host

#endif
