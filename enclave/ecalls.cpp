#include "dkg_t.h"
#include "protocol/enclave_protocol_handler.h"

using noise::AckMessage;
using noise::EnclaveProtocolHandler;
using noise::SharePackage;
using noise::SharePoint;

namespace
{
EnclaveProtocolHandler g_handler;
}

extern "C" int ecall_init_party(
    uint64_t party_id,
    uint64_t party_count,
    uint64_t threshold,
    uint32_t noise_bound_bits)
{
    return g_handler.init(party_id, party_count, threshold, noise_bound_bits);
}

extern "C" int ecall_prss_next(ring_element_t* share_value)
{
    return g_handler.prss_next(reinterpret_cast<noise::RingElementRaw*>(share_value));
}

extern "C" int ecall_przs_next(ring_element_t* share_value)
{
    return g_handler.przs_next(reinterpret_cast<noise::RingElementRaw*>(share_value));
}

extern "C" int ecall_triple_generate_batch(
    uint64_t* round_ids,
    size_t batch_count,
    triple_d_package_t* packages,
    size_t package_count)
{
    return g_handler.triple_generate_batch(
        round_ids,
        batch_count,
        reinterpret_cast<noise::TripleDPackage*>(packages),
        package_count);
}

extern "C" int ecall_triple_store_batch(
    triple_d_package_t* packages,
    size_t batch_count)
{
    return g_handler.triple_store_batch(
        reinterpret_cast<noise::TripleDPackage*>(packages),
        batch_count);
}

extern "C" int ecall_triple_done_batch(
    triple_share_t* triples,
    size_t batch_count)
{
    return g_handler.triple_done_batch(
        reinterpret_cast<noise::TripleShare*>(triples),
        batch_count);
}

extern "C" int ecall_verify_triple_output(triple_share_t* triple)
{
    return g_handler.verify_triple_output(reinterpret_cast<noise::TripleShare*>(triple));
}

extern "C" int ecall_bit_generate_batch(
    uint64_t* round_ids,
    size_t batch_count,
    bit_v_package_t* packages,
    size_t package_count)
{
    return g_handler.bit_generate_batch(
        round_ids,
        batch_count,
        reinterpret_cast<noise::BitVPackage*>(packages),
        package_count);
}

extern "C" int ecall_bit_store_batch(
    bit_v_package_t* packages,
    size_t batch_count)
{
    return g_handler.bit_store_batch(
        reinterpret_cast<noise::BitVPackage*>(packages),
        batch_count);
}

extern "C" int ecall_bit_done_batch(
    bit_share_t* bits,
    size_t batch_count)
{
    return g_handler.bit_done_batch(
        reinterpret_cast<noise::BitShare*>(bits),
        batch_count);
}

extern "C" int ecall_verify_bit_output(bit_share_t* bit)
{
    return g_handler.verify_bit_output(reinterpret_cast<noise::BitShare*>(bit));
}

extern "C" int ecall_sharegen(
    uint64_t round_id,
    share_package_t* packages,
    size_t package_count,
    ring_element_t* sampled_secret)
{
    return g_handler.sharegen(
        round_id,
        reinterpret_cast<SharePackage*>(packages),
        package_count,
        reinterpret_cast<noise::RingElementRaw*>(sampled_secret));
}

extern "C" int ecall_sharegen_batch(
    uint64_t* round_ids,
    size_t batch_count,
    share_package_t* packages,
    size_t package_count,
    ring_element_t* sampled_secrets)
{
    return g_handler.sharegen_batch(
        round_ids,
        batch_count,
        reinterpret_cast<SharePackage*>(packages),
        package_count,
        reinterpret_cast<noise::RingElementRaw*>(sampled_secrets));
}

extern "C" int ecall_sharegen_batch_with_bound(
    uint64_t* round_ids,
    size_t batch_count,
    share_package_t* packages,
    size_t package_count,
    ring_element_t* sampled_secrets,
    uint32_t noise_bound_bits)
{
    return g_handler.sharegen_batch_with_bound(
        round_ids,
        batch_count,
        reinterpret_cast<SharePackage*>(packages),
        package_count,
        reinterpret_cast<noise::RingElementRaw*>(sampled_secrets),
        noise_bound_bits);
}

extern "C" int ecall_store(
    share_package_t* package,
    ack_message_t* ack)
{
    if (package == nullptr)
    {
        return noise::kInvalidArgument;
    }

    return g_handler.store(
        *reinterpret_cast<SharePackage*>(package),
        reinterpret_cast<AckMessage*>(ack));
}

extern "C" int ecall_store_batch(
    share_package_t* packages,
    size_t batch_count,
    ack_message_t* acks)
{
    return g_handler.store_batch(
        reinterpret_cast<SharePackage*>(packages),
        batch_count,
        reinterpret_cast<AckMessage*>(acks));
}

extern "C" int ecall_done(share_point_t* aggregate)
{
    return g_handler.done(reinterpret_cast<SharePoint*>(aggregate));
}

extern "C" int ecall_done_batch(share_point_t* aggregates, size_t batch_count)
{
    return g_handler.done_batch(reinterpret_cast<SharePoint*>(aggregates), batch_count);
}

extern "C" int ecall_verify_noise_output(share_point_t* point)
{
    return g_handler.verify_noise_output(reinterpret_cast<SharePoint*>(point));
}

