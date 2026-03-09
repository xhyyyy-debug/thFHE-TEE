#include "noise_t.h"
#include "prog_mpc.h"

using noise::AckMessage;
using noise::ProgMPCHandler;
using noise::SharePackage;
using noise::SharePoint;

namespace
{
ProgMPCHandler g_handler;
}

extern "C" int ecall_init_party(
    uint64_t party_id,
    uint64_t party_count,
    uint64_t threshold)
{
    return g_handler.init(party_id, party_count, threshold);
}

extern "C" int ecall_sharegen(
    uint64_t round_id,
    share_package_t* packages,
    size_t package_count,
    uint64_t* sampled_secret)
{
    return g_handler.sharegen(
        round_id,
        reinterpret_cast<SharePackage*>(packages),
        package_count,
        sampled_secret);
}

extern "C" int ecall_sharegen_batch(
    uint64_t* round_ids,
    size_t batch_count,
    share_package_t* packages,
    size_t package_count,
    uint64_t* sampled_secrets)
{
    return g_handler.sharegen_batch(
        round_ids,
        batch_count,
        reinterpret_cast<SharePackage*>(packages),
        package_count,
        sampled_secrets);
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
