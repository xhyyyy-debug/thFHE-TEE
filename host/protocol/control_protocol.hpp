#ifndef HOST_CONTROL_PROTOCOL_HPP
#define HOST_CONTROL_PROTOCOL_HPP

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "../../enclave/common/noise_types.h"
#include "../transport/network.hpp"

namespace host
{
// Snapshot returned by each party to controller-side tools. It intentionally
// includes both coarse progress fields and optional debug payloads for diagnosis.
struct StatusSnapshot
{
    uint64_t party_id = 0;
    uint64_t round_id = 0;
    uint64_t batch_size = 0;
    std::string state = "IDLE";
    uint64_t current_item = 0;
    uint64_t completed_items = 0;
    uint64_t received_shares = 0;
    uint64_t ack_count = 0;
    uint64_t expected_shares = 0;
    uint64_t success = 0;
    std::vector<noise::RingElementRaw> local_secrets;
    std::vector<noise::SharePoint> aggregates;
    std::vector<noise::TripleShare> triples;
    std::vector<noise::BitShare> bits;
};

inline std::vector<std::string> split_csv(const std::string& text);
inline std::vector<std::string> split(const std::string& text, char separator);

// Rings are serialized as hex words so the debugging protocol remains readable
// while still being lossless for 128-bit coefficient components.
inline std::string encode_u64_hex(uint64_t value)
{
    std::ostringstream out;
    out << std::hex << std::setw(16) << std::setfill('0') << value;
    return out.str();
}

inline uint64_t decode_u64_hex(const std::string& value)
{
    return std::stoull(value, nullptr, 16);
}

inline std::string encode_ring(const noise::RingElementRaw& value)
{
    std::ostringstream out;
    for (size_t i = 0; i < 4; ++i)
    {
        if (i != 0)
        {
            out << '.';
        }
        out << encode_u64_hex(value.coeffs[i].lo) << '.'
            << encode_u64_hex(value.coeffs[i].hi);
    }
    return out.str();
}

inline bool decode_ring(const std::string& text, noise::RingElementRaw* out)
{
    if (out == nullptr)
    {
        return false;
    }
    const auto parts = split(text, '.');
    if (parts.size() != 8)
    {
        return false;
    }
    size_t idx = 0;
    for (size_t i = 0; i < 4; ++i)
    {
        out->coeffs[i].lo = decode_u64_hex(parts[idx++]);
        out->coeffs[i].hi = decode_u64_hex(parts[idx++]);
    }
    return true;
}

struct BatchShareMessage
{
    std::vector<noise::SharePackage> packages;
};

struct BatchAckMessage
{
    std::vector<noise::AckMessage> acks;
};

inline uint64_t make_subround_id(uint64_t round_id, uint64_t batch_index)
{
    return (round_id << 32U) | (batch_index + 1U);
}

inline std::string build_start_message(uint64_t round_id, uint64_t batch_size)
{
    return "START " + std::to_string(round_id) + " " + std::to_string(batch_size);
}

inline bool parse_start_message(const std::string& line, uint64_t* round_id, uint64_t* batch_size)
{
    std::istringstream input(line);
    std::string kind;
    if (!(input >> kind) || kind != "START")
    {
        return false;
    }

    return static_cast<bool>(input >> *round_id >> *batch_size);
}

inline std::string build_status_request()
{
    return "STATUS";
}

inline bool is_status_request(const std::string& line)
{
    return line == "STATUS";
}

inline std::string build_status_request_full()
{
    return "STATUS_FULL";
}

inline bool is_status_request_full(const std::string& line)
{
    return line == "STATUS_FULL";
}

inline std::string build_share_message(const noise::SharePackage& share)
{
    std::ostringstream output;
    output << "SHARE "
           << share.round_id << ' '
           << share.sender_id << ' '
           << share.receiver_id << ' '
           << share.share_x << ' '
           << encode_ring(share.share_y) << ' '
           << share.sigma;
    return output.str();
}

inline std::string build_batch_share_message(const BatchShareMessage& message)
{
    std::ostringstream output;
    output << "BATCH_SHARE " << message.packages.size() << ' ';
    for (size_t i = 0; i < message.packages.size(); ++i)
    {
        if (i != 0)
        {
            output << ';';
        }

        const auto& share = message.packages[i];
        output << share.round_id << ','
               << share.sender_id << ','
               << share.receiver_id << ','
               << share.share_x << ','
               << encode_ring(share.share_y) << ','
               << share.sigma;
    }
    return output.str();
}

inline bool parse_batch_share_message(const std::string& line, BatchShareMessage* message)
{
    std::istringstream input(line);
    std::string kind;
    size_t count = 0;
    std::string payload;
    if (!(input >> kind) || kind != "BATCH_SHARE" || !(input >> count))
    {
        return false;
    }

    std::getline(input, payload);
    if (!payload.empty() && payload.front() == ' ')
    {
        payload.erase(payload.begin());
    }

    message->packages.clear();
    if (count == 0)
    {
        return true;
    }

    const auto items = split(payload, ';');
    if (items.size() != count)
    {
        return false;
    }

    for (const auto& item : items)
    {
        const auto fields = split(item, ',');
        if (fields.size() != 6)
        {
            return false;
        }

        noise::SharePackage share{};
        share.round_id = std::stoull(fields[0]);
        share.sender_id = std::stoull(fields[1]);
        share.receiver_id = std::stoull(fields[2]);
        share.share_x = std::stoull(fields[3]);
        if (!decode_ring(fields[4], &share.share_y))
        {
            return false;
        }
        share.sigma = std::stoull(fields[5]);
        message->packages.push_back(share);
    }

    return true;
}

inline bool parse_share_message(const std::string& line, noise::SharePackage* share)
{
    std::istringstream input(line);
    std::string kind;
    if (!(input >> kind) || kind != "SHARE")
    {
        return false;
    }

    std::string ring_text;
    if (!(input >> share->round_id
                >> share->sender_id
                >> share->receiver_id
                >> share->share_x
                >> ring_text
                >> share->sigma))
    {
        return false;
    }
    return decode_ring(ring_text, &share->share_y);
}

inline std::string build_ack_message(const noise::AckMessage& ack)
{
    std::ostringstream output;
    output << "ACK "
           << ack.round_id << ' '
           << ack.acking_party << ' '
           << ack.for_sender << ' '
           << ack.sigma << ' '
           << ack.accepted;
    return output.str();
}

inline std::string build_batch_ack_message(const BatchAckMessage& message)
{
    std::ostringstream output;
    output << "BATCH_ACK " << message.acks.size() << ' ';
    for (size_t i = 0; i < message.acks.size(); ++i)
    {
        if (i != 0)
        {
            output << ';';
        }

        const auto& ack = message.acks[i];
        output << ack.round_id << ','
               << ack.acking_party << ','
               << ack.for_sender << ','
               << ack.sigma << ','
               << ack.accepted;
    }
    return output.str();
}

inline bool parse_batch_ack_message(const std::string& line, BatchAckMessage* message)
{
    std::istringstream input(line);
    std::string kind;
    size_t count = 0;
    std::string payload;
    if (!(input >> kind) || kind != "BATCH_ACK" || !(input >> count))
    {
        return false;
    }

    std::getline(input, payload);
    if (!payload.empty() && payload.front() == ' ')
    {
        payload.erase(payload.begin());
    }

    message->acks.clear();
    if (count == 0)
    {
        return true;
    }

    const auto items = split(payload, ';');
    if (items.size() != count)
    {
        return false;
    }

    for (const auto& item : items)
    {
        const auto fields = split(item, ',');
        if (fields.size() != 5)
        {
            return false;
        }

        message->acks.push_back(
            {std::stoull(fields[0]),
             std::stoull(fields[1]),
             std::stoull(fields[2]),
             std::stoull(fields[3]),
             std::stoull(fields[4])});
    }

    return true;
}

inline bool parse_ack_message(const std::string& line, noise::AckMessage* ack)
{
    std::istringstream input(line);
    std::string kind;
    if (!(input >> kind) || kind != "ACK")
    {
        return false;
    }

    return static_cast<bool>(
        input >> ack->round_id
              >> ack->acking_party
              >> ack->for_sender
              >> ack->sigma
              >> ack->accepted);
}

inline std::string build_status_response(const StatusSnapshot& status)
{
    std::ostringstream output;
    std::ostringstream secrets;
    std::ostringstream aggregates;

    if (status.local_secrets.empty())
    {
        secrets << "-";
    }
    else
    {
        for (size_t i = 0; i < status.local_secrets.size(); ++i)
        {
            if (i != 0)
            {
                secrets << ",";
            }
            secrets << encode_ring(status.local_secrets[i]);
        }
    }

    if (status.aggregates.empty())
    {
        aggregates << "-";
    }
    else
    {
        for (size_t i = 0; i < status.aggregates.size(); ++i)
        {
            if (i != 0)
            {
                aggregates << ",";
            }
            aggregates << status.aggregates[i].x << ":" << encode_ring(status.aggregates[i].y);
        }
    }

    output << "STATUS "
           << status.party_id << ' '
           << status.round_id << ' '
           << status.batch_size << ' '
           << status.state << ' '
           << status.current_item << ' '
           << status.completed_items << ' '
           << status.received_shares << ' '
           << status.ack_count << ' '
           << status.expected_shares << ' '
           << status.success << ' '
           << secrets.str() << ' '
           << aggregates.str();
    return output.str();
}

inline std::string build_status_response_summary(const StatusSnapshot& status)
{
    std::ostringstream output;
    output << "STATUS "
           << status.party_id << ' '
           << status.round_id << ' '
           << status.batch_size << ' '
           << status.state << ' '
           << status.current_item << ' '
           << status.completed_items << ' '
           << status.received_shares << ' '
           << status.ack_count << ' '
           << status.expected_shares << ' '
           << status.success << ' '
           << "-" << ' '
           << "-";
    return output.str();
}

inline bool parse_status_response(const std::string& line, StatusSnapshot* status)
{
    std::istringstream input(line);
    std::string kind;
    std::string secrets;
    std::string aggregates;
    if (!(input >> kind) || kind != "STATUS")
    {
        return false;
    }

    if (!(input >> status->party_id
                >> status->round_id
                >> status->batch_size
                >> status->state
                >> status->current_item
                >> status->completed_items
                >> status->received_shares
                >> status->ack_count
                >> status->expected_shares
                >> status->success
                >> secrets
                >> aggregates))
    {
        return false;
    }

    status->local_secrets.clear();
    status->aggregates.clear();

    if (secrets != "-")
    {
        for (const auto& part : split_csv(secrets))
        {
            noise::RingElementRaw value{};
            if (!decode_ring(part, &value))
            {
                return false;
            }
            status->local_secrets.push_back(value);
        }
    }

    if (aggregates != "-")
    {
        for (const auto& part : split_csv(aggregates))
        {
            const auto pos = part.find(':');
            if (pos == std::string::npos)
            {
                return false;
            }

            noise::SharePoint point{};
            point.x = std::stoull(part.substr(0, pos));
            if (!decode_ring(part.substr(pos + 1), &point.y))
            {
                return false;
            }
            status->aggregates.push_back(point);
        }
    }

    return true;
}

inline std::vector<std::string> split_csv(const std::string& text)
{
    std::vector<std::string> parts;
    std::string current;
    std::istringstream input(text);

    while (std::getline(input, current, ','))
    {
        if (!current.empty())
        {
            parts.push_back(current);
        }
    }

    return parts;
}

inline std::vector<std::string> split(const std::string& text, char separator)
{
    std::vector<std::string> parts;
    std::string current;
    std::istringstream input(text);

    while (std::getline(input, current, separator))
    {
        if (!current.empty())
        {
            parts.push_back(current);
        }
    }

    return parts;
}

inline Endpoint parse_endpoint(const std::string& text)
{
    const auto pos = text.rfind(':');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= text.size())
    {
        throw std::runtime_error("Endpoint must be host:port, got: " + text);
    }

    Endpoint endpoint;
    endpoint.host = text.substr(0, pos);
    endpoint.port = static_cast<uint16_t>(std::stoul(text.substr(pos + 1)));
    return endpoint;
}

inline std::vector<Endpoint> parse_endpoints_csv(const std::string& text)
{
    std::vector<Endpoint> endpoints;
    for (const auto& part : split_csv(text))
    {
        endpoints.push_back(parse_endpoint(part));
    }
    return endpoints;
}
} // namespace host

#endif
