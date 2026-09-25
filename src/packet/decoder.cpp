#include "packet/packet.h"
#include "telemetry/telemetry.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace delta_nids::packet {
namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86dd;
constexpr std::uint16_t kEtherTypeVlan = 0x8100;
constexpr std::uint16_t kEtherTypeQinQ = 0x88a8;
constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
constexpr std::uint8_t kIcmp = 1;
constexpr std::uint8_t kIcmpv6 = 58;

class Reader {
public:
    explicit Reader(const std::vector<std::uint8_t>& bytes) : data_(bytes.data()), size_(bytes.size()) {}

    [[nodiscard]] bool available(std::size_t offset, std::size_t length) const {
        return offset <= size_ && length <= size_ - offset;
    }
    [[nodiscard]] std::uint8_t u8(std::size_t offset) const { return data_[offset]; }
    [[nodiscard]] std::uint16_t u16(std::size_t offset) const {
        return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data_[offset]) << 8) | data_[offset + 1]);
    }
    [[nodiscard]] std::uint32_t u32(std::size_t offset) const {
        return (static_cast<std::uint32_t>(data_[offset]) << 24) |
               (static_cast<std::uint32_t>(data_[offset + 1]) << 16) |
               (static_cast<std::uint32_t>(data_[offset + 2]) << 8) |
               static_cast<std::uint32_t>(data_[offset + 3]);
    }
    [[nodiscard]] std::vector<std::uint8_t> copy(std::size_t offset, std::size_t length) const {
        return {data_ + offset, data_ + offset + length};
    }

private:
    const std::uint8_t* data_;
    std::size_t size_;
};

DecodeResult failure(Packet packet, DecodeStatus status, const char* message) {
    packet.status = status;
    return {std::move(packet), status, message};
}

bool is_vlan(std::uint16_t ether_type) {
    return ether_type == kEtherTypeVlan || ether_type == kEtherTypeQinQ;
}

DecodeResult decode_transport(Packet packet, const Reader& reader, std::size_t offset,
                              std::size_t end, std::uint8_t protocol) {
    packet.ip.protocol_number = protocol;
    const auto available = end - offset;
    if (protocol == kTcp) {
        if (available < 20) return failure(std::move(packet), DecodeStatus::truncated, "truncated TCP header");
        const auto header_length = static_cast<std::size_t>((reader.u8(offset + 12) >> 4) * 4U);
        if (header_length < 20 || header_length > available)
            return failure(std::move(packet), DecodeStatus::malformed, "invalid TCP header length");
        TcpMetadata tcp;
        tcp.sequence = reader.u32(offset);
        tcp.acknowledgement = reader.u32(offset + 4);
        tcp.header_length = static_cast<std::uint8_t>(header_length);
        tcp.flags = reader.u8(offset + 13);
        tcp.window = reader.u16(offset + 14);
        packet.transport = TransportProtocol::tcp;
        packet.source_port = reader.u16(offset);
        packet.destination_port = reader.u16(offset + 2);
        packet.tcp = tcp;
        packet.payload = reader.copy(offset + header_length, available - header_length);
        return {std::move(packet), DecodeStatus::valid, {}};
    }
    if (protocol == kUdp) {
        if (available < 8) return failure(std::move(packet), DecodeStatus::truncated, "truncated UDP header");
        const auto length = reader.u16(offset + 4);
        if (length < 8) return failure(std::move(packet), DecodeStatus::malformed, "invalid UDP length");
        if (length > available) return failure(std::move(packet), DecodeStatus::truncated, "truncated UDP payload");
        packet.transport = TransportProtocol::udp;
        packet.source_port = reader.u16(offset);
        packet.destination_port = reader.u16(offset + 2);
        packet.udp = UdpMetadata{length};
        packet.payload = reader.copy(offset + 8, length - 8);
        return {std::move(packet), DecodeStatus::valid, {}};
    }
    if (protocol == kIcmp || protocol == kIcmpv6) {
        if (available < 4) return failure(std::move(packet), DecodeStatus::truncated, "truncated ICMP header");
        packet.transport = protocol == kIcmp ? TransportProtocol::icmp : TransportProtocol::icmpv6;
        packet.icmp = IcmpMetadata{reader.u8(offset), reader.u8(offset + 1)};
        packet.payload = reader.copy(offset + 4, available - 4);
        return {std::move(packet), DecodeStatus::valid, {}};
    }
    packet.transport = TransportProtocol::other;
    packet.payload = reader.copy(offset, available);
    return {std::move(packet), DecodeStatus::valid, {}};
}

DecodeResult decode_ipv4(Packet packet, const Reader& reader, std::size_t offset) {
    if (!reader.available(offset, 20)) return failure(std::move(packet), DecodeStatus::truncated, "truncated IPv4 header");
    const auto version_ihl = reader.u8(offset);
    if ((version_ihl >> 4) != 4) return failure(std::move(packet), DecodeStatus::malformed, "invalid IPv4 version");
    const auto header_length = static_cast<std::size_t>((version_ihl & 0x0f) * 4U);
    if (header_length < 20) return failure(std::move(packet), DecodeStatus::malformed, "invalid IPv4 header length");
    if (!reader.available(offset, header_length)) return failure(std::move(packet), DecodeStatus::truncated, "truncated IPv4 options");
    const auto total_length = reader.u16(offset + 2);
    if (total_length < header_length) return failure(std::move(packet), DecodeStatus::malformed, "invalid IPv4 total length");
    if (!reader.available(offset, total_length)) return failure(std::move(packet), DecodeStatus::truncated, "truncated IPv4 packet");

    packet.ip.version = 4;
    packet.ip.ttl_or_hop_limit = reader.u8(offset + 8);
    packet.ip.total_length = total_length;
    packet.ip.protocol_number = reader.u8(offset + 9);
    const auto fragment = reader.u16(offset + 6);
    packet.ip.fragment_offset = static_cast<std::uint32_t>(fragment & 0x1fffU) * 8U;
    packet.ip.more_fragments = (fragment & 0x2000U) != 0;
    packet.ip.fragmented = packet.ip.more_fragments || packet.ip.fragment_offset != 0;
    packet.source = {AddressFamily::ipv4, reader.copy(offset + 12, 4)};
    packet.destination = {AddressFamily::ipv4, reader.copy(offset + 16, 4)};
    if (packet.ip.fragment_offset != 0) {
        packet.transport = TransportProtocol::other;
        packet.payload = reader.copy(offset + header_length, total_length - header_length);
        return {std::move(packet), DecodeStatus::valid, {}};
    }
    const auto protocol = packet.ip.protocol_number;
    return decode_transport(std::move(packet), reader, offset + header_length, offset + total_length,
                             protocol);
}

DecodeResult decode_ipv6(Packet packet, const Reader& reader, std::size_t offset) {
    if (!reader.available(offset, 40)) return failure(std::move(packet), DecodeStatus::truncated, "truncated IPv6 header");
    if ((reader.u8(offset) >> 4) != 6) return failure(std::move(packet), DecodeStatus::malformed, "invalid IPv6 version");
    const auto payload_length = reader.u16(offset + 4);
    const auto end = offset + 40U + payload_length;
    if (end < offset || !reader.available(offset, 40U + payload_length))
        return failure(std::move(packet), DecodeStatus::truncated, "truncated IPv6 payload");

    packet.ip.version = 6;
    packet.ip.ttl_or_hop_limit = reader.u8(offset + 7);
    packet.ip.total_length = static_cast<std::uint16_t>(std::min<std::size_t>(65535, 40U + payload_length));
    packet.source = {AddressFamily::ipv6, reader.copy(offset + 8, 16)};
    packet.destination = {AddressFamily::ipv6, reader.copy(offset + 24, 16)};

    std::size_t transport_offset = offset + 40;
    std::uint8_t next_header = reader.u8(offset + 6);
    for (int extensions = 0; extensions < 16; ++extensions) {
        const bool length_encoded = next_header == 0 || next_header == 43 || next_header == 60 || next_header == 135 || next_header == 139;
        if (!length_encoded && next_header != 44) break;
        if (next_header == 44) {
            if (!reader.available(transport_offset, 8)) return failure(std::move(packet), DecodeStatus::truncated, "truncated IPv6 fragment header");
            const auto fragment = reader.u16(transport_offset + 2);
            packet.ip.fragment_offset = static_cast<std::uint32_t>((fragment >> 3) & 0x1fffU) * 8U;
            packet.ip.more_fragments = (fragment & 1U) != 0;
            packet.ip.fragmented = true;
            // Store the 32-bit Fragment Identification for deduplication.
            packet.ip.fragment_id = reader.u32(transport_offset + 4);
            next_header = reader.u8(transport_offset);
            transport_offset += 8;
        } else {
            if (!reader.available(transport_offset, 2)) return failure(std::move(packet), DecodeStatus::truncated, "truncated IPv6 extension header");
            const auto extension_length = (static_cast<std::size_t>(reader.u8(transport_offset + 1)) + 1U) * 8U;
            if (!reader.available(transport_offset, extension_length)) return failure(std::move(packet), DecodeStatus::truncated, "truncated IPv6 extension payload");
            next_header = reader.u8(transport_offset);
            transport_offset += extension_length;
        }
    }
    packet.ip.protocol_number = next_header;
    if (packet.ip.fragment_offset != 0) {
        packet.transport = TransportProtocol::other;
        packet.payload = reader.copy(transport_offset, end - transport_offset);
        return {std::move(packet), DecodeStatus::valid, {}};
    }
    const auto protocol = next_header;
    return decode_transport(std::move(packet), reader, transport_offset, end, protocol);
}

}  // namespace

DecodeResult decode(const capture::CapturedPacket& captured, std::string interface_id) {
    telemetry::MetricsRegistry::global().increment("packets_received");
    Packet packet;
    packet.timestamp_seconds = captured.seconds;
    packet.timestamp_nanoseconds = captured.nanoseconds;
    packet.capture_length = captured.captured_length;
    packet.original_length = captured.original_length;
    packet.interface_id = std::move(interface_id);
    Reader reader(captured.bytes);
    if (captured.captured_length != captured.bytes.size()) {
        telemetry::MetricsRegistry::global().increment("parser_errors");
        return failure(std::move(packet), DecodeStatus::malformed, "capture length does not match frame data");
    }
    if (captured.original_length < captured.captured_length) {
        telemetry::MetricsRegistry::global().increment("parser_errors");
        return failure(std::move(packet), DecodeStatus::malformed, "original length is smaller than capture length");
    }
    if (!reader.available(0, 14)) return failure(std::move(packet), DecodeStatus::truncated, "truncated Ethernet header");

    packet.ethernet.destination_mac = reader.copy(0, 6);
    packet.ethernet.source_mac = reader.copy(6, 6);
    std::uint16_t ether_type = reader.u16(12);
    std::size_t offset = 14;
    for (std::size_t tags = 0; tags < 8 && is_vlan(ether_type); ++tags) {
        if (!reader.available(offset, 4)) return failure(std::move(packet), DecodeStatus::truncated, "truncated VLAN header");
        const auto tci = reader.u16(offset);
        packet.vlan.identifiers.push_back(static_cast<std::uint16_t>(tci & 0x0fffU));
        // 3-bit PCP in the upper bits of TCI.
        packet.vlan.priorities.push_back(static_cast<std::uint8_t>((tci >> 13) & 0x07U));
        ether_type = reader.u16(offset + 2);
        offset += 4;
    }
    packet.ethernet.ether_type = ether_type;
    if (ether_type == kEtherTypeIpv4) return decode_ipv4(std::move(packet), reader, offset);
    if (ether_type == kEtherTypeIpv6) return decode_ipv6(std::move(packet), reader, offset);
    packet.status = DecodeStatus::unsupported;
    return {std::move(packet), DecodeStatus::unsupported, "unsupported Ethernet protocol"};
}

}  // namespace delta_nids::packet
