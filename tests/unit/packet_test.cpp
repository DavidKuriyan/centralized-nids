#include <cassert>
#include <cstdint>
#include <vector>

#include "packet/packet.h"

namespace {
using delta_nids::capture::CapturedPacket;
using delta_nids::packet::AddressFamily;
using delta_nids::packet::DecodeStatus;
using delta_nids::packet::TransportProtocol;

void put16(std::vector<std::uint8_t>& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}
void put32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 24));
    b.push_back(static_cast<std::uint8_t>(v >> 16));
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}
void ethernet(std::vector<std::uint8_t>& b, std::uint16_t type) {
    b.insert(b.end(), {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11});
    put16(b, type);
}
CapturedPacket captured(std::vector<std::uint8_t> bytes) {
    return {1, 2, static_cast<std::uint32_t>(bytes.size()), static_cast<std::uint32_t>(bytes.size()), std::move(bytes)};
}
std::vector<std::uint8_t> ipv4_tcp() {
    std::vector<std::uint8_t> b;
    ethernet(b, 0x0800);
    b.insert(b.end(), {0x45, 0, 0, 0x28, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2});
    put16(b, 1234); put16(b, 80); put32(b, 10); put32(b, 0);
    b.insert(b.end(), {0x50, 0x02, 0x10, 0, 0, 0, 0, 0});
    return b;
}
}  // namespace

int main() {
    {
        auto result = delta_nids::packet::decode(captured(ipv4_tcp()), "test0");
        assert(result.status == DecodeStatus::valid);
        assert(result.packet.has_value());
        assert(result.packet->source.family == AddressFamily::ipv4);
        assert(result.packet->source.to_string() == "192.0.2.1");
        assert(result.packet->destination.to_string() == "198.51.100.2");
        assert(result.packet->transport == TransportProtocol::tcp);
        assert(result.packet->source_port == 1234);
        assert(result.packet->destination_port == 80);
        assert(result.packet->tcp->flags == 2);
        assert(result.packet->interface_id == "test0");
    }
    {
        auto bytes = ipv4_tcp();
        bytes.resize(10);
        auto result = delta_nids::packet::decode(captured(std::move(bytes)), "test0");
        assert(result.status == DecodeStatus::truncated);
        assert(result.packet.has_value());
    }
    {
        std::vector<std::uint8_t> bytes;
        ethernet(bytes, 0x8100);
        put16(bytes, 7); put16(bytes, 0x0800);
        const auto inner = ipv4_tcp();
        bytes.insert(bytes.end(), inner.begin() + 14, inner.end());
        auto result = delta_nids::packet::decode(captured(std::move(bytes)), "test0");
        assert(result.status == DecodeStatus::valid);
        assert(result.packet->vlan.identifiers.size() == 1);
        assert(result.packet->vlan.identifiers.front() == 7);
    }
    {
        std::vector<std::uint8_t> bytes;
        ethernet(bytes, 0x0800);
        bytes.insert(bytes.end(), {0x41, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2});
        auto result = delta_nids::packet::decode(captured(std::move(bytes)), "test0");
        assert(result.status == DecodeStatus::malformed);
    }
    return 0;
}
