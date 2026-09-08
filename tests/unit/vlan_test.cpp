#include <cassert>
#include <cstdint>
#include <vector>

#include "packet/packet.h"

namespace {
using delta_nids::capture::CapturedPacket;
using delta_nids::packet::DecodeStatus;

void put16(std::vector<std::uint8_t>& b, std::uint16_t v) {
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

std::vector<std::uint8_t> ipv4_icmp() {
    std::vector<std::uint8_t> b;
    ethernet(b, 0x0800);
    // IPv4 header: 20 bytes
    b.insert(b.end(), {0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2});
    // ICMP echo request: 8 bytes
    b.insert(b.end(), {8, 0, 0, 0, 0, 1, 0, 1});
    return b;
}
} // namespace

int main() {
    // Test 1: Single VLAN (802.1Q)
    {
        std::vector<std::uint8_t> bytes;
        ethernet(bytes, 0x8100);
        put16(bytes, 100);       // VLAN ID 100
        put16(bytes, 0x0800);    // Inner EtherType IPv4
        const auto inner = ipv4_icmp();
        bytes.insert(bytes.end(), inner.begin() + 14, inner.end());

        auto result = delta_nids::packet::decode(captured(std::move(bytes)), "eth0");
        assert(result.status == DecodeStatus::valid);
        assert(result.packet.has_value());
        assert(result.packet->vlan.identifiers.size() == 1);
        assert(result.packet->vlan.identifiers[0] == 100);
        assert(result.packet->source.to_string() == "10.0.0.1");
        assert(result.packet->destination.to_string() == "10.0.0.2");
    }

    // Test 2: Double VLAN / QinQ (802.1ad outer 0x88A8, 802.1Q inner 0x8100)
    {
        std::vector<std::uint8_t> bytes;
        ethernet(bytes, 0x88A8);
        put16(bytes, 200);       // Outer VLAN 200
        put16(bytes, 0x8100);    // Inner 802.1Q
        put16(bytes, 100);       // Inner VLAN 100
        put16(bytes, 0x0800);    // Inner EtherType IPv4
        const auto inner = ipv4_icmp();
        bytes.insert(bytes.end(), inner.begin() + 14, inner.end());

        auto result = delta_nids::packet::decode(captured(std::move(bytes)), "eth0");
        assert(result.status == DecodeStatus::valid);
        assert(result.packet.has_value());
        assert(result.packet->vlan.identifiers.size() == 2);
        assert(result.packet->vlan.identifiers[0] == 200);
        assert(result.packet->vlan.identifiers[1] == 100);
    }

    return 0;
}
