#include <cassert>
#include <array>
#include <chrono>
#include <cstdint>
#include <vector>

#include "capture/ipv6_fragment_cache.h"
#include "packet/packet.h"

namespace {
using delta_nids::capture::CapturedPacket;
using delta_nids::capture::Fragment;
using delta_nids::capture::FragmentKey;
using delta_nids::capture::IPv6FragmentCache;
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

std::vector<std::uint8_t> ipv6_tcp() {
    std::vector<std::uint8_t> b;
    ethernet(b, 0x86DD); // IPv6 ethertype
    // IPv6 header: version 6, traffic class 0, flow label 0 (4 bytes: 0x60, 0, 0, 0)
    b.insert(b.end(), {0x60, 0x00, 0x00, 0x00});
    // Payload length: 20 bytes TCP (2 bytes)
    put16(b, 20);
    // Next header: 6 (TCP), Hop limit: 64
    b.push_back(6);
    b.push_back(64);
    // Source: 2001:db8::1
    b.insert(b.end(), {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    // Destination: 2001:db8::2
    b.insert(b.end(), {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2});
    // TCP header: sport 8080, dport 443
    put16(b, 8080); put16(b, 443); put32(b, 100); put32(b, 0);
    // data offset 5, flags SYN (0x02), window 8192, checksum 0, urgent 0
    b.insert(b.end(), {0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0});
    return b;
}
} // namespace

int main() {
    // Test 1: IPv6 decoding
    {
        auto result = delta_nids::packet::decode(captured(ipv6_tcp()), "eth0");
        assert(result.status == DecodeStatus::valid);
        assert(result.packet.has_value());
        assert(result.packet->source.family == AddressFamily::ipv6);
        assert(result.packet->destination.family == AddressFamily::ipv6);
        assert(result.packet->transport == TransportProtocol::tcp);
        assert(result.packet->source_port == 8080);
        assert(result.packet->destination_port == 443);
    }

    // Test 2: IPv6FragmentCache
    {
        IPv6FragmentCache cache;
        assert(cache.group_count() == 0);

        FragmentKey key;
        key.src = {0x20, 1, 0xd, 0xb8, 0,0,0,0,0,0,0,0,0,0,0,1};
        key.dst = {0x20, 1, 0xd, 0xb8, 0,0,0,0,0,0,0,0,0,0,0,2};
        key.id = 0x12345678;

        Fragment frag1;
        frag1.offset = 0;
        frag1.last = false;
        frag1.next_header = 6; // TCP
        frag1.arrived = 100;
        frag1.data = {1, 2, 3, 4, 5, 6, 7, 8};

        std::uint8_t proto = 0;
        auto res1 = cache.add(key, frag1, proto);
        assert(!res1.has_value());
        assert(cache.group_count() == 1);

        Fragment frag2;
        frag2.offset = 8;
        frag2.last = true;
        frag2.next_header = 6;
        frag2.arrived = 101;
        frag2.data = {9, 10, 11, 12};

        auto res2 = cache.add(key, frag2, proto);
        assert(res2.has_value());
        assert(res2->size() == 12);
        assert(proto == 6);
        assert(res2->at(0) == 1);
        assert(res2->at(11) == 12);
        assert(cache.group_count() == 0);
    }

    return 0;
}
