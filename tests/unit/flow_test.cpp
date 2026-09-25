#include <cassert>
#include <cstdint>
#include <vector>

#include "flow/flow_manager.h"

namespace {

delta_nids::packet::Packet make_packet(const char* source, const char* destination,
                                       std::uint16_t source_port, std::uint16_t destination_port,
                                       std::int64_t timestamp) {
    delta_nids::packet::Packet packet;
    packet.timestamp_seconds = timestamp;
    packet.capture_length = 100;
    packet.original_length = 100;
    packet.source = {delta_nids::packet::AddressFamily::ipv4, {192, 0, 2, static_cast<std::uint8_t>(source[0] - '0')}};
    packet.destination = {delta_nids::packet::AddressFamily::ipv4, {198, 51, 100, static_cast<std::uint8_t>(destination[0] - '0')}};
    packet.source_port = source_port;
    packet.destination_port = destination_port;
    packet.transport = delta_nids::packet::TransportProtocol::tcp;
    packet.tcp = delta_nids::packet::TcpMetadata{};
    return packet;
}

}  // namespace

int main() {
    using namespace delta_nids::flow;
    FlowManagerConfig config;
    config.idle_timeout_seconds = 10;
    config.lifetime_timeout_seconds = 100;
    config.maximum_flows = 2;
    FlowManager manager(config);
    const auto forward = make_packet("1", "2", 40000, 443, 10);
    auto reverse = make_packet("1", "2", 443, 40000, 11);
    reverse.source = forward.destination;
    reverse.destination = forward.source;

    auto& first = manager.process(forward);
    const auto id = first.id;
    assert(first.stats.client_packets == 1);
    assert(first.stats.server_packets == 0);
    auto& same = manager.process(reverse);
    assert(same.id == id);
    assert(manager.size() == 1);
    assert(same.stats.client_packets == 1);
    assert(same.stats.server_packets == 1);
    assert(same.state == FlowState::established);

    const auto expired = manager.expire(21);
    assert(expired.size() == 1);
    assert(expired.front().reason == ExpirationReason::idle_timeout);
    assert(manager.size() == 0);

    (void)manager.process(make_packet("1", "2", 1, 2, 30));
    (void)manager.process(make_packet("3", "4", 3, 4, 30));
    (void)manager.process(make_packet("5", "6", 5, 6, 30));
    assert(manager.size() == 2);
    assert(manager.statistics().evicted == 1);

    // IPv6 flow test
    {
        delta_nids::packet::Packet v6_fwd;
        v6_fwd.timestamp_seconds = 40;
        v6_fwd.capture_length = 100;
        v6_fwd.original_length = 100;
        v6_fwd.source = {delta_nids::packet::AddressFamily::ipv6, {0x20, 1, 0x0d, 0xb8, 0,0,0,0,0,0,0,0,0,0,0,1}};
        v6_fwd.destination = {delta_nids::packet::AddressFamily::ipv6, {0x20, 1, 0x0d, 0xb8, 0,0,0,0,0,0,0,0,0,0,0,2}};
        v6_fwd.source_port = 50000;
        v6_fwd.destination_port = 80;
        v6_fwd.transport = delta_nids::packet::TransportProtocol::tcp;
        v6_fwd.tcp = delta_nids::packet::TcpMetadata{};

        delta_nids::packet::Packet v6_rev = v6_fwd;
        v6_rev.source = v6_fwd.destination;
        v6_rev.destination = v6_fwd.source;
        v6_rev.source_port = 80;
        v6_rev.destination_port = 50000;
        v6_rev.timestamp_seconds = 41;

        auto& v6_flow1 = manager.process(v6_fwd);
        const auto v6_id = v6_flow1.id;
        auto& v6_flow2 = manager.process(v6_rev);
        assert(v6_flow2.id == v6_id);
        assert(manager.size() == 1);
        assert(v6_flow2.stats.client_packets == 1);
        assert(v6_flow2.stats.server_packets == 1);
        (void)manager.flush();
    }

    return 0;
}
