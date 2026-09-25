#include <cassert>
#include <cstdint>
#include <algorithm>

#include "behavioral/behavioral_manager.h"

namespace {
delta_nids::packet::Packet packet(std::uint8_t source_last, std::uint8_t destination_last,
                                   std::uint16_t destination_port, std::int64_t timestamp,
                                   std::uint8_t flags = 0x02) {
    delta_nids::packet::Packet value;
    value.timestamp_seconds = timestamp;
    value.capture_length = 60;
    value.transport = delta_nids::packet::TransportProtocol::tcp;
    value.source = {delta_nids::packet::AddressFamily::ipv4, {192, 0, 2, source_last}};
    value.destination = {delta_nids::packet::AddressFamily::ipv4, {198, 51, 100, destination_last}};
    value.source_port = 40000;
    value.destination_port = destination_port;
    value.tcp = delta_nids::packet::TcpMetadata{};
    value.tcp->flags = flags;
    return value;
}
}

int main() {
    using namespace delta_nids::behavioral;
    BehavioralConfig config;
    config.window_seconds = 30;
    config.port_scan_threshold = 3;
    config.host_sweep_threshold = 3;
    config.brute_force_threshold = 3;
    config.connection_flood_threshold = 3;
    config.dns_query_threshold = 3;
    BehavioralManager manager(config);

    delta_nids::flow::Flow flow;
    flow.id = 1;
    flow.service = "generic_tcp";
    for (std::uint16_t port = 1; port <= 3; ++port) {
        auto value = packet(1, 2, port, port);
        auto events = manager.observe(value, flow);
        if (port == 3) {
            bool found = false;
            for (const auto& event : events) found |= event.type == BehavioralType::port_scan;
            assert(found);
        }
    }

    BehavioralManager isolated_manager(config);
    auto udp_one = packet(1, 2, 53, 20);
    udp_one.transport = delta_nids::packet::TransportProtocol::udp;
    udp_one.source_port = 53000;
    auto udp_two = udp_one;
    udp_two.destination_port = 123;
    auto udp_other_destination = udp_one;
    udp_other_destination.destination = {delta_nids::packet::AddressFamily::ipv4, {198, 51, 100, 3}};
    assert(isolated_manager.observe(udp_one, flow).empty());
    assert(isolated_manager.observe(udp_two, flow).empty());
    assert(isolated_manager.observe(udp_other_destination, flow).empty());
    isolated_manager.expire(100);
    auto udp_after_expiry = udp_one;
    udp_after_expiry.timestamp_seconds = 101;
    assert(isolated_manager.observe(udp_after_expiry, flow).empty());

    BehavioralManager anomaly_manager(config);
    auto anomaly = packet(1, 2, 80, 10, 0x03);
    auto anomaly_events = anomaly_manager.observe(anomaly, flow);
    bool found_anomaly = false;
    for (const auto& event : anomaly_events) found_anomaly |= event.type == BehavioralType::tcp_anomaly;
    assert(found_anomaly);
    assert(anomaly_manager.metrics().packets_observed == 1);

    // Test SSH brute force detection (RST or FIN flags on SSH service flow)
    BehavioralManager ssh_manager(config);
    delta_nids::flow::Flow ssh_flow;
    ssh_flow.id = 2;
    ssh_flow.service = "SSH";
    for (std::int64_t t = 1; t <= 3; ++t) {
        auto ssh_pkt = packet(1, 2, 22, t, 0x04); // RST flag
        auto ssh_events = ssh_manager.observe(ssh_pkt, ssh_flow);
        if (t == 3) {
            bool found_ssh = false;
            for (const auto& event : ssh_events) found_ssh |= event.type == BehavioralType::brute_force;
            assert(found_ssh);
        }
    }

    // A real brute-force campaign (one new TCP connection per attempt) is a
    // series of plain SYNs toward the SSH service, not bare RST/FIN packets.
    BehavioralManager ssh_syn_manager(config);
    delta_nids::flow::Flow ssh_syn_flow;
    ssh_syn_flow.id = 7;
    ssh_syn_flow.service = "SSH";
    for (std::int64_t t = 1; t <= 3; ++t) {
        auto ssh_syn_pkt = packet(1, 2, 22, t, 0x02); // plain SYN flag
        auto ssh_syn_events = ssh_syn_manager.observe(ssh_syn_pkt, ssh_syn_flow);
        if (t == 3) {
            bool found_ssh_syn = false;
            for (const auto& event : ssh_syn_events) found_ssh_syn |= event.type == BehavioralType::brute_force;
            assert(found_ssh_syn);
        }
    }

    // Test Connection flood detection (repeated connections to same target)
    BehavioralManager flood_manager(config);
    delta_nids::flow::Flow generic_flow;
    generic_flow.id = 3;
    generic_flow.service = "HTTP";
    for (std::int64_t t = 1; t <= 3; ++t) {
        auto flood_pkt = packet(1, 2, 80, t, 0x02); // SYN flag
        auto flood_events = flood_manager.observe(flood_pkt, generic_flow);
        if (t == 3) {
            bool found_flood = false;
            for (const auto& event : flood_events) found_flood |= event.type == BehavioralType::connection_flood;
            assert(found_flood);
        }
    }

    // Test DNS anomaly detection (high DNS query rate with payload)
    BehavioralManager dns_manager(config);
    delta_nids::flow::Flow dns_flow;
    dns_flow.id = 4;
    dns_flow.service = "DNS";
    for (std::int64_t t = 1; t <= 3; ++t) {
        auto dns_pkt = packet(1, 2, 53, t);
        dns_pkt.transport = delta_nids::packet::TransportProtocol::udp;
        dns_pkt.payload = {0x00, 0x01, 0x01, 0x00, 0x00, 0x01}; // Sample DNS header payload
        auto dns_events = dns_manager.observe(dns_pkt, dns_flow);
        if (t == 3) {
            bool found_dns = false;
            for (const auto& event : dns_events) found_dns |= event.type == BehavioralType::dns_anomaly;
            assert(found_dns);
        }
    }

    // Ordinary established traffic must not be interpreted as host discovery.
    BehavioralManager ordinary_manager(config);
    delta_nids::flow::Flow ordinary_flow;
    ordinary_flow.id = 6;
    ordinary_flow.service = "generic_tcp";
    for (std::uint8_t target_host = 1; target_host <= 3; ++target_host) {
        auto ordinary_pkt = packet(1, target_host, 443, target_host, 0x10); // ACK only
        auto ordinary_events = ordinary_manager.observe(ordinary_pkt, ordinary_flow);
        const bool emitted_host_sweep = std::any_of(
            ordinary_events.begin(), ordinary_events.end(),
            [](const auto& event) { return event.type == BehavioralType::host_sweep; });
        (void)emitted_host_sweep;
        assert(!emitted_host_sweep);
    }

    // Test Host sweep / ICMP sweep detection (contacting multiple unique hosts)
    BehavioralManager sweep_manager(config);
    delta_nids::flow::Flow icmp_flow;
    icmp_flow.id = 5;
    icmp_flow.service = "ICMP";
    for (std::uint8_t target_host = 1; target_host <= 3; ++target_host) {
        auto sweep_pkt = packet(1, target_host, 0, target_host);
        sweep_pkt.transport = delta_nids::packet::TransportProtocol::icmp;
        sweep_pkt.source_port.reset();
        sweep_pkt.destination_port.reset();
        sweep_pkt.tcp.reset();
        sweep_pkt.icmp = delta_nids::packet::IcmpMetadata{8, 0};
        auto sweep_events = sweep_manager.observe(sweep_pkt, icmp_flow);
        if (target_host == 3) {
            bool found_sweep = false;
            for (const auto& event : sweep_events) found_sweep |= event.type == BehavioralType::host_sweep;
            assert(found_sweep);
        }
    }

    return 0;
}

