#include <cassert>
#include <string>

#include "capture/packet_capture.h"
#include "capture/span_diagnostics.h"

int main() {
    using delta_nids::capture::CaptureConfig;
    using delta_nids::capture::CaptureMode;
    using delta_nids::capture::CaptureStatistics;
    using delta_nids::capture::zero_traffic_diagnostic;
    using delta_nids::capture::zero_traffic_warning_short;

    // Test 1: CaptureConfig SPAN mode defaults and assignment
    CaptureConfig config;
    config.interface_name = "eth0";
    config.mode = CaptureMode::span;
    config.promiscuous = true;
    config.snap_length = 65535;
    config.buffer_size = 16 * 1024 * 1024;

    assert(config.mode == CaptureMode::span);
    assert(config.promiscuous == true);
    assert(config.snap_length == 65535);
    assert(config.buffer_size == 16 * 1024 * 1024);

    // Test 2: CaptureStatistics protocol accounting
    CaptureStatistics stats;
    stats.received = 100;
    stats.ipv4_packets = 80;
    stats.ipv6_packets = 20;
    stats.tcp_packets = 50;
    stats.udp_packets = 30;
    stats.icmp_packets = 15;
    stats.icmpv6_packets = 5;
    stats.vlan_packets = 10;
    stats.duplicate_packets = 2;

    assert(stats.received == 100);
    assert(stats.ipv4_packets == 80);
    assert(stats.ipv6_packets == 20);
    assert(stats.vlan_packets == 10);
    assert(stats.duplicate_packets == 2);

    // Test 3: Zero-traffic diagnostic messages
    const auto diag_msg = zero_traffic_diagnostic("eth1", 15.0);
    assert(!diag_msg.empty());
    assert(diag_msg.find("eth1") != std::string::npos);
    assert(diag_msg.find("No traffic detected on SPAN interface") != std::string::npos);

    const auto short_warn = zero_traffic_warning_short("eth1");
    assert(!short_warn.empty());
    assert(short_warn.find("eth1") != std::string::npos);

    return 0;
}
