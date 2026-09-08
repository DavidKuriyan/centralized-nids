#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace delta_nids::capture {

// Capture mode selection.
// normal : standard live interface capture
// span   : SPAN / port-mirror destination interface (promiscuous, no BPF)
// pcap   : offline PCAP replay
enum class CaptureMode { normal, span, pcap };

[[nodiscard]] inline const char* capture_mode_name(CaptureMode mode) noexcept {
    switch (mode) {
        case CaptureMode::normal: return "normal";
        case CaptureMode::span:   return "span";
        case CaptureMode::pcap:   return "pcap";
    }
    return "unknown";
}

struct CaptureConfig {
    std::string interface_name;
    std::string pcap_path;
    std::string bpf_filter;
    std::size_t snap_length = 65535;
    std::size_t buffer_size = 0;
    int timeout_ms = 1000;
    bool promiscuous = true;
    // When mode == span the capture layer forces promiscuous ON and applies
    // no BPF filter (all EtherTypes pass).  The caller may still override
    // bpf_filter for additional filtering, but the default is empty.
    CaptureMode mode = CaptureMode::normal;
};

struct CapturedPacket {
    std::int64_t seconds = 0;
    std::int32_t nanoseconds = 0;
    std::uint32_t captured_length = 0;
    std::uint32_t original_length = 0;
    std::vector<std::uint8_t> bytes;
};

// Extended capture statistics available for monitoring and dashboard display.
struct CaptureStatistics {
    // Core pcap counters
    std::uint64_t received   = 0;
    std::uint64_t delivered  = 0;
    std::uint64_t dropped    = 0;   // reported by pcap_stats (kernel drops)
    std::uint64_t truncated  = 0;   // caplen < origlen (snaplen hit)

    // Extended counters (populated by PcapCapture)
    std::uint64_t bytes_captured     = 0;
    std::uint64_t duplicate_packets  = 0;
    std::uint64_t malformed_packets  = 0;

    // Protocol breakdown
    std::uint64_t ipv4_packets   = 0;
    std::uint64_t ipv6_packets   = 0;
    std::uint64_t vlan_packets   = 0;
    std::uint64_t tcp_packets    = 0;
    std::uint64_t udp_packets    = 0;
    std::uint64_t icmp_packets   = 0;
    std::uint64_t icmpv6_packets = 0;

    // Capture loss as a fraction [0,100].  -1 indicates "not available".
    double capture_loss_percent = -1.0;
};

using PacketHandler = std::function<void(CapturedPacket)>;

class PacketCapture {
public:
    virtual ~PacketCapture() = default;
    virtual void run(const PacketHandler& handler) = 0;
    virtual void stop() noexcept = 0;
    [[nodiscard]] virtual CaptureStatistics statistics() const noexcept = 0;
};

[[nodiscard]] std::unique_ptr<PacketCapture> make_capture(const CaptureConfig& config);

}  // namespace delta_nids::capture
