#include "capture/packet_capture.h"
#include "telemetry/telemetry.h"

#include <pcap/pcap.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

// EtherType constants used for protocol-breakdown counters.
// These are only needed here for statistics; the full decoder in packet/decoder.cpp
// uses its own local copies and they must stay in sync with IEEE 802.
namespace {
constexpr std::uint16_t kEtherTypeVlan  = 0x8100;
constexpr std::uint16_t kEtherTypeQinQ  = 0x88a8;
constexpr std::uint16_t kEtherTypeIpv4  = 0x0800;
constexpr std::uint16_t kEtherTypeIpv6  = 0x86dd;
constexpr std::uint8_t  kProtoTcp       = 6;
constexpr std::uint8_t  kProtoUdp       = 17;
constexpr std::uint8_t  kProtoIcmp      = 1;
constexpr std::uint8_t  kProtoIcmpv6    = 58;
}  // namespace

namespace delta_nids::capture {
namespace {

// Update protocol-breakdown counters from a raw Ethernet frame.
// This is a lightweight pass over the frame header only – it never
// deep-copies payload bytes and stops as soon as it has classified the frame.
void update_protocol_counters(const std::uint8_t* data, std::uint32_t caplen,
                              CaptureStatistics& stats) noexcept {
    if (caplen < 14) return;
    std::uint16_t ether_type =
        static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[12]) << 8) | data[13]);
    std::size_t offset = 14;

    // Strip VLAN tags (802.1Q / QinQ).
    if (ether_type == kEtherTypeVlan || ether_type == kEtherTypeQinQ) {
        ++stats.vlan_packets;
        while ((ether_type == kEtherTypeVlan || ether_type == kEtherTypeQinQ) &&
               offset + 4 <= caplen) {
            ether_type = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(data[offset + 2]) << 8) | data[offset + 3]);
            offset += 4;
        }
    }

    if (ether_type == kEtherTypeIpv4) {
        ++stats.ipv4_packets;
        // IP header must be at least 20 bytes.
        if (offset + 20 > caplen) return;
        const std::uint8_t ihl   = (data[offset] & 0x0fU) * 4U;
        const std::uint8_t proto = data[offset + 9];
        offset += ihl;
        if (proto == kProtoTcp)    { ++stats.tcp_packets;    return; }
        if (proto == kProtoUdp)    { ++stats.udp_packets;    return; }
        if (proto == kProtoIcmp)   { ++stats.icmp_packets;   return; }
        return;
    }
    if (ether_type == kEtherTypeIpv6) {
        ++stats.ipv6_packets;
        // IPv6 fixed header = 40 bytes; next-header at byte 6.
        if (offset + 40 > caplen) return;
        std::uint8_t next_header = data[offset + 6];
        std::size_t  ext_offset  = offset + 40;
        // Walk extension headers (up to 16 hops, matching decoder.cpp).
        for (int ext = 0; ext < 16; ++ext) {
            const bool length_encoded =
                next_header == 0 || next_header == 43 || next_header == 60 ||
                next_header == 135 || next_header == 139;
            if (!length_encoded && next_header != 44) break;
            if (ext_offset + 2 > caplen) return;
            const std::uint8_t ext_len = next_header == 44
                ? 8U
                : (static_cast<std::uint8_t>(data[ext_offset + 1]) + 1U) * 8U;
            next_header = data[ext_offset];
            ext_offset += ext_len;
        }
        if (next_header == kProtoTcp)    { ++stats.tcp_packets;    return; }
        if (next_header == kProtoUdp)    { ++stats.udp_packets;    return; }
        if (next_header == kProtoIcmpv6) { ++stats.icmpv6_packets; return; }
        return;
    }
}

class PcapCapture final : public PacketCapture {
public:
    explicit PcapCapture(CaptureConfig config) : config_(std::move(config)) {}
    ~PcapCapture() override { stop(); }

    void run(const PacketHandler& handler) override {
        if (!handler) throw std::invalid_argument("packet handler must not be empty");
        stopped_.store(false);
        open();
        while (!stopped_.load()) {
            pcap_pkthdr* header  = nullptr;
            const u_char* bytes  = nullptr;
            const int result = pcap_next_ex(handle_, &header, &bytes);
            if (result == 0)  continue;
            if (result == -2) break;
            if (result < 0) {
                telemetry::MetricsRegistry::global().increment("capture_errors");
                throw std::runtime_error(pcap_geterr(handle_));
            }
            ++statistics_.received;
            telemetry::MetricsRegistry::global().increment("packets_received");

            CapturedPacket packet;
            packet.seconds          = static_cast<std::int64_t>(header->ts.tv_sec);
            packet.nanoseconds      = static_cast<std::int32_t>(header->ts.tv_usec) * 1000;
            packet.captured_length  = header->caplen;
            packet.original_length  = header->len;
            packet.bytes.assign(bytes, bytes + header->caplen);

            if (header->caplen < header->len) ++statistics_.truncated;
            statistics_.bytes_captured += header->caplen;

            // Per-frame protocol breakdown counters.
            if (!packet.bytes.empty())
                update_protocol_counters(packet.bytes.data(), packet.captured_length,
                                         statistics_);

            ++statistics_.delivered;
            telemetry::MetricsRegistry::global().increment("packets_processed");
            handler(std::move(packet));
        }
        // Refresh kernel drop count before closing.
        sync_pcap_stats();
        close();
    }

    void stop() noexcept override {
        stopped_.store(true);
        if (handle_) pcap_breakloop(handle_);
    }

    [[nodiscard]] CaptureStatistics statistics() const noexcept override {
        return statistics_;
    }

private:
    // ------------------------------------------------------------------
    // Open the pcap handle, applying SPAN-mode settings when required.
    //
    // SPAN mode forces:
    //   - promiscuous = 1        (catch all frames on the mirror interface)
    //   - snaplen     = 65535    (capture full frames)
    //   - NO BPF filter by default (all EtherTypes must pass)
    //
    // Normal mode applies the user-supplied BPF filter (if any).  The
    // old hard-coded "ip" filter that silently discarded IPv6 has been
    // removed.
    // ------------------------------------------------------------------
    void open() {
        char error[PCAP_ERRBUF_SIZE] = {};
        if (!config_.pcap_path.empty()) {
            // ----- Offline PCAP replay -----
            handle_ = pcap_open_offline(config_.pcap_path.c_str(), error);
        } else {
            // ----- Live capture (normal or SPAN) -----
            const bool span_mode = config_.mode == CaptureMode::span;

            // SPAN mode always uses promiscuous capture.
            const bool promisc = span_mode || config_.promiscuous;
            // SPAN mode always captures the maximum frame size.
            const int snaplen  = span_mode
                ? 65535
                : static_cast<int>(config_.snap_length);

            handle_ = pcap_create(config_.interface_name.c_str(), error);
            if (!handle_) throw std::runtime_error(error);

            if (pcap_set_snaplen(handle_, snaplen) != 0 ||
                pcap_set_promisc(handle_, promisc ? 1 : 0) != 0 ||
                pcap_set_timeout(handle_, config_.timeout_ms) != 0) {
                const std::string message = pcap_geterr(handle_);
                close();
                throw std::runtime_error(message);
            }
            if (config_.buffer_size > 0 &&
                pcap_set_buffer_size(handle_, static_cast<int>(config_.buffer_size)) != 0) {
                const std::string message = pcap_geterr(handle_);
                close();
                throw std::runtime_error(message);
            }
            const int activated = pcap_activate(handle_);
            if (activated != 0) {
                const std::string message = pcap_statustostr(activated);
                close();
                throw std::runtime_error(message);
            }

            // Apply BPF filter only when explicitly requested.
            // SPAN mode: no default filter (all EtherTypes including IPv6 must pass).
            // Normal mode: no default filter either — the old hard-coded "ip" filter
            //              that silently discarded IPv6 has been intentionally removed.
            if (!config_.bpf_filter.empty()) {
                bpf_program program{};
                if (pcap_compile(handle_, &program, config_.bpf_filter.c_str(), 1,
                                 PCAP_NETMASK_UNKNOWN) != 0) {
                    const std::string message = pcap_geterr(handle_);
                    close();
                    throw std::runtime_error(message);
                }
                const int set_result = pcap_setfilter(handle_, &program);
                pcap_freecode(&program);
                if (set_result != 0) {
                    const std::string message = pcap_geterr(handle_);
                    close();
                    throw std::runtime_error(message);
                }
            }
        }
        if (!handle_) throw std::runtime_error(error[0] ? error : "unable to open capture source");
    }

    void close() noexcept {
        if (handle_) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
    }

    // Refresh statistics_.dropped from the kernel's pcap_stats().
    // pcap_stats() is only valid for live captures (not offline).
    void sync_pcap_stats() noexcept {
        if (!handle_ || !config_.pcap_path.empty()) return;
        pcap_stat ps{};
        if (pcap_stats(handle_, &ps) == 0) {
            statistics_.dropped = ps.ps_drop;
            const std::uint64_t total = statistics_.received + statistics_.dropped;
            if (total > 0) {
                statistics_.capture_loss_percent =
                    static_cast<double>(statistics_.dropped) / static_cast<double>(total) * 100.0;
            } else {
                statistics_.capture_loss_percent = 0.0;
            }
        }
    }

    CaptureConfig     config_;
    pcap_t*           handle_   = nullptr;
    std::atomic<bool> stopped_{false};
    CaptureStatistics statistics_{};
};

}  // namespace

std::unique_ptr<PacketCapture> make_pcap_capture(const CaptureConfig& config) {
    return std::make_unique<PcapCapture>(config);
}

}  // namespace delta_nids::capture
