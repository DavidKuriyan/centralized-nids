#include "capture/packet_capture.h"
#include "telemetry/telemetry.h"

#include <pcap/pcap.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

namespace delta_nids::capture {
namespace {

class PcapCapture final : public PacketCapture {
public:
    explicit PcapCapture(CaptureConfig config) : config_(std::move(config)) {}
    ~PcapCapture() override { stop(); }

    void run(const PacketHandler& handler) override {
        if (!handler) throw std::invalid_argument("packet handler must not be empty");
        stopped_.store(false);
        open();
        while (!stopped_.load()) {
            pcap_pkthdr* header = nullptr;
            const u_char* bytes = nullptr;
            const int result = pcap_next_ex(handle_, &header, &bytes);
            if (result == 0) continue;
            if (result == -2) break;
            if (result < 0) { telemetry::MetricsRegistry::global().increment("capture_errors"); throw std::runtime_error(pcap_geterr(handle_)); }
            ++statistics_.received;
            telemetry::MetricsRegistry::global().increment("packets_received");
            CapturedPacket packet;
            packet.seconds = static_cast<std::int64_t>(header->ts.tv_sec);
            packet.nanoseconds = static_cast<std::int32_t>(header->ts.tv_usec) * 1000;
            packet.captured_length = header->caplen;
            packet.original_length = header->len;
            packet.bytes.assign(bytes, bytes + header->caplen);
            if (header->caplen < header->len) ++statistics_.truncated;
            ++statistics_.delivered;
            telemetry::MetricsRegistry::global().increment("packets_processed");
            handler(std::move(packet));
        }
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
    void open() {
        char error[PCAP_ERRBUF_SIZE] = {};
        if (!config_.pcap_path.empty()) {
            handle_ = pcap_open_offline(config_.pcap_path.c_str(), error);
        } else {
            handle_ = pcap_create(config_.interface_name.c_str(), error);
            if (!handle_) throw std::runtime_error(error);
            if (pcap_set_snaplen(handle_, static_cast<int>(config_.snap_length)) != 0 ||
                pcap_set_promisc(handle_, config_.promiscuous ? 1 : 0) != 0 ||
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
        }
        if (!handle_) throw std::runtime_error(error[0] ? error : "unable to open capture source");
        if (!config_.bpf_filter.empty() && !config_.pcap_path.empty()) {
            // Offline filtering is intentionally not emulated. PCAP filters are
            // applied by the live capture backend only in this phase.
        }
        if (config_.pcap_path.empty()) {
            // Enforce IPv4-only capture at the libpcap boundary. A user filter
            // may further narrow traffic, but cannot re-enable IPv6.
            const std::string ipv4_filter = config_.bpf_filter.empty()
                ? "ip"
                : "(ip) and (" + config_.bpf_filter + ")";
            bpf_program program{};
            if (pcap_compile(handle_, &program, ipv4_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
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

    void close() noexcept {
        if (handle_) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
    }

    CaptureConfig config_;
    pcap_t* handle_ = nullptr;
    std::atomic<bool> stopped_{false};
    CaptureStatistics statistics_{};
};

}  // namespace

std::unique_ptr<PacketCapture> make_pcap_capture(const CaptureConfig& config) {
    return std::make_unique<PcapCapture>(config);
}

}  // namespace delta_nids::capture
