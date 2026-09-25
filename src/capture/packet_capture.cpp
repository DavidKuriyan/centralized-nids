#include "capture/packet_capture.h"

#include <stdexcept>

namespace delta_nids::capture {

std::unique_ptr<PacketCapture> make_pcap_capture(const CaptureConfig& config);

namespace {
void validate(const CaptureConfig& config) {
    if (config.snap_length == 0 || config.snap_length > 262144)
        throw std::invalid_argument("snap length must be between 1 and 262144 bytes");
    if (config.timeout_ms < 0)
        throw std::invalid_argument("capture timeout cannot be negative");
    if (config.interface_name.empty() == config.pcap_path.empty())
        throw std::invalid_argument("exactly one of interface_name or pcap_path is required");
}
}  // namespace

std::unique_ptr<PacketCapture> make_capture(const CaptureConfig& config) {
    validate(config);
    return make_pcap_capture(config);
}

}  // namespace delta_nids::capture
