#include <cassert>
#include <stdexcept>

#include "capture/packet_capture.h"

int main() {
    using delta_nids::capture::CaptureConfig;
    using delta_nids::capture::make_capture;

    CaptureConfig invalid;
    bool rejected = false;
    try {
        auto source = make_capture(invalid);
        (void)source;
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    assert(rejected);

    CaptureConfig invalid_length;
    invalid_length.pcap_path = "missing.pcap";
    invalid_length.snap_length = 0;
    rejected = false;
    try {
        auto source = make_capture(invalid_length);
        (void)source;
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    assert(rejected);
    return 0;
}
