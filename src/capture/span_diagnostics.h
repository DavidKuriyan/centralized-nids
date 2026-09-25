// span_diagnostics.h  —  Delta-NIDS SPAN / Port-Mirror capture diagnostics
//
// Provides a clear, actionable diagnostic when a SPAN interface receives
// zero traffic, and validates that the interface is ready for capture before
// the capture loop starts.
#pragma once

#include "capture/packet_capture.h"

#include <string>
#include <vector>

// libpcap forward declaration (avoids pulling the full header in translation
// units that only need the diagnostic helpers).
struct pcap;
typedef pcap pcap_t;

namespace delta_nids::capture {

// Result of pre-capture SPAN interface validation.
struct SpanValidationResult {
    bool ok          = false;   // true when all checks pass
    bool iface_found = false;   // interface exists in the system
    bool iface_up    = false;   // interface is administratively/operationally UP
    bool pcap_ok     = false;   // libpcap can open the interface
    bool promisc_ok  = false;   // promiscuous mode activated successfully
    std::string error_message;  // human-readable summary of the first failure
};

// Validate that a SPAN interface is ready before starting the capture loop.
// Checks:
//   1. Interface is present in the system interface list.
//   2. libpcap can open the interface.
//   3. Promiscuous mode can be activated.
//
// Does NOT require the interface to have an IP address (SPAN monitoring
// interfaces are typically unconfigured at Layer 3).
[[nodiscard]] SpanValidationResult validate_span_interface(
    const std::string& interface_name) noexcept;

// Zero-traffic diagnostic message displayed when a SPAN interface has been
// running for `seconds_elapsed` seconds without receiving a single packet.
// Returns a multi-line string suitable for console or log output.
[[nodiscard]] std::string zero_traffic_diagnostic(
    const std::string& interface_name,
    double seconds_elapsed) noexcept;

// Concise one-line warning for the statistics/heartbeat JSON blob.
[[nodiscard]] std::string zero_traffic_warning_short(
    const std::string& interface_name) noexcept;

}  // namespace delta_nids::capture
