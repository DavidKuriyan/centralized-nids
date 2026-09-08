#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "behavioral/behavioral_detector.h"
#include "detection/detection_engine.h"

namespace delta_nids::alert {

enum class Severity { info, low, medium, high, critical };

struct Alert {
    std::uint64_t id = 0;
    std::int64_t first_seen = 0;
    std::int64_t last_seen = 0;
    std::uint64_t occurrence_count = 0;
    std::uint64_t suppressed_count = 0;
    Severity severity = Severity::medium;
    int confidence = 0;
    int risk = 0;
    detection::DetectionType detection_type = detection::DetectionType::signature;
    std::uint32_t gid = 1;
    std::uint32_t sid = 0;
    std::uint32_t revision = 0;
    std::string source_ip;
    std::uint16_t source_port = 0;
    std::string destination_ip;
    std::uint16_t destination_port = 0;
    std::string protocol;
    std::string service;
    std::uint64_t flow_id = 0;
    std::uint64_t traffic_id = 0;
    std::string message;
    std::string evidence;
    std::string explanation;
    std::string fingerprint;

    // SPAN / capture context -----------------------------------------------
    // IP version of the triggering packet (4 or 6; 0 = unknown).
    int ip_version = 0;
    // Capture mode at the time of detection ("normal", "span", "pcap").
    std::string capture_mode;
    // Interface name on which the packet was captured.
    std::string capture_interface;
    // Outermost VLAN ID of the triggering packet (-1 = untagged / not applicable).
    int vlan_id = -1;
    // Ethernet MAC addresses (colon-separated hex, e.g. "aa:bb:cc:dd:ee:ff").
    // Empty when not available (e.g. PCAP replay without Ethernet headers).
    std::string source_mac;
    std::string destination_mac;
};

struct AlertConfig {
    std::int64_t deduplication_window_seconds = 60;
    std::int64_t suppression_window_seconds = 60;
    std::size_t maximum_alerts = 100000;
    std::size_t maximum_events_per_window = 1000;
};

[[nodiscard]] const char* severity_name(Severity severity) noexcept;
[[nodiscard]] Severity severity_from_rule(detection::RuleSeverity severity) noexcept;
[[nodiscard]] std::string fingerprint_for(const detection::DetectionEvent& event,
                                          const std::string& source_ip,
                                          const std::string& destination_ip,
                                          std::uint16_t source_port = 0,
                                          std::uint16_t destination_port = 0);

}  // namespace delta_nids::alert
