#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "flow/flow.h"
#include "packet/packet.h"

namespace delta_nids::behavioral {

enum class BehavioralType { port_scan, host_sweep, brute_force, connection_flood, dns_anomaly, tcp_anomaly };

struct BehavioralEvent {
    BehavioralType type;
    std::int64_t timestamp_seconds;
    std::uint64_t flow_id;
    std::string source_ip;
    std::string destination_ip;
    std::string protocol;
    std::string message;
    std::string explanation;
    int confidence = 0;
};

struct BehavioralConfig {
    std::int64_t window_seconds = 60;
    std::size_t maximum_sources = 10000;
    std::size_t maximum_destinations_per_source = 4096;
    std::size_t port_scan_threshold = 20;
    std::size_t host_sweep_threshold = 20;
    std::size_t brute_force_threshold = 10;
    std::size_t connection_flood_threshold = 100;
    std::size_t dns_query_threshold = 100;
};

class BehavioralDetector {
public:
    virtual ~BehavioralDetector() = default;
    virtual void observe(const packet::Packet& packet, const flow::Flow& flow,
                         std::vector<BehavioralEvent>& events) = 0;
    virtual void expire(std::int64_t now) = 0;
    virtual void reset() = 0;
};

[[nodiscard]] const char* behavioral_type_name(BehavioralType type) noexcept;

}  // namespace delta_nids::behavioral
