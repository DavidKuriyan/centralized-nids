#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "detection/rule_matcher.h"

namespace delta_nids::detection {

enum class DetectionType { signature, protocol_anomaly, behavioral };

struct DetectionEvent {
    DetectionType type = DetectionType::signature;
    std::int64_t timestamp_seconds = 0;
    std::uint64_t flow_id = 0;
    std::uint32_t gid = 1;
    std::uint32_t sid = 0;
    std::uint32_t revision = 0;
    std::string message;
    std::string service;
    std::string protocol;
    BufferName buffer = BufferName::payload;
    BufferDirection direction = BufferDirection::not_applicable;
    std::vector<std::uint8_t> evidence;
    std::string explanation;
    RuleSeverity severity = RuleSeverity::medium;
    std::uint32_t priority = 3;
};

struct DetectionMetrics {
    std::uint64_t rules_loaded = 0;
    std::uint64_t rules_evaluated = 0;
    std::uint64_t rules_matched = 0;
    std::uint64_t events_generated = 0;
};

class DetectionEngine {
public:
    DetectionEngine() = default;
    explicit DetectionEngine(std::vector<Rule> rules);

    void set_rules(std::vector<Rule> rules);
    [[nodiscard]] const std::vector<Rule>& rules() const noexcept;
    [[nodiscard]] std::vector<DetectionEvent> detect(const MatchContext& context,
                                                     std::int64_t timestamp_seconds) const;
    [[nodiscard]] const DetectionMetrics& metrics() const noexcept;

private:
    RuleMatcher matcher_;
    mutable DetectionMetrics metrics_;
};

[[nodiscard]] const char* detection_type_name(DetectionType type) noexcept;

}  // namespace delta_nids::detection
