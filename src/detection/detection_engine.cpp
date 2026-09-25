#include "detection/detection_engine.h"
#include "telemetry/telemetry.h"

#include <string>
#include <utility>

namespace {
const char* transport_name(delta_nids::packet::TransportProtocol protocol) noexcept {
    using delta_nids::packet::TransportProtocol;
    switch (protocol) {
        case TransportProtocol::tcp: return "TCP";
        case TransportProtocol::udp: return "UDP";
        case TransportProtocol::icmp: return "ICMP";
        case TransportProtocol::icmpv6: return "ICMPv6";
        case TransportProtocol::other: return "other";
        default: return "none";
    }
}
}

namespace delta_nids::detection {

DetectionEngine::DetectionEngine(std::vector<Rule> rules) { set_rules(std::move(rules)); }

void DetectionEngine::set_rules(std::vector<Rule> rules) {
    matcher_.set_rules(std::move(rules));
    metrics_.rules_loaded = matcher_.rules().size();
}

const std::vector<Rule>& DetectionEngine::rules() const noexcept { return matcher_.rules(); }

std::vector<DetectionEvent> DetectionEngine::detect(const MatchContext& context,
                                                    std::int64_t timestamp_seconds) const {
    std::vector<DetectionEvent> events;
    if (!context.flow || !context.buffers) return events;
    metrics_.rules_evaluated += matcher_.rules().size();
    telemetry::MetricsRegistry::global().increment("rules_evaluated", matcher_.rules().size());
    const auto matches = matcher_.match(context);
    for (const auto& match : matches) {
        if (!match.rule) continue;
        DetectionEvent event;
        event.type = DetectionType::signature;
        event.timestamp_seconds = timestamp_seconds;
        event.flow_id = context.flow->id;
        event.gid = match.rule->gid;
        event.sid = match.rule->sid;
        event.revision = match.rule->revision;
        event.message = match.rule->message;
        event.service = context.flow->service;
        event.protocol = transport_name(context.flow->key.protocol);
        event.buffer = match.rule->buffer;
        event.direction = context.direction;
        event.evidence = match.evidence;
        event.explanation = match.explanation + ": " + match.rule->message;
        event.severity = match.rule->severity;
        event.priority = match.rule->priority;
        events.push_back(std::move(event));
        ++metrics_.rules_matched;
        telemetry::MetricsRegistry::global().increment("rules_matched");
        ++metrics_.events_generated;
    }
    return events;
}

const DetectionMetrics& DetectionEngine::metrics() const noexcept { return metrics_; }

const char* detection_type_name(DetectionType type) noexcept {
    switch (type) {
        case DetectionType::signature: return "signature";
        case DetectionType::protocol_anomaly: return "protocol_anomaly";
        case DetectionType::behavioral: return "behavioral";
    }
    return "unknown";
}

}  // namespace delta_nids::detection
