#include "alert/alert_manager.h"
#include "telemetry/telemetry.h"

#include <algorithm>
#include <functional>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <stdexcept>

namespace delta_nids::alert {

const char* severity_name(Severity severity) noexcept {
    switch (severity) { case Severity::info: return "INFO"; case Severity::low: return "LOW"; case Severity::medium: return "MEDIUM"; case Severity::high: return "HIGH"; case Severity::critical: return "CRITICAL"; }
    return "MEDIUM";
}

Severity severity_from_rule(detection::RuleSeverity severity) noexcept {
    switch (severity) { case detection::RuleSeverity::info: return Severity::info; case detection::RuleSeverity::low: return Severity::low; case detection::RuleSeverity::medium: return Severity::medium; case detection::RuleSeverity::high: return Severity::high; case detection::RuleSeverity::critical: return Severity::critical; }
    return Severity::medium;
}

std::string fingerprint_for(const detection::DetectionEvent& event,
                            const std::string& source_ip,
                            const std::string& destination_ip,
                            std::uint16_t source_port,
                            std::uint16_t destination_port) {
    std::ostringstream value;
    value << static_cast<int>(event.type) << '|' << event.gid << '|' << event.sid << '|'
          << event.revision << '|' << source_ip << '|' << source_port << '|'
          << destination_ip << '|' << destination_port << '|' << event.flow_id << '|'
          << event.service << '|' << event.protocol << '|' << static_cast<int>(event.buffer)
          << '|' << event.explanation << '|'
          << std::string(event.evidence.begin(), event.evidence.end());
    return std::to_string(std::hash<std::string>{}(value.str()));
}

AlertManager::AlertManager(AlertConfig config) : config_(config) {
    if (config_.deduplication_window_seconds <= 0 || config_.suppression_window_seconds <= 0 ||
        config_.maximum_alerts == 0 || config_.maximum_events_per_window == 0)
        throw std::invalid_argument("alert limits and windows must be positive");
}

static std::string alert_timestamp(std::int64_t seconds) {
    const auto instant = std::chrono::system_clock::from_time_t(static_cast<std::time_t>(seconds));
    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(instant.time_since_epoch()).count() % 1000000;
    const auto wall = std::chrono::system_clock::to_time_t(instant);
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &wall);
#else
    localtime_r(&wall, &local);
#endif
    std::ostringstream output;
    output << std::put_time(&local, "%m/%d-%H:%M:%S") << '.' << std::setw(6) << std::setfill('0') << micros;
    return output.str();
}

static std::string format_alert(const Alert& value) {
    std::ostringstream output;
    output << alert_timestamp(value.last_seen) << "  [*] [" << value.gid << ':' << value.sid << ':' << value.revision
           << "] " << value.message << " [*]\\n[Priority: " << (value.risk > 0 ? std::max(1, 5 - value.risk / 25) : 3)
           << "] {" << value.protocol << "} " << value.source_ip;
    if (value.source_port) output << ':' << value.source_port;
    output << " -> " << value.destination_ip;
    if (value.destination_port) output << ':' << value.destination_port;
    return output.str();
}

Alert AlertManager::make_alert(const detection::DetectionEvent& event,
                               const std::string& source_ip,
                               const std::string& destination_ip,
                               std::uint16_t source_port,
                               std::uint16_t destination_port,
                               const std::string& fingerprint) const {
    Alert alert;
    alert.first_seen = event.timestamp_seconds;
    alert.last_seen = event.timestamp_seconds;
    alert.occurrence_count = 1;
    alert.severity = severity_from_rule(event.severity);
    alert.confidence = event.type == detection::DetectionType::signature ? 90 : 70;
    alert.risk = std::min(100, static_cast<int>(alert.severity) * 20 + alert.confidence / 2);
    alert.detection_type = event.type;
    alert.gid = event.gid;
    alert.sid = event.sid;
    alert.revision = event.revision;
    alert.source_ip = source_ip;
    alert.source_port = source_port;
    alert.destination_ip = destination_ip;
    alert.destination_port = destination_port;
    alert.protocol = event.protocol;
    alert.service = event.service;
    alert.flow_id = event.flow_id;
    alert.message = event.message;
    alert.evidence.assign(event.evidence.begin(), event.evidence.end());
    alert.explanation = event.explanation;
    alert.fingerprint = fingerprint;
    return alert;
}

std::vector<Alert> AlertManager::ingest(const detection::DetectionEvent& event,
                                        const std::string& source_ip,
                                        const std::string& destination_ip,
                                        std::uint16_t source_port,
                                        std::uint16_t destination_port) {
    std::vector<Alert> emitted;
    const auto fingerprint = fingerprint_for(event, source_ip, destination_ip,
                                             source_port, destination_port);
    auto iterator = alerts_.find(fingerprint);
    if (iterator != alerts_.end()) {
        auto& alert = iterator->second;
        ++alert.occurrence_count;
        alert.last_seen = event.timestamp_seconds;
        if (event.timestamp_seconds - alert.first_seen <= config_.suppression_window_seconds) {
            ++alert.suppressed_count;
            ++suppressed_events_;
    telemetry::MetricsRegistry::global().increment("alerts_suppressed");
            return emitted;
        }
        alert.first_seen = event.timestamp_seconds;
        alert.suppressed_count = 0;
        emitted.push_back(alert);
        ++emitted_alerts_;
    telemetry::MetricsRegistry::global().increment("alerts_generated");
        return emitted;
    }
    if (alerts_.size() >= config_.maximum_alerts) {
        auto oldest = std::min_element(alerts_.begin(), alerts_.end(), [](const auto& left, const auto& right) {
            return left.second.last_seen < right.second.last_seen;
        });
        alerts_.erase(oldest);
    }
    auto alert = make_alert(event, source_ip, destination_ip, source_port, destination_port, fingerprint);
    alert.id = next_id_++;
    const auto inserted = alerts_.emplace(fingerprint, std::move(alert));
    emitted.push_back(inserted.first->second);
    ++emitted_alerts_;
    (void)format_alert(inserted.first->second);
    telemetry::MetricsRegistry::global().increment("alerts_generated");
    return emitted;
}

const std::map<std::string, Alert>& AlertManager::alerts() const noexcept { return alerts_; }
std::uint64_t AlertManager::suppressed_events() const noexcept { return suppressed_events_; }
std::uint64_t AlertManager::emitted_alerts() const noexcept { return emitted_alerts_; }

void AlertManager::expire(std::int64_t now) {
    for (auto iterator = alerts_.begin(); iterator != alerts_.end();) {
        if (now - iterator->second.last_seen > config_.deduplication_window_seconds)
            iterator = alerts_.erase(iterator);
        else ++iterator;
    }
}

void AlertManager::clear() { alerts_.clear(); }

}  // namespace delta_nids::alert
