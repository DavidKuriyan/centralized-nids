#include "incident/incident_manager.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace delta_nids::incident {
namespace {

int severity_value(alert::Severity severity) { return static_cast<int>(severity); }
std::string category_for(const alert::Alert& value) {
    if (value.detection_type == detection::DetectionType::behavioral) return "behavioral";
    if (value.service.empty()) return "signature";
    return value.service;
}

}  // namespace

const char* status_name(IncidentStatus status) noexcept {
    switch (status) { case IncidentStatus::open: return "OPEN"; case IncidentStatus::acknowledged: return "ACKNOWLEDGED"; case IncidentStatus::resolved: return "RESOLVED"; }
    return "OPEN";
}

IncidentManager::IncidentManager(IncidentConfig config) : config_(config) {
    if (config_.correlation_window_seconds <= 0 || config_.maximum_incidents == 0)
        throw std::invalid_argument("incident window and maximum must be positive");
}

bool IncidentManager::related(const Incident& incident, const alert::Alert& value) const {
    if (incident.status == IncidentStatus::resolved) return false;
    if (value.first_seen - incident.last_seen > config_.correlation_window_seconds) return false;
    if (incident.category != category_for(value)) return false;
    const bool source_match = incident.source_entities.count(value.source_ip) != 0;
    const bool destination_match = incident.destination_entities.count(value.destination_ip) != 0;
    const bool service_match = !value.service.empty() && incident.explanation.find(value.service) != std::string::npos;
    return source_match && (destination_match || service_match);
}

Incident& IncidentManager::ingest(const alert::Alert& alert) {
    Incident* target = nullptr;
    for (auto iterator = incidents_.rbegin(); iterator != incidents_.rend(); ++iterator) {
        if (related(iterator->second, alert)) { target = &iterator->second; break; }
    }
    if (!target) {
        evict_if_needed();
        Incident incident;
        incident.id = next_id_++;
        incident.first_seen = alert.first_seen;
        incident.last_seen = alert.last_seen;
        incident.category = category_for(alert);
        incident.severity = alert.severity;
        incident.confidence = alert.confidence;
        incident.risk = alert.risk;
        incident.explanation = "Incident grouped by source, destination/service, category, and time window";
        incident.alert_ids.insert(alert.id);
        incident.source_entities.insert(alert.source_ip);
        incident.destination_entities.insert(alert.destination_ip);
        incident.event_count = alert.occurrence_count;
        auto inserted = incidents_.emplace(incident.id, std::move(incident));
        ++metrics_.created;
        return inserted.first->second;
    }

    target->last_seen = std::max(target->last_seen, alert.last_seen);
    target->severity = severity_value(alert.severity) > severity_value(target->severity) ? alert.severity : target->severity;
    target->confidence = std::max(target->confidence, alert.confidence);
    target->risk = std::min(100, std::max(target->risk, alert.risk) + static_cast<int>(alert.occurrence_count > 1));
    target->alert_ids.insert(alert.id);
    target->source_entities.insert(alert.source_ip);
    target->destination_entities.insert(alert.destination_ip);
    target->event_count += alert.occurrence_count;
    ++metrics_.updated;
    return *target;
}

const std::map<std::uint64_t, Incident>& IncidentManager::incidents() const noexcept { return incidents_; }
const IncidentMetrics& IncidentManager::metrics() const noexcept { return metrics_; }

void IncidentManager::acknowledge(std::uint64_t id) {
    const auto iterator = incidents_.find(id);
    if (iterator != incidents_.end() && iterator->second.status == IncidentStatus::open)
        iterator->second.status = IncidentStatus::acknowledged;
}

void IncidentManager::resolve(std::uint64_t id) {
    const auto iterator = incidents_.find(id);
    if (iterator != incidents_.end() && iterator->second.status != IncidentStatus::resolved) {
        iterator->second.status = IncidentStatus::resolved;
        ++metrics_.resolved;
    }
}

void IncidentManager::expire(std::int64_t now) {
    for (auto& entry : incidents_) {
        if (entry.second.status != IncidentStatus::resolved &&
            now - entry.second.last_seen > config_.correlation_window_seconds)
            entry.second.status = IncidentStatus::resolved;
    }
}

void IncidentManager::evict_if_needed() {
    while (incidents_.size() >= config_.maximum_incidents) {
        auto oldest = incidents_.begin();
        incidents_.erase(oldest);
    }
}

void IncidentManager::clear() { incidents_.clear(); }

}  // namespace delta_nids::incident
