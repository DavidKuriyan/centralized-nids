#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "alert/alert.h"

namespace delta_nids::incident {

enum class IncidentStatus { open, acknowledged, resolved };

struct Incident {
    std::uint64_t id = 0;
    std::int64_t first_seen = 0;
    std::int64_t last_seen = 0;
    IncidentStatus status = IncidentStatus::open;
    alert::Severity severity = alert::Severity::medium;
    int confidence = 0;
    int risk = 0;
    std::string category;
    std::set<std::uint64_t> alert_ids;
    std::set<std::string> source_entities;
    std::set<std::string> destination_entities;
    std::uint64_t event_count = 0;
    std::string explanation;
};

struct IncidentConfig {
    std::int64_t correlation_window_seconds = 300;
    std::size_t maximum_incidents = 10000;
};

[[nodiscard]] const char* status_name(IncidentStatus status) noexcept;

}  // namespace delta_nids::incident
