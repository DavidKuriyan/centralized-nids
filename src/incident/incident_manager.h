#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "incident/incident.h"

namespace delta_nids::incident {

struct IncidentMetrics {
    std::uint64_t created = 0;
    std::uint64_t updated = 0;
    std::uint64_t resolved = 0;
};

class IncidentManager {
public:
    explicit IncidentManager(IncidentConfig config = {});

    [[nodiscard]] Incident& ingest(const alert::Alert& alert);
    [[nodiscard]] const std::map<std::uint64_t, Incident>& incidents() const noexcept;
    [[nodiscard]] const IncidentMetrics& metrics() const noexcept;
    void acknowledge(std::uint64_t id);
    void resolve(std::uint64_t id);
    void expire(std::int64_t now);
    void clear();

private:
    [[nodiscard]] bool related(const Incident& incident, const alert::Alert& alert) const;
    void evict_if_needed();

    IncidentConfig config_;
    std::uint64_t next_id_ = 1;
    std::map<std::uint64_t, Incident> incidents_;
    IncidentMetrics metrics_;
};

}  // namespace delta_nids::incident
