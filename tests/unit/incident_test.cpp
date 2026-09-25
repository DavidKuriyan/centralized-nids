#include <cassert>

#include "incident/incident_manager.h"

namespace {
delta_nids::alert::Alert make_alert(std::uint64_t id, std::int64_t timestamp,
                                     const char* source, const char* destination,
                                     const char* service) {
    delta_nids::alert::Alert alert;
    alert.id = id;
    alert.first_seen = timestamp;
    alert.last_seen = timestamp;
    alert.occurrence_count = 1;
    alert.source_ip = source;
    alert.destination_ip = destination;
    alert.service = service;
    alert.detection_type = delta_nids::detection::DetectionType::signature;
    alert.severity = delta_nids::alert::Severity::high;
    alert.confidence = 80;
    alert.risk = 75;
    return alert;
}
}

int main() {
    using namespace delta_nids::incident;
    IncidentManager manager({30, 10});
    auto first = manager.ingest(make_alert(1, 100, "192.0.2.1", "198.51.100.1", "SSH"));
    auto second = manager.ingest(make_alert(2, 110, "192.0.2.1", "198.51.100.1", "SSH"));
    assert(first.id == second.id);
    assert(manager.incidents().size() == 1);
    assert(second.event_count == 2);
    assert(second.alert_ids.size() == 2);

    auto separate = manager.ingest(make_alert(3, 110, "192.0.2.2", "198.51.100.1", "SSH"));
    assert(separate.id != second.id);
    assert(manager.incidents().size() == 2);

    manager.acknowledge(first.id);
    assert(manager.incidents().at(first.id).status == IncidentStatus::acknowledged);
    manager.resolve(first.id);
    assert(manager.incidents().at(first.id).status == IncidentStatus::resolved);

    manager.expire(200);
    assert(manager.incidents().at(separate.id).status == IncidentStatus::resolved);
    return 0;
}
