#include <cassert>

#include "alert/alert_manager.h"
#include "detection/detection_engine.h"

int main() {
    using namespace delta_nids::alert;
    delta_nids::detection::DetectionEvent event;
    event.timestamp_seconds = 100;
    event.flow_id = 9;
    event.sid = 3001;
    event.revision = 2;
    event.message = "test alert";
    event.explanation = "buffer http_uri matched";
    event.protocol = "TCP";
    event.service = "HTTP";
    event.evidence = {'x', 'y'};
    event.severity = delta_nids::detection::RuleSeverity::high;

    AlertManager manager({60, 60, 10, 100});
    auto first = manager.ingest(event, "192.0.2.1", "198.51.100.2", 40000, 80);
    assert(first.size() == 1);
    assert(first.front().occurrence_count == 1);
    assert(first.front().confidence == 90);
    assert(first.front().risk > 0);

    event.timestamp_seconds = 110;
    auto suppressed = manager.ingest(event, "192.0.2.1", "198.51.100.2", 40000, 80);
    assert(suppressed.empty());
    assert(manager.suppressed_events() == 1);
    assert(manager.alerts().begin()->second.occurrence_count == 2);

    event.timestamp_seconds = 200;
    auto repeated = manager.ingest(event, "192.0.2.1", "198.51.100.2", 40000, 80);
    assert(repeated.size() == 1);
    assert(manager.emitted_alerts() == 2);

    manager.expire(300);
    assert(manager.alerts().empty());
    return 0;
}
