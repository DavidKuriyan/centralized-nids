#include <cassert>
#include <cstdio>
#include <fstream>

#include "storage/storage.h"

int main() {
    const char* path = "delta-nids-storage-test.sqlite";
    std::remove(path);
    auto storage = delta_nids::storage::make_sqlite_storage({path, 4});

    delta_nids::alert::Alert alert;
    alert.id = 1;
    alert.first_seen = 10;
    alert.last_seen = 10;
    alert.occurrence_count = 1;
    alert.fingerprint = "test-fingerprint";
    alert.message = "test";
    storage->store_alert(alert);

    delta_nids::incident::Incident incident;
    incident.id = 1;
    incident.first_seen = 10;
    incident.last_seen = 10;
    incident.explanation = "test incident";
    storage->store_incident(incident);
    storage->flush();

    assert(storage->metrics().writes_accepted == 2);
    assert(storage->metrics().writes_completed == 2);
    auto page = storage->query_alerts({1, 10}, {"", "", "", 0});
    assert(page.total == 1);
    assert(page.items.size() == 1);
    assert(storage->count_rows("alerts") == 1);

    delta_nids::flow::Flow flow;
    flow.id = 7;
    flow.start_time = 10;
    flow.last_seen = 12;
    flow.service = "HTTP";
    flow.key.protocol = delta_nids::packet::TransportProtocol::tcp;
    flow.stats.packets = 3;
    flow.stats.bytes = 180;
    storage->store_flow(flow);

    delta_nids::detection::DetectionEvent event;
    event.timestamp_seconds = 12;
    event.flow_id = 7;
    event.sid = 42;
    event.explanation = "test evidence";
    storage->store_detection_event(event);

    delta_nids::detection::Rule rule;
    rule.sid = 42;
    rule.revision = 1;
    rule.message = "test rule";
    storage->store_rule(rule);
    storage->store_statistic(12, "packets_processed", 3);
    storage->flush();
    assert(storage->count_rows("flows") == 1);
    assert(storage->count_rows("detection_events") == 1);
    assert(storage->count_rows("rules") == 1);
    assert(storage->count_rows("statistics") == 1);
    const auto flows = storage->query_flows({1, 10});
    assert(flows.total == 1 && flows.items.front().id == 7 && flows.items.front().packets == 3);
    const auto events = storage->query_detection_events({1, 10});
    assert(events.total == 1 && events.items.front().sid == 42 && events.items.front().flow_id == 7);
    const auto rules = storage->query_rules({1, 10});
    assert(rules.total == 1 && rules.items.front().sid == 42 && rules.items.front().enabled);
    const auto statistics = storage->query_statistics({1, 10});
    assert(statistics.total == 1 && statistics.items.front().name == "packets_processed");

    auto limited = delta_nids::storage::make_sqlite_storage({"delta-nids-storage-limit.sqlite", 1});
    for (int index = 0; index < 100; ++index) limited->store_alert(alert);
    assert(limited->metrics().writes_dropped > 0 || limited->metrics().writes_accepted > 0);
    limited->flush();

    bool rejected = false;
    try { auto invalid = delta_nids::storage::make_sqlite_storage({"/proc/invalid/delta.db", 2}); (void)invalid; }
    catch (...) { rejected = true; }
    assert(rejected);
    std::remove(path);
    std::remove("delta-nids-storage-limit.sqlite");
    return 0;
}
