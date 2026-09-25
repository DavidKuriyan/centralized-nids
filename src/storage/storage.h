#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "alert/alert.h"
#include "flow/flow.h"
#include "incident/incident.h"
#include "detection/detection_engine.h"
#include "detection/rule.h"

namespace delta_nids::storage {

struct StorageConfig {
    std::string database_path;
    std::size_t maximum_pending_writes = 4096;
};

struct StorageMetrics {
    std::uint64_t writes_accepted = 0;
    std::uint64_t writes_completed = 0;
    std::uint64_t writes_dropped = 0;
    std::uint64_t errors = 0;
};

struct PageRequest {
    std::size_t page = 1;
    std::size_t page_size = 50;
};struct AlertFilter { std::string severity; std::string source_ip; std::string destination_ip; std::uint32_t sid = 0; std::string message; std::string protocol; std::string search; std::int64_t since = 0; std::int64_t until = 0; };
struct IncidentFilter { std::string status; std::string category; std::string search; };
struct TrafficFilter {
    std::string search;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    std::int64_t since = 0;
    std::int64_t until = 0;
};
struct RuleFilter { std::string search; };
struct AlertPage { std::vector<alert::Alert> items; std::size_t total = 0; };
struct IncidentPage { std::vector<incident::Incident> items; std::size_t total = 0; };
struct TrafficRecord {
    std::uint64_t id = 0;
    std::int64_t timestamp = 0;
    std::string src_ip;
    int src_port = 0;
    std::string dst_ip;
    int dst_port = 0;
    std::string protocol;
    std::uint64_t length = 0;
    std::string payload_summary;
    std::string details;
};
struct TrafficPage { std::vector<TrafficRecord> items; std::size_t total = 0; };
struct FlowRecord { std::uint64_t id = 0; std::int64_t start_time = 0; std::int64_t last_seen = 0; std::string service; std::string protocol; std::uint64_t packets = 0; std::uint64_t bytes = 0; };
struct DetectionEventRecord { std::int64_t timestamp = 0; std::uint64_t flow_id = 0; std::uint32_t sid = 0; std::string event_type; std::string explanation; std::string evidence; };
struct RuleRecord { std::uint32_t gid = 1; std::uint32_t sid = 0; std::uint32_t revision = 0; std::string message; std::uint32_t priority = 3; std::string protocol; bool enabled = false; std::string source_file; };
struct StatisticRecord { std::int64_t timestamp = 0; std::string name; std::int64_t value = 0; std::string text_value; };
struct FlowPage { std::vector<FlowRecord> items; std::size_t total = 0; };
struct DetectionEventPage { std::vector<DetectionEventRecord> items; std::size_t total = 0; };
struct RulePage { std::vector<RuleRecord> items; std::size_t total = 0; };
struct StatisticPage { std::vector<StatisticRecord> items; std::size_t total = 0; };

class Storage {
public:
    virtual ~Storage() = default;
    virtual void store_alert(const alert::Alert& value) = 0;
    virtual void store_incident(const incident::Incident& value) = 0;
    virtual void store_flow(const flow::Flow& value) = 0;
    virtual void store_detection_event(const detection::DetectionEvent& value) = 0;
    virtual void store_rule(const detection::Rule& value) = 0;
    virtual void store_statistic(std::int64_t timestamp, const std::string& name, std::int64_t value) = 0;
    virtual void store_traffic(const TrafficRecord& value) = 0;
    [[nodiscard]] virtual AlertPage query_alerts(PageRequest request, const AlertFilter& filter = {}) const = 0;
    [[nodiscard]] virtual bool get_alert(std::uint64_t id, alert::Alert& value) const = 0;
    [[nodiscard]] virtual bool get_incident(std::uint64_t id, incident::Incident& value) const = 0;
    [[nodiscard]] virtual AlertPage query_incident_alerts(std::uint64_t incident_id, PageRequest request = {}) const = 0;
    [[nodiscard]] virtual IncidentPage query_incidents(PageRequest request, const IncidentFilter& filter = {}) const = 0;
    [[nodiscard]] virtual TrafficPage query_traffic(PageRequest request, const TrafficFilter& filter = {}) const = 0;
    [[nodiscard]] virtual bool get_traffic(std::uint64_t id, TrafficRecord& value) const = 0;
    [[nodiscard]] virtual std::size_t clear_alerts() = 0;
    [[nodiscard]] virtual std::size_t clear_traffic() = 0;
    [[nodiscard]] virtual std::size_t clear_incidents() = 0;
    [[nodiscard]] virtual std::size_t clear_flows() = 0;
    [[nodiscard]]    virtual std::size_t clear_statistics() = 0;
    [[nodiscard]] virtual TrafficPage query_traffic_export(const TrafficFilter& filter = {}) const = 0;
    [[nodiscard]] virtual FlowPage query_flows(PageRequest request = {}) const = 0;
    [[nodiscard]] virtual DetectionEventPage query_detection_events(PageRequest request = {}) const = 0;
    [[nodiscard]] virtual RulePage query_rules(PageRequest request = {}, const RuleFilter& filter = {}) const = 0;
    [[nodiscard]] virtual StatisticPage query_statistics(PageRequest request = {}) const = 0;
    [[nodiscard]] virtual std::size_t count_rows(const std::string& table) const = 0;
    virtual void flush() = 0;
    [[nodiscard]] virtual const StorageMetrics& metrics() const noexcept = 0;
};

[[nodiscard]] std::unique_ptr<Storage> make_sqlite_storage(const StorageConfig& config);

}  // namespace delta_nids::storage
