#include "storage/storage.h"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <condition_variable>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <cstdint>
#include <string>
#include <thread>
#include <utility>

namespace delta_nids::storage {
namespace {

// Builds a parameterized WHERE clause. Every user-supplied value is bound through
// sqlite3_bind_*; no user input is ever concatenated into the SQL text. LIKE
// patterns escape the value so '%', '_' and '\\' match literally.
class FilterBuilder {
public:
    void clause(const std::string& sql) { if (!clauses_.empty()) clauses_ += " AND "; clauses_ += "(" + sql + ")"; }
    void clause(const std::string& sql, std::function<void(sqlite3_stmt*, int)> binder, int params = 1) {
        clause(sql);
        binders_.push_back({std::move(binder), param_count_ + 1});
        param_count_ += params;
    }
    void contains(const std::string& column, const std::string& value) {
        const std::string pattern = contains_pattern(value);
        clause("LOWER(" + column + ") LIKE LOWER(?) ESCAPE '\\'", [pattern](sqlite3_stmt* s, int index) { sqlite3_bind_text(s, index, pattern.c_str(), -1, SQLITE_TRANSIENT); });
    }
    void equals_text(const std::string& column, const std::string& value) {
        clause("LOWER(" + column + ") = LOWER(?)", [value](sqlite3_stmt* s, int index) { sqlite3_bind_text(s, index, value.c_str(), -1, SQLITE_TRANSIENT); });
    }
    void equals_int(const std::string& column, std::int64_t value) {
        clause(column + " = ?", [value](sqlite3_stmt* s, int index) { sqlite3_bind_int64(s, index, value); });
    }
    void at_least(const std::string& column, std::int64_t value) {
        clause(column + " >= ?", [value](sqlite3_stmt* s, int index) { sqlite3_bind_int64(s, index, value); });
    }
    void at_most(const std::string& column, std::int64_t value) {
        clause(column + " <= ?", [value](sqlite3_stmt* s, int index) { sqlite3_bind_int64(s, index, value); });
    }
    [[nodiscard]] const std::string& sql() const noexcept { return clauses_; }
    [[nodiscard]] int binder_count() const noexcept { return param_count_; }
    void bind(sqlite3_stmt* statement) const { for (const auto& b : binders_) b.fn(statement, b.start_index); }
    static std::string contains_pattern(const std::string& value) { return "%" + escape_like(value) + "%"; }
    static std::string escape_like(const std::string& value) {
        std::string escaped;
        escaped.reserve(value.size() * 2);
        for (const char character : value) {
            if (character == '\\' || character == '%' || character == '_') escaped += '\\';
            escaped += character;
        }
        return escaped;
    }

private:
    struct BoundBinder {
        std::function<void(sqlite3_stmt*, int)> fn;
        int start_index;
    };
    std::string clauses_ = "1=1";
    std::vector<BoundBinder> binders_;
    int param_count_ = 0;
};

bool is_numeric(const std::string& value) { return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char character) { return std::isdigit(character) != 0; }); }

FilterBuilder alert_filter_builder(const AlertFilter& filter) {
    FilterBuilder builder;
    if (!filter.severity.empty()) builder.equals_text("severity", filter.severity);
    if (!filter.source_ip.empty()) builder.equals_text("source_ip", filter.source_ip);
    if (!filter.destination_ip.empty()) builder.equals_text("destination_ip", filter.destination_ip);
    if (filter.sid != 0) builder.equals_int("sid", filter.sid);
    if (!filter.message.empty()) builder.contains("message", filter.message);
    if (!filter.protocol.empty()) builder.contains("protocol", filter.protocol);
    if (filter.since > 0) builder.at_least("last_seen", filter.since);
    if (filter.until > 0) builder.at_most("last_seen", filter.until);
    if (!filter.search.empty()) {
        const std::string pattern = FilterBuilder::contains_pattern(filter.search);
        const auto bind_pattern = [pattern](sqlite3_stmt* s, int index) { sqlite3_bind_text(s, index, pattern.c_str(), -1, SQLITE_TRANSIENT); };
        if (is_numeric(filter.search) && filter.search.size() <= 18) {
            const std::int64_t number = std::stoll(filter.search);
            builder.clause("(LOWER(message) LIKE LOWER(?) ESCAPE '\\' OR LOWER(source_ip) LIKE LOWER(?) ESCAPE '\\' OR LOWER(destination_ip) LIKE LOWER(?) ESCAPE '\\' OR LOWER(protocol) LIKE LOWER(?) ESCAPE '\\' OR LOWER(severity) LIKE LOWER(?) ESCAPE '\\' OR sid = ?)",
                           [bind_pattern, number](sqlite3_stmt* s, int index) { for (int offset = 0; offset < 5; ++offset) bind_pattern(s, index + offset); sqlite3_bind_int64(s, index + 5, number); }, 6);
        } else {
            builder.clause("(LOWER(message) LIKE LOWER(?) ESCAPE '\\' OR LOWER(source_ip) LIKE LOWER(?) ESCAPE '\\' OR LOWER(destination_ip) LIKE LOWER(?) ESCAPE '\\' OR LOWER(protocol) LIKE LOWER(?) ESCAPE '\\' OR LOWER(severity) LIKE LOWER(?) ESCAPE '\\')",
                           [bind_pattern](sqlite3_stmt* s, int index) { for (int offset = 0; offset < 5; ++offset) bind_pattern(s, index + offset); }, 5);
        }
    }
    return builder;
}

FilterBuilder traffic_filter_builder(const TrafficFilter& filter) {
    FilterBuilder builder;
    if (!filter.src_ip.empty()) builder.contains("src_ip", filter.src_ip);
    if (!filter.dst_ip.empty()) builder.contains("dst_ip", filter.dst_ip);
    if (!filter.protocol.empty()) builder.contains("protocol", filter.protocol);
    if (filter.since > 0) builder.at_least("timestamp", filter.since);
    if (filter.until > 0) builder.at_most("timestamp", filter.until);
    if (!filter.search.empty()) {
        const std::string pattern = FilterBuilder::contains_pattern(filter.search);
        const auto bind_pattern = [pattern](sqlite3_stmt* s, int index) { sqlite3_bind_text(s, index, pattern.c_str(), -1, SQLITE_TRANSIENT); };
        if (is_numeric(filter.search) && filter.search.size() <= 18) {
            const std::int64_t number = std::stoll(filter.search);
            builder.clause("(LOWER(src_ip) LIKE LOWER(?) ESCAPE '\\' OR LOWER(dst_ip) LIKE LOWER(?) ESCAPE '\\' OR LOWER(protocol) LIKE LOWER(?) ESCAPE '\\' OR src_port = ? OR dst_port = ? OR length = ?)",
                           [bind_pattern, number](sqlite3_stmt* s, int index) { for (int offset = 0; offset < 3; ++offset) bind_pattern(s, index + offset); sqlite3_bind_int64(s, index + 3, number); sqlite3_bind_int64(s, index + 4, number); sqlite3_bind_int64(s, index + 5, number); }, 6);
        } else {
            builder.clause("(LOWER(src_ip) LIKE LOWER(?) ESCAPE '\\' OR LOWER(dst_ip) LIKE LOWER(?) ESCAPE '\\' OR LOWER(protocol) LIKE LOWER(?) ESCAPE '\\')",
                           [bind_pattern](sqlite3_stmt* s, int index) { for (int offset = 0; offset < 3; ++offset) bind_pattern(s, index + offset); }, 3);
        }
    }
    return builder;
}

struct Write {
    enum class Type { alert, incident, flow, event, rule, statistic, traffic } type;
    alert::Alert alert;
    incident::Incident incident;
    struct FlowSummary { std::uint64_t id = 0; std::int64_t start_time = 0; std::int64_t last_seen = 0; std::string service; std::string protocol; std::uint64_t packets = 0; std::uint64_t bytes = 0; } flow;
    detection::DetectionEvent event;
    detection::Rule rule;
    TrafficRecord traffic;
    std::int64_t timestamp = 0;
    std::string name;
    std::int64_t value = 0;
};

class SqliteStorage final : public Storage {
public:
    explicit SqliteStorage(StorageConfig config) : config_(std::move(config)) {
        if (config_.database_path.empty() || config_.maximum_pending_writes == 0)
            throw std::invalid_argument("database path and pending-write limit are required");
        const auto database = std::filesystem::path(config_.database_path);
        const auto parent = database.parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent);
        if (std::filesystem::exists(database)) {
            std::error_code permissions_error;
            const auto permissions = std::filesystem::status(database, permissions_error).permissions();
            if (permissions_error || (permissions & std::filesystem::perms::owner_write) == std::filesystem::perms::none) {
                throw std::runtime_error("database is not writable: " + config_.database_path + " (check file ownership/permissions)");
            }
        } else if (!parent.empty()) {
            std::error_code permissions_error;
            const auto permissions = std::filesystem::status(parent, permissions_error).permissions();
            if (permissions_error || (permissions & std::filesystem::perms::owner_write) == std::filesystem::perms::none) {
                throw std::runtime_error("database directory is not writable: " + parent.string() + " (check directory ownership/permissions)");
            }
        }
        if (sqlite3_open(config_.database_path.c_str(), &database_) != SQLITE_OK) {
            const std::string message = database_ ? sqlite3_errmsg(database_) : "unable to open database";
            close_database();
            throw std::runtime_error(message);
        }
        // Coexist with the Python capture process writing the same database.
        sqlite3_busy_timeout(database_, 5000);
        initialize_schema();
        worker_ = std::thread(&SqliteStorage::worker_loop, this);
    }

    ~SqliteStorage() override {
        flush();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        condition_.notify_all();
        if (worker_.joinable()) worker_.join();
        close_database();
    }

    void store_alert(const alert::Alert& value) override { Write write{}; write.type=Write::Type::alert; write.alert=value; enqueue(std::move(write)); }
    void store_incident(const incident::Incident& value) override { Write write{}; write.type=Write::Type::incident; write.incident = value; enqueue(std::move(write)); }
    void store_flow(const flow::Flow& value) override { Write write{}; write.type=Write::Type::flow; write.flow.id=value.id; write.flow.start_time=value.start_time; write.flow.last_seen=value.last_seen; write.flow.service=value.service; write.flow.protocol=transport_name(value.key.protocol); write.flow.packets=value.stats.packets; write.flow.bytes=value.stats.bytes; enqueue(std::move(write)); }
    void store_detection_event(const detection::DetectionEvent& value) override { Write write{}; write.type=Write::Type::event; write.event = value; enqueue(std::move(write)); }
    void store_rule(const detection::Rule& value) override { Write write{}; write.type=Write::Type::rule; write.rule = value; enqueue(std::move(write)); }
    void store_statistic(std::int64_t timestamp, const std::string& name, std::int64_t value) override { Write write{}; write.type = Write::Type::statistic; write.timestamp = timestamp; write.name = name; write.value = value; enqueue(std::move(write)); }
    void store_traffic(const TrafficRecord& value) override { Write write{}; write.type = Write::Type::traffic; write.traffic = value; enqueue(std::move(write)); }

    AlertPage query_alerts(PageRequest request, const AlertFilter& filter) const override {
        normalize(request);
        std::lock_guard<std::mutex> lock(mutex_);
        const FilterBuilder builder = alert_filter_builder(filter);
        AlertPage page;
        page.total = count_where("alerts", builder);
        const auto offset = (request.page - 1) * request.page_size;
        const std::string sql = "SELECT id, first_seen, last_seen, occurrence_count, suppressed_count, severity, confidence, risk, detection_type, sid, revision, source_ip, source_port, destination_ip, destination_port, protocol, service, flow_id, traffic_id, message, evidence, explanation, fingerprint FROM alerts WHERE " + builder.sql() + " ORDER BY last_seen DESC LIMIT ? OFFSET ?;";
        sqlite3_stmt* statement = prepare(sql.c_str());
        if (!statement) return page;
        builder.bind(statement);
        sqlite3_bind_int64(statement, builder.binder_count() + 1, static_cast<sqlite3_int64>(request.page_size));
        sqlite3_bind_int64(statement, builder.binder_count() + 2, static_cast<sqlite3_int64>(offset));
        while (sqlite3_step(statement) == SQLITE_ROW) page.items.push_back(read_alert(statement));
        sqlite3_finalize(statement);
        return page;
    }

    IncidentPage query_incidents(PageRequest request, const IncidentFilter& filter) const override {
        normalize(request);
        std::lock_guard<std::mutex> lock(mutex_);
        IncidentPage page;
        FilterBuilder builder;
        if (!filter.status.empty()) builder.equals_text("status", filter.status);
        if (!filter.category.empty()) builder.equals_text("category", filter.category);
        if (!filter.search.empty()) {
            const std::string pattern = FilterBuilder::contains_pattern(filter.search);
            builder.clause("(LOWER(category) LIKE LOWER(?) ESCAPE '\\' OR LOWER(status) LIKE LOWER(?) ESCAPE '\\' OR LOWER(explanation) LIKE LOWER(?) ESCAPE '\\')",
                           [pattern](sqlite3_stmt* s, int index) { for (int offset = 0; offset < 3; ++offset) sqlite3_bind_text(s, index + offset, pattern.c_str(), -1, SQLITE_TRANSIENT); }, 3);
        }
        page.total = count_where("incidents", builder);
        const auto offset = (request.page - 1) * request.page_size;
        const std::string sql = "SELECT id, first_seen, last_seen, status, severity, confidence, risk, category, event_count, explanation FROM incidents WHERE " + builder.sql() + " ORDER BY last_seen DESC LIMIT ? OFFSET ?;";
        sqlite3_stmt* statement = prepare(sql.c_str());
        if (!statement) return page;
        builder.bind(statement);
        sqlite3_bind_int64(statement, builder.binder_count() + 1, static_cast<sqlite3_int64>(request.page_size));
        sqlite3_bind_int64(statement, builder.binder_count() + 2, static_cast<sqlite3_int64>(offset));
        while (sqlite3_step(statement) == SQLITE_ROW) page.items.push_back(read_incident(statement));
        sqlite3_finalize(statement);
        return page;
    }

    bool get_alert(std::uint64_t id, alert::Alert& value) const override { std::lock_guard<std::mutex> lock(mutex_); auto* s=prepare("SELECT id, first_seen, last_seen, occurrence_count, suppressed_count, severity, confidence, risk, detection_type, sid, revision, source_ip, source_port, destination_ip, destination_port, protocol, service, flow_id, traffic_id, message, evidence, explanation, fingerprint FROM alerts WHERE id=?;"); if(!s) return false; sqlite3_bind_int64(s,1,static_cast<sqlite3_int64>(id)); const bool found=sqlite3_step(s)==SQLITE_ROW; if(found) value=read_alert(s); sqlite3_finalize(s); return found; }
    bool get_incident(std::uint64_t id, incident::Incident& value) const override { std::lock_guard<std::mutex> lock(mutex_); auto* s=prepare("SELECT id, first_seen, last_seen, status, severity, confidence, risk, category, event_count, explanation FROM incidents WHERE id=?;"); if(!s) return false; sqlite3_bind_int64(s,1,static_cast<sqlite3_int64>(id)); const bool found=sqlite3_step(s)==SQLITE_ROW; if(found) value=read_incident(s); sqlite3_finalize(s); return found; }
    AlertPage query_incident_alerts(std::uint64_t incident_id, PageRequest request) const override {
        normalize(request);
        std::lock_guard<std::mutex> lock(mutex_);
        AlertPage page;
        sqlite3_stmt* count = prepare("SELECT COUNT(*) FROM incident_alerts ia JOIN alerts a ON a.id=ia.alert_id WHERE ia.incident_id=?;");
        if (count) { sqlite3_bind_int64(count, 1, static_cast<sqlite3_int64>(incident_id)); if (sqlite3_step(count) == SQLITE_ROW) page.total = static_cast<std::size_t>(sqlite3_column_int64(count, 0)); sqlite3_finalize(count); }
        sqlite3_stmt* statement = prepare("SELECT a.id, a.first_seen, a.last_seen, a.occurrence_count, a.suppressed_count, a.severity, a.confidence, a.risk, a.detection_type, a.sid, a.revision, a.source_ip, a.source_port, a.destination_ip, a.destination_port, a.protocol, a.service, a.flow_id, a.traffic_id, a.message, a.evidence, a.explanation, a.fingerprint FROM incident_alerts ia JOIN alerts a ON a.id=ia.alert_id WHERE ia.incident_id=? ORDER BY a.last_seen DESC LIMIT ? OFFSET ?;");
        if (!statement) return page;
        sqlite3_bind_int64(statement, 1, static_cast<sqlite3_int64>(incident_id));
        sqlite3_bind_int64(statement, 2, static_cast<sqlite3_int64>(request.page_size));
        sqlite3_bind_int64(statement, 3, static_cast<sqlite3_int64>((request.page - 1) * request.page_size));
        while (sqlite3_step(statement) == SQLITE_ROW) page.items.push_back(read_alert(statement));
        sqlite3_finalize(statement);
        return page;
    }
    TrafficPage query_traffic_export(const TrafficFilter& filter) const override {
        return query_traffic({1, 500}, filter);
    }

    TrafficPage query_traffic(PageRequest request, const TrafficFilter& filter) const override {
        normalize(request);
        std::lock_guard<std::mutex> lock(mutex_);
        const FilterBuilder builder = traffic_filter_builder(filter);
        TrafficPage page;
        {
            sqlite3_stmt* statement = prepare(("SELECT COUNT(*) FROM traffic_logs WHERE " + builder.sql() + ";").c_str());
            if (statement) {
                builder.bind(statement);
                if (sqlite3_step(statement) == SQLITE_ROW) page.total = static_cast<std::size_t>(sqlite3_column_int64(statement, 0));
                sqlite3_finalize(statement);
            }
        }
        const auto offset = (request.page - 1) * request.page_size;
        sqlite3_stmt* statement = prepare(("SELECT id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, length, payload_summary, details FROM traffic_logs WHERE " + builder.sql() + " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?;").c_str());
        if (!statement) return page;
        builder.bind(statement);
        sqlite3_bind_int64(statement, builder.binder_count() + 1, static_cast<sqlite3_int64>(request.page_size));
        sqlite3_bind_int64(statement, builder.binder_count() + 2, static_cast<sqlite3_int64>(offset));
        while (sqlite3_step(statement) == SQLITE_ROW) page.items.push_back(read_traffic(statement));
        sqlite3_finalize(statement);
        return page;
    }
    bool get_traffic(std::uint64_t id, TrafficRecord& value) const override { std::lock_guard<std::mutex> lock(mutex_); auto* s=prepare("SELECT id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, length, payload_summary, details FROM traffic_logs WHERE id=?;"); if(!s) return false; sqlite3_bind_int64(s,1,static_cast<sqlite3_int64>(id)); const bool found=sqlite3_step(s)==SQLITE_ROW; if(found) value=read_traffic(s); sqlite3_finalize(s); return found; }
    std::size_t clear_alerts() override { std::size_t deleted = 0; clear_table("DELETE FROM alerts;", deleted); return deleted; }
    std::size_t clear_traffic() override { std::size_t deleted = 0; clear_table("DELETE FROM traffic_logs;", deleted); return deleted; }
    std::size_t clear_incidents() override { std::size_t deleted = 0; clear_table("DELETE FROM incident_alerts;", deleted); std::size_t incidents = 0; clear_table("DELETE FROM incidents;", incidents); return incidents; }
    std::size_t clear_flows() override { std::size_t deleted = 0; clear_table("DELETE FROM flows;", deleted); return deleted; }
    std::size_t clear_statistics() override { std::size_t deleted = 0; clear_table("DELETE FROM statistics;", deleted); return deleted; }
    FlowPage query_flows(PageRequest request) const override { return query_simple_flows(request); }
    DetectionEventPage query_detection_events(PageRequest request) const override { return query_simple_events(request); }
    RulePage query_rules(PageRequest request, const RuleFilter& filter) const override { return query_simple_rules(request, filter); }
    StatisticPage query_statistics(PageRequest request) const override { return query_simple_statistics(request); }

    void flush() override {
        std::unique_lock<std::mutex> lock(mutex_);
        drained_.wait(lock, [this] { return writes_.empty() && !processing_; });
    }
    [[nodiscard]] const StorageMetrics& metrics() const noexcept override { return metrics_; }

private:
    static void normalize(PageRequest& request) { request.page = request.page == 0 ? 1 : request.page; request.page_size = request.page_size == 0 ? 1 : std::min<std::size_t>(request.page_size, 500); }
    FlowPage query_simple_flows(PageRequest request) const { normalize(request); std::lock_guard<std::mutex> lock(mutex_); FlowPage page; page.total=scalar_count("flows"); sqlite3_stmt* s=prepare("SELECT id,start_time,last_seen,service,protocol,packets,bytes FROM flows ORDER BY last_seen DESC LIMIT ? OFFSET ?;"); if(!s) return page; sqlite3_bind_int64(s,1,request.page_size); sqlite3_bind_int64(s,2,(request.page-1)*request.page_size); while(sqlite3_step(s)==SQLITE_ROW){ FlowRecord v; v.id=sqlite3_column_int64(s,0); v.start_time=sqlite3_column_int64(s,1); v.last_seen=sqlite3_column_int64(s,2); v.service=reada(s,3); v.protocol=reada(s,4); v.packets=sqlite3_column_int64(s,5); v.bytes=sqlite3_column_int64(s,6); page.items.push_back(std::move(v)); } sqlite3_finalize(s); return page; }
    DetectionEventPage query_simple_events(PageRequest request) const { normalize(request); std::lock_guard<std::mutex> lock(mutex_); DetectionEventPage page; page.total=scalar_count("detection_events"); sqlite3_stmt* s=prepare("SELECT timestamp,flow_id,sid,event_type,explanation,evidence FROM detection_events ORDER BY timestamp DESC LIMIT ? OFFSET ?;"); if(!s) return page; sqlite3_bind_int64(s,1,request.page_size); sqlite3_bind_int64(s,2,(request.page-1)*request.page_size); while(sqlite3_step(s)==SQLITE_ROW){ DetectionEventRecord v; v.timestamp=sqlite3_column_int64(s,0); v.flow_id=sqlite3_column_int64(s,1); v.sid=sqlite3_column_int(s,2); v.event_type=reada(s,3); v.explanation=reada(s,4); v.evidence=reada(s,5); page.items.push_back(std::move(v)); } sqlite3_finalize(s); return page; }
    RulePage query_simple_rules(PageRequest request, const RuleFilter& filter = {}) const {
        normalize(request);
        std::lock_guard<std::mutex> lock(mutex_);
        RulePage page;
        FilterBuilder builder;
        if (!filter.search.empty()) {
            const std::string pattern = FilterBuilder::contains_pattern(filter.search);
            if (is_numeric(filter.search) && filter.search.size() <= 18) {
                const std::int64_t number = std::stoll(filter.search);
                builder.clause("(LOWER(message) LIKE LOWER(?) ESCAPE '\\' OR LOWER(protocol) LIKE LOWER(?) ESCAPE '\\' OR LOWER(source_file) LIKE LOWER(?) ESCAPE '\\' OR sid = ?)",
                               [pattern, number](sqlite3_stmt* s, int index) { sqlite3_bind_text(s, index, pattern.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_text(s, index + 1, pattern.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_text(s, index + 2, pattern.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_int64(s, index + 3, number); }, 4);
            } else {
                builder.clause("(LOWER(message) LIKE LOWER(?) ESCAPE '\\' OR LOWER(protocol) LIKE LOWER(?) ESCAPE '\\' OR LOWER(source_file) LIKE LOWER(?) ESCAPE '\\')",
                               [pattern](sqlite3_stmt* s, int index) { sqlite3_bind_text(s, index, pattern.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_text(s, index + 1, pattern.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_text(s, index + 2, pattern.c_str(), -1, SQLITE_TRANSIENT); }, 3);
            }
        }
        {
            sqlite3_stmt* count = prepare(("SELECT COUNT(*) FROM rules WHERE " + builder.sql() + ";").c_str());
            if (count) {
                builder.bind(count);
                if (sqlite3_step(count) == SQLITE_ROW) page.total = static_cast<std::size_t>(sqlite3_column_int64(count, 0));
                sqlite3_finalize(count);
            }
        }
        const auto offset = (request.page - 1) * request.page_size;
        sqlite3_stmt* s = prepare(("SELECT sid,revision,message,enabled,source_file,gid,priority,protocol FROM rules WHERE " + builder.sql() + " ORDER BY sid,revision LIMIT ? OFFSET ?;").c_str());
        if (!s) return page;
        builder.bind(s);
        sqlite3_bind_int64(s, builder.binder_count() + 1, static_cast<sqlite3_int64>(request.page_size));
        sqlite3_bind_int64(s, builder.binder_count() + 2, static_cast<sqlite3_int64>(offset));
        while (sqlite3_step(s) == SQLITE_ROW) {
            RuleRecord v;
            v.sid = sqlite3_column_int(s, 0);
            v.revision = sqlite3_column_int(s, 1);
            v.message = reada(s, 2);
            v.enabled = sqlite3_column_int(s, 3) != 0;
            v.source_file = reada(s, 4);
            v.gid = sqlite3_column_int(s, 5);
            v.priority = sqlite3_column_int(s, 6);
            v.protocol = reada(s, 7);
            page.items.push_back(std::move(v));
        }
        sqlite3_finalize(s);
        return page;
    }
    StatisticPage query_simple_statistics(PageRequest request) const { normalize(request); std::lock_guard<std::mutex> lock(mutex_); StatisticPage page; page.total=scalar_count("statistics"); sqlite3_stmt* s=prepare("SELECT timestamp,name,value,text_value FROM statistics ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?;"); if(!s) return page; sqlite3_bind_int64(s,1,request.page_size); sqlite3_bind_int64(s,2,(request.page-1)*request.page_size); while(sqlite3_step(s)==SQLITE_ROW){ StatisticRecord v; v.timestamp=sqlite3_column_int64(s,0); v.name=reada(s,1); v.value=sqlite3_column_int64(s,2); v.text_value=reada(s,3); page.items.push_back(std::move(v)); } sqlite3_finalize(s); return page; }

    void enqueue(Write write) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_ || writes_.size() >= config_.maximum_pending_writes) { ++metrics_.writes_dropped; return; }
        writes_.push(std::move(write));
        ++metrics_.writes_accepted;
        condition_.notify_one();
    }

    void worker_loop() {
        for (;;) {
            Write write;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                condition_.wait(lock, [this] { return stopping_ || !writes_.empty(); });
                if (stopping_ && writes_.empty()) return;
                write = std::move(writes_.front()); writes_.pop(); processing_ = true;
            }
            persist(write);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                processing_ = false; ++metrics_.writes_completed;
            }
            drained_.notify_all();
        }
    }

    void persist(const Write& write) {
        std::lock_guard<std::mutex> lock(mutex_);
        switch (write.type) {
            case Write::Type::alert: persist_alert(write.alert); break;
            case Write::Type::incident: persist_incident(write.incident); break;
            case Write::Type::flow: persist_flow(write.flow); break;
            case Write::Type::event: persist_event(write.event); break;
            case Write::Type::rule: persist_rule(write.rule); break;
            case Write::Type::statistic: persist_statistic(write.timestamp, write.name, write.value); break;
            case Write::Type::traffic: persist_traffic(write.traffic); break;
        }
    }

    void persist_alert(const alert::Alert& value) { execute("INSERT OR REPLACE INTO alerts (id, first_seen, last_seen, occurrence_count, suppressed_count, severity, confidence, risk, detection_type, sid, revision, source_ip, source_port, destination_ip, destination_port, protocol, service, flow_id, traffic_id, message, evidence, explanation, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", [&](sqlite3_stmt* s) { bind_alert(s, value); }); }
    void persist_incident(const incident::Incident& value) { execute("INSERT OR REPLACE INTO incidents (id, first_seen, last_seen, status, severity, confidence, risk, category, event_count, explanation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", [&](sqlite3_stmt* s) { sqlite3_bind_int64(s,1,value.id); sqlite3_bind_int64(s,2,value.first_seen); sqlite3_bind_int64(s,3,value.last_seen); text(s,4,incident::status_name(value.status)); text(s,5,alert::severity_name(value.severity)); sqlite3_bind_int(s,6,value.confidence); sqlite3_bind_int(s,7,value.risk); text(s,8,value.category); sqlite3_bind_int64(s,9,value.event_count); text(s,10,value.explanation); }); }
    void persist_flow(const Write::FlowSummary& value) { execute("INSERT OR REPLACE INTO flows (id, start_time, last_seen, service, protocol, packets, bytes) VALUES (?, ?, ?, ?, ?, ?, ?);", [&](sqlite3_stmt* s) { sqlite3_bind_int64(s,1,value.id); sqlite3_bind_int64(s,2,value.start_time); sqlite3_bind_int64(s,3,value.last_seen); text(s,4,value.service); text(s,5,value.protocol); sqlite3_bind_int64(s,6,value.packets); sqlite3_bind_int64(s,7,value.bytes); }); }
    void persist_event(const detection::DetectionEvent& value) { execute("INSERT INTO detection_events (timestamp, flow_id, sid, event_type, explanation, evidence) VALUES (?, ?, ?, ?, ?, ?);", [&](sqlite3_stmt* s) { sqlite3_bind_int64(s,1,value.timestamp_seconds); sqlite3_bind_int64(s,2,value.flow_id); sqlite3_bind_int(s,3,value.sid); text(s,4,detection::detection_type_name(value.type)); text(s,5,value.explanation); text(s,6,std::string(value.evidence.begin(), value.evidence.end())); }); }
    void persist_rule(const detection::Rule& value) { execute("INSERT OR REPLACE INTO rules (sid, revision, message, enabled, source_file, gid, priority, protocol) VALUES (?, ?, ?, 1, ?, ?, ?, ?);", [&](sqlite3_stmt* s) { sqlite3_bind_int(s,1,value.sid); sqlite3_bind_int(s,2,value.revision); text(s,3,value.message); text(s,4,value.source_file); sqlite3_bind_int(s,5,value.gid); sqlite3_bind_int(s,6,value.priority); text(s,7,transport_name(value.protocol)); }); }
    void persist_statistic(std::int64_t timestamp, const std::string& name, std::int64_t value) { execute("INSERT INTO statistics (timestamp, name, value) VALUES (?, ?, ?);", [&](sqlite3_stmt* s) { sqlite3_bind_int64(s,1,timestamp); text(s,2,name); sqlite3_bind_int64(s,3,value); }); }
    void persist_traffic(const TrafficRecord& value) {
        if (value.id == 0) {
            execute("INSERT INTO traffic_logs (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, length, payload_summary, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);", [&](sqlite3_stmt* s) { bind_traffic(s, value, false); });
        } else {
            execute("INSERT OR REPLACE INTO traffic_logs (id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, length, payload_summary, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", [&](sqlite3_stmt* s) { bind_traffic(s, value, true); });
        }
    }
    void bind_traffic(sqlite3_stmt* s, const TrafficRecord& value, bool with_id) {
        int index = 1;
        if (with_id) sqlite3_bind_int64(s, index++, static_cast<sqlite3_int64>(value.id));
        sqlite3_bind_int64(s, index++, value.timestamp);
        text(s, index++, value.src_ip);
        sqlite3_bind_int(s, index++, value.src_port);
        text(s, index++, value.dst_ip);
        sqlite3_bind_int(s, index++, value.dst_port);
        text(s, index++, value.protocol);
        sqlite3_bind_int64(s, index++, static_cast<sqlite3_int64>(value.length));
        text(s, index++, value.payload_summary);
        text(s, index++, value.details);
    }

    template <typename Binder> void execute(const char* sql, Binder binder) { auto* statement = prepare(sql); if (!statement) { ++metrics_.errors; return; } binder(statement); if (sqlite3_step(statement) != SQLITE_DONE) ++metrics_.errors; sqlite3_finalize(statement); }
    static void text(sqlite3_stmt* statement, int index, const std::string& value) { sqlite3_bind_text(statement,index,value.c_str(),-1,SQLITE_TRANSIENT); }
    void bind_alert(sqlite3_stmt* s, const alert::Alert& v) { sqlite3_bind_int64(s,1,static_cast<sqlite3_int64>(v.id)); sqlite3_bind_int64(s,2,v.first_seen); sqlite3_bind_int64(s,3,v.last_seen); sqlite3_bind_int64(s,4,static_cast<sqlite3_int64>(v.occurrence_count)); sqlite3_bind_int64(s,5,static_cast<sqlite3_int64>(v.suppressed_count)); text(s,6,alert::severity_name(v.severity)); sqlite3_bind_int(s,7,v.confidence); sqlite3_bind_int(s,8,v.risk); text(s,9,detection::detection_type_name(v.detection_type)); sqlite3_bind_int(s,10,static_cast<int>(v.sid)); sqlite3_bind_int(s,11,static_cast<int>(v.revision)); text(s,12,v.source_ip); sqlite3_bind_int(s,13,v.source_port); text(s,14,v.destination_ip); sqlite3_bind_int(s,15,v.destination_port); text(s,16,v.protocol); text(s,17,v.service); sqlite3_bind_int64(s,18,static_cast<sqlite3_int64>(v.flow_id)); sqlite3_bind_int64(s,19,static_cast<sqlite3_int64>(v.traffic_id)); text(s,20,v.message); text(s,21,v.evidence); text(s,22,v.explanation); text(s,23,v.fingerprint); }

    static const char* transport_name(packet::TransportProtocol protocol) noexcept { switch(protocol) { case packet::TransportProtocol::tcp: return "TCP"; case packet::TransportProtocol::udp: return "UDP"; case packet::TransportProtocol::icmp: return "ICMP"; case packet::TransportProtocol::icmpv6: return "ICMPv6"; default: return "other"; } }
    std::size_t count_rows(const std::string& table) const override { return scalar_count(table.c_str()); }
    std::size_t count_where(const char* table, const FilterBuilder& builder) const {
        sqlite3_stmt* statement = prepare((std::string("SELECT COUNT(*) FROM ") + table + " WHERE " + builder.sql() + ";").c_str());
        if (!statement) return 0;
        builder.bind(statement);
        const auto result = sqlite3_step(statement) == SQLITE_ROW ? static_cast<std::size_t>(sqlite3_column_int64(statement, 0)) : 0;
        sqlite3_finalize(statement);
        return result;
    }
    std::size_t count_rows_filtered(const char* table, const IncidentFilter& filter) const { if (std::string(table) != "incidents") return scalar_count(table); FilterBuilder builder; if (!filter.status.empty()) builder.equals_text("status", filter.status); if (!filter.category.empty()) builder.equals_text("category", filter.category); if (!filter.search.empty()) { const std::string pattern = FilterBuilder::contains_pattern(filter.search); builder.clause("(LOWER(category) LIKE LOWER(?) ESCAPE '\\' OR LOWER(status) LIKE LOWER(?) ESCAPE '\\' OR LOWER(explanation) LIKE LOWER(?) ESCAPE '\\')", [pattern](sqlite3_stmt* s, int index) { for (int offset = 0; offset < 3; ++offset) sqlite3_bind_text(s, index + offset, pattern.c_str(), -1, SQLITE_TRANSIENT); }); } return count_where(table, builder); }
    bool clear_table(const char* sql, std::size_t& deleted) {
        std::lock_guard<std::mutex> lock(mutex_);
        char* error = nullptr;
        if (sqlite3_exec(database_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
            ++metrics_.errors;
            sqlite3_free(error);
            return false;
        }
        deleted = static_cast<std::size_t>(sqlite3_changes(database_));
        return true;
    }
    sqlite3_stmt* prepare(const char* sql) const { sqlite3_stmt* statement = nullptr; if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK) return nullptr; return statement; }
    std::size_t scalar_count(const char* table) const { const std::string sql = std::string("SELECT COUNT(*) FROM ") + table + ";"; sqlite3_stmt* statement = prepare(sql.c_str()); if (!statement) return 0; const auto result = sqlite3_step(statement) == SQLITE_ROW ? static_cast<std::size_t>(sqlite3_column_int64(statement,0)) : 0; sqlite3_finalize(statement); return result; }
    alert::Alert read_alert(sqlite3_stmt* s) const { alert::Alert value; value.id=sqlite3_column_int64(s,0); value.gid=1; value.first_seen=sqlite3_column_int64(s,1); value.last_seen=sqlite3_column_int64(s,2); value.occurrence_count=sqlite3_column_int64(s,3); value.suppressed_count=sqlite3_column_int64(s,4); value.severity=parse_severity(reada(s,5)); value.confidence=sqlite3_column_int(s,6); value.risk=sqlite3_column_int(s,7); value.detection_type=parse_detection_type(reada(s,8)); value.sid=static_cast<std::uint32_t>(sqlite3_column_int64(s,9)); value.revision=static_cast<std::uint32_t>(sqlite3_column_int64(s,10)); value.source_ip=reada(s,11); value.source_port=static_cast<std::uint16_t>(sqlite3_column_int64(s,12)); value.destination_ip=reada(s,13); value.destination_port=static_cast<std::uint16_t>(sqlite3_column_int64(s,14)); value.protocol=reada(s,15); value.service=reada(s,16); value.flow_id=sqlite3_column_int64(s,17); value.traffic_id=sqlite3_column_int64(s,18); value.message=reada(s,19); value.evidence=reada(s,20); value.explanation=reada(s,21); value.fingerprint=reada(s,22); return value; }
    TrafficRecord read_traffic(sqlite3_stmt* s) const { TrafficRecord value; value.id=sqlite3_column_int64(s,0); value.timestamp=sqlite3_column_int64(s,1); value.src_ip=reada(s,2); value.src_port=sqlite3_column_int(s,3); value.dst_ip=reada(s,4); value.dst_port=sqlite3_column_int(s,5); value.protocol=reada(s,6); value.length=sqlite3_column_int64(s,7); value.payload_summary=reada(s,8); value.details=reada(s,9); return value; }
    incident::Incident read_incident(sqlite3_stmt* s) const { incident::Incident value; value.id=sqlite3_column_int64(s,0); value.first_seen=sqlite3_column_int64(s,1); value.last_seen=sqlite3_column_int64(s,2); value.status=parse_incident_status(reada(s,3)); value.severity=parse_severity(reada(s,4)); value.confidence=sqlite3_column_int(s,5); value.risk=sqlite3_column_int(s,6); value.category=reada(s,7); value.event_count=sqlite3_column_int64(s,8); value.explanation=reada(s,9); return value; }
    static std::string reada(sqlite3_stmt* s, int index) { const auto* value=sqlite3_column_text(s,index); return value ? reinterpret_cast<const char*>(value) : ""; }
    static alert::Severity parse_severity(const std::string& value) { if (value == "INFO") return alert::Severity::info; if (value == "LOW") return alert::Severity::low; if (value == "HIGH") return alert::Severity::high; if (value == "CRITICAL") return alert::Severity::critical; return alert::Severity::medium; }
    static detection::DetectionType parse_detection_type(const std::string& value) { if (value == "protocol_anomaly") return detection::DetectionType::protocol_anomaly; if (value == "behavioral") return detection::DetectionType::behavioral; return detection::DetectionType::signature; }
    static incident::IncidentStatus parse_incident_status(const std::string& value) { if (value == "ACKNOWLEDGED") return incident::IncidentStatus::acknowledged; if (value == "RESOLVED") return incident::IncidentStatus::resolved; return incident::IncidentStatus::open; }

    void ensure_column(const char* table, const char* column, const char* definition) {
        sqlite3_stmt* statement = prepare((std::string("PRAGMA table_info(") + table + ");").c_str());
        if (!statement) return;
        bool exists = false;
        while (sqlite3_step(statement) == SQLITE_ROW) {
            const auto* name = sqlite3_column_text(statement, 1);
            if (name && column == std::string(reinterpret_cast<const char*>(name))) { exists = true; break; }
        }
        sqlite3_finalize(statement);
        if (exists) return;
        char* error = nullptr;
        const std::string sql = std::string("ALTER TABLE ") + table + " ADD COLUMN " + column + " " + definition + ";";
        if (sqlite3_exec(database_, sql.c_str(), nullptr, nullptr, &error) != SQLITE_OK) {
            const std::string message = error ? error : "schema migration failed";
            sqlite3_free(error);
            throw std::runtime_error(message);
        }
    }
    void initialize_schema() { // Readers must not block the writers of a
        // concurrently running Python capture: WAL journaling (persistent for
        // the file) plus the busy timeout below keep multi-process access
        // safe. Failures are ignored -- a locked pragma only delays the
        // upgrade, it must not abort API startup.
        sqlite3_exec(database_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr); const char* schema = "PRAGMA user_version = 1; CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, occurrence_count INTEGER NOT NULL, suppressed_count INTEGER NOT NULL, severity TEXT NOT NULL, confidence INTEGER NOT NULL, risk INTEGER NOT NULL, detection_type TEXT NOT NULL, sid INTEGER NOT NULL, revision INTEGER NOT NULL, source_ip TEXT, source_port INTEGER, destination_ip TEXT, destination_port INTEGER, protocol TEXT, service TEXT, flow_id INTEGER, traffic_id INTEGER NOT NULL DEFAULT 0, message TEXT, evidence TEXT, explanation TEXT, fingerprint TEXT UNIQUE); CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen); CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity); CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, status TEXT NOT NULL, severity TEXT NOT NULL, confidence INTEGER NOT NULL, risk INTEGER NOT NULL, category TEXT NOT NULL, event_count INTEGER NOT NULL, explanation TEXT); CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen); CREATE TABLE IF NOT EXISTS flows (id INTEGER PRIMARY KEY, start_time INTEGER, last_seen INTEGER, service TEXT, protocol TEXT, packets INTEGER, bytes INTEGER); CREATE TABLE IF NOT EXISTS incident_alerts (incident_id INTEGER NOT NULL, alert_id INTEGER NOT NULL, PRIMARY KEY (incident_id, alert_id)); CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident ON incident_alerts(incident_id); CREATE TABLE IF NOT EXISTS traffic_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, src_ip VARCHAR(50), dst_ip VARCHAR(50), src_port INTEGER, dst_port INTEGER, protocol VARCHAR(20), length INTEGER, payload_summary TEXT, details TEXT); CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs(timestamp); CREATE TABLE IF NOT EXISTS detection_events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, flow_id INTEGER, sid INTEGER, event_type TEXT, explanation TEXT, evidence TEXT); CREATE TABLE IF NOT EXISTS rules (sid INTEGER, revision INTEGER, message TEXT, enabled INTEGER, source_file TEXT, gid INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 3, protocol TEXT, PRIMARY KEY(sid, revision)); CREATE TABLE IF NOT EXISTS rule_metadata (sid INTEGER, revision INTEGER, metadata TEXT, PRIMARY KEY(sid, revision)); CREATE TABLE IF NOT EXISTS statistics (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, name TEXT, value INTEGER, text_value TEXT);"; char* error=nullptr; if(sqlite3_exec(database_,schema,nullptr,nullptr,&error)!=SQLITE_OK){const std::string message=error?error:"schema initialization failed";sqlite3_free(error);throw std::runtime_error(message);}
        ensure_column("alerts", "traffic_id",         "INTEGER NOT NULL DEFAULT 0");
        ensure_column("alerts", "ip_version",          "INTEGER NOT NULL DEFAULT 0");
        ensure_column("alerts", "capture_mode",        "TEXT");
        ensure_column("alerts", "capture_interface",   "TEXT");
        ensure_column("alerts", "vlan_id",             "INTEGER NOT NULL DEFAULT -1");
        ensure_column("alerts", "source_mac",          "TEXT");
        ensure_column("alerts", "destination_mac",     "TEXT");
        ensure_column("traffic_logs", "details",       "TEXT");
        ensure_column("traffic_logs", "ip_version",    "INTEGER NOT NULL DEFAULT 0");
        ensure_column("traffic_logs", "capture_mode",  "TEXT");
        ensure_column("traffic_logs", "vlan_id",       "INTEGER NOT NULL DEFAULT -1");
        ensure_column("rules", "gid",                  "INTEGER NOT NULL DEFAULT 1");
        ensure_column("rules", "priority",             "INTEGER NOT NULL DEFAULT 3");
        ensure_column("rules", "protocol",             "TEXT");
        ensure_column("statistics", "text_value",      "TEXT");
    }
    void close_database() noexcept { if(database_) sqlite3_close(database_); database_=nullptr; }

    StorageConfig config_; mutable std::mutex mutex_; std::condition_variable condition_; std::condition_variable drained_; std::queue<Write> writes_; bool processing_=false; bool stopping_=false; std::thread worker_; sqlite3* database_=nullptr; StorageMetrics metrics_{};
};

}  // namespace

std::unique_ptr<Storage> make_sqlite_storage(const StorageConfig& config) { return std::make_unique<SqliteStorage>(config); }

}  // namespace delta_nids::storage
