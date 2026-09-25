#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <memory>

namespace delta_nids::telemetry {

enum class LogLevel { trace, debug, info, warn, error };
const char* log_level_name(LogLevel level) noexcept;

class Logger {
public:
    explicit Logger(LogLevel minimum = LogLevel::info, bool json = false);
    void set_level(LogLevel minimum) noexcept;
    void set_json(bool enabled) noexcept;
    void log(LogLevel level, std::string_view component, std::string_view event,
             const std::map<std::string, std::string>& fields = {}) const;
private:
    LogLevel minimum_;
    bool json_;
    mutable std::mutex mutex_;
};

struct MetricsSnapshot { std::map<std::string, std::uint64_t> counters; };
class MetricsRegistry {
public:
    static MetricsRegistry& global();
    void increment(std::string_view name, std::uint64_t amount = 1);
    void set(std::string_view name, std::uint64_t value);
    [[nodiscard]] MetricsSnapshot snapshot() const;
private:
    mutable std::mutex mutex_;
    std::map<std::string, std::uint64_t> counters_;
};

class TraceSpan {
public:
    TraceSpan(MetricsRegistry& metrics, std::string name);
    ~TraceSpan();
    TraceSpan(const TraceSpan&) = delete;
    TraceSpan& operator=(const TraceSpan&) = delete;
private:
    MetricsRegistry& metrics_;
    std::string name_;
};

} // namespace delta_nids::telemetry
