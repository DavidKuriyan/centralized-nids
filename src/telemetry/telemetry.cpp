#include "telemetry/telemetry.h"

#include <chrono>
#include <iostream>
#include <sstream>

namespace delta_nids::telemetry {
const char* log_level_name(LogLevel level) noexcept {
    switch (level) { case LogLevel::trace:return "TRACE"; case LogLevel::debug:return "DEBUG"; case LogLevel::info:return "INFO"; case LogLevel::warn:return "WARN"; case LogLevel::error:return "ERROR"; }
    return "INFO";
}
Logger::Logger(LogLevel minimum, bool json) : minimum_(minimum), json_(json) {}
void Logger::set_level(LogLevel minimum) noexcept { std::lock_guard lock(mutex_); minimum_ = minimum; }
void Logger::set_json(bool enabled) noexcept { std::lock_guard lock(mutex_); json_ = enabled; }
void Logger::log(LogLevel level, std::string_view component, std::string_view event, const std::map<std::string,std::string>& fields) const {
    std::lock_guard lock(mutex_); if (static_cast<int>(level) < static_cast<int>(minimum_)) return;
    if (json_) { std::cout << "{\"level\":\"" << log_level_name(level) << "\",\"component\":\"" << component << "\",\"event\":\"" << event << "\""; for (const auto& [key,value] : fields) std::cout << ",\"" << key << "\":\"" << value << "\""; std::cout << "}\n"; }
    else { std::cout << "[" << log_level_name(level) << "] " << component << ": " << event; for (const auto& [key,value] : fields) std::cout << " " << key << "=" << value; std::cout << '\n'; }
}
MetricsRegistry& MetricsRegistry::global() { static MetricsRegistry registry; return registry; }

void MetricsRegistry::increment(std::string_view name, std::uint64_t amount) { std::lock_guard lock(mutex_); counters_[std::string(name)] += amount; }
void MetricsRegistry::set(std::string_view name, std::uint64_t value) { std::lock_guard lock(mutex_); counters_[std::string(name)] = value; }
MetricsSnapshot MetricsRegistry::snapshot() const { std::lock_guard lock(mutex_); return {counters_}; }
TraceSpan::TraceSpan(MetricsRegistry& metrics, std::string name) : metrics_(metrics), name_(std::move(name)) { metrics_.increment(name_ + ".started"); }
TraceSpan::~TraceSpan() { metrics_.increment(name_ + ".completed"); }
} // namespace delta_nids::telemetry
