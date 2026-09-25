#include "telemetry/telemetry.h"
#include <cassert>
#include <thread>

int main() {
    delta_nids::telemetry::MetricsRegistry metrics;
    std::thread a([&] { for (int i=0;i<100;++i) metrics.increment("packets"); });
    std::thread b([&] { for (int i=0;i<100;++i) metrics.increment("packets"); });
    a.join(); b.join();
    { delta_nids::telemetry::TraceSpan span(metrics, "decode"); }
    const auto snapshot = metrics.snapshot();
    assert(snapshot.counters.at("packets") == 200);
    assert(snapshot.counters.at("decode.started") == 1);
    assert(snapshot.counters.at("decode.completed") == 1);
    delta_nids::telemetry::Logger logger;
    logger.set_level(delta_nids::telemetry::LogLevel::error);
    logger.set_json(true);
    logger.log(delta_nids::telemetry::LogLevel::debug, "test", "filtered");
    return 0;
}
