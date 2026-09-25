#include "benchmark/benchmark.h"
#include "flow/flow_manager.h"
#include <cassert>
int main() {
    delta_nids::flow::FlowManager manager({300, 86400, 2, {}});
    assert(manager.size() == 0);
    const auto result = delta_nids::benchmark::run(1000, [](std::size_t) {});
    assert(result.iterations == 1000 && result.elapsed_microseconds > 0 && result.operations_per_second > 0);
    return 0;
}
