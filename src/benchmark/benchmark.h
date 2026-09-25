#pragma once
#include <cstddef>
#include <cstdint>
#include <chrono>
namespace delta_nids::benchmark {
struct Result { std::size_t iterations=0; std::uint64_t elapsed_microseconds=0; double operations_per_second=0; };
template <typename Function> Result run(std::size_t iterations, Function function) {
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t index=0; index<iterations; ++index) function(index);
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count();
    const auto safe_elapsed = elapsed == 0 ? std::uint64_t{1} : static_cast<std::uint64_t>(elapsed);
    return {iterations, safe_elapsed, static_cast<double>(iterations) * 1000000.0 / static_cast<double>(safe_elapsed)};
}
} // namespace delta_nids::benchmark
