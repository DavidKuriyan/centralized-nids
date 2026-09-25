# Performance Benchmarking & Optimization Guide

This document establishes benchmarking procedures, state boundary contracts, and performance profiling guidelines for Centralized-NIDS.

---

## 1. Benchmarking Objectives & Scope

Performance validation ensures that packet acquisition, protocol decoding, flow tracking, rule evaluation, and SQLite persistence operate within deterministic memory boundaries and meet line-rate throughput targets.

Benchmarks measure:
* **Throughput**: Packets per second (PPS) and aggregate Megabits/Gigabits per second (Gbps).
* **Processing Latency**: End-to-end time from wire capture to alert persistence.
* **Capture Integrity**: Kernel drop counters, buffer overruns, and libpcap/Npcap ring buffer utilization.
* **Memory Constancy**: Resident Set Size (RSS) during sustained high-throughput packet streams.
* **Storage Ingestion Rate**: SQLite transaction latency and write queue depths.

---

## 2. Automated Benchmark Execution

To execute the automated C++ native benchmark and state-limit verification suite:

```bash
# Compile with Release optimizations
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build --config Release

# Run automated tests and benchmark harness
ctest --test-dir build --output-on-failure
```

On Windows Developer PowerShell:
```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

---

## 3. Bounded-State Resource Contracts

To ensure operational stability under adversarial traffic conditions (e.g. state-exhaustion DoS attacks), all internal tables maintain strict bounds:

| Subsystem | Allocation Model | Eviction / Overflow Strategy |
| :--- | :--- | :--- |
| **Flow Table** | Maximum active flow count (bounded hash map) | Least-Recently-Used (LRU) eviction and sliding TTL timeouts. |
| **Behavioral Scan Cache** | Bounded target/port tracking windows | Automatic expiration based on sliding time window (default 30s). |
| **IPv6 Fragment Cache** | LRU-bounded fragment queue | Stale fragment timeout (60s); oldest uncompleted slices dropped. |
| **Alert & Storage Queue** | Asynchronous ring buffer | Backpressure throttling; drops low-priority debug logs before alert loss. |
| **SPAN Deduplication Cache**| Rolling hash index (configurable 1,000–10,000 entries) | Fixed FIFO ring replacement. |

---

## 4. Performance Tuning Recommendations

### Linux Kernel & Buffer Tuning
For high-speed SPAN feeds or 10G/25G capture adapters:
```bash
# Expand OS socket receive memory
sudo sysctl -w net.core.rmem_max=67108864
sudo sysctl -w net.core.rmem_default=33554432

# Increase adapter ring buffer sizes (where supported by driver)
sudo ethtool -G eth1 rx 4096
```

### Process Buffer Configuration
When launching via `main.py` or `delta-nids`, adjust buffer size and snap-length for high-volume environments:
```bash
# Set 64 MB kernel buffer and capture full jumbo frames (9216 bytes)
python main.py -i eth1 --capture-mode span --buffer-size 67108864 --snap-length 9216
```
