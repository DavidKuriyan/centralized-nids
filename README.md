# Centralized-NIDS: Enterprise Passive Network Intrusion Detection System

<div align="center">

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blue.svg)](#requirements)
[![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=c%2B%2B)](#building-c-native-engine)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python)](#python-environment-setup)
[![Capture Backend](https://img.shields.io/badge/Backend-libpcap%20%7C%20Npcap-orange.svg)](#packet-capture-architecture)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20Proprietary-green.svg)](#license)
[![Documentation](https://img.shields.io/badge/Docs-Complete%20Specifications-brightgreen.svg)](#documentation-index)

**A high-throughput, passive, dual-stack network intrusion detection system with real-time signature matching, stateful behavioral analytics, SPAN/TAP mirror ingestion, and an integrated telemetry dashboard.**

</div>

---

## Executive Summary

**Centralized-NIDS** (Delta-NIDS engine) is a lightweight, carrier-grade, **passive** Network Intrusion Detection System (NIDS) designed for both edge monitoring and centralized security operations. Operating on Linux and Windows, it monitors live networks via standard interfaces, hardware TAPs, or switch SPAN (Port Mirroring) sessions, as well as replaying offline PCAP dump files. 

Traffic is ingested with zero transmission footprint, normalized across IPv4 and IPv6 protocol stacks (including 802.1Q/QinQ VLAN stripping and fragment caching), evaluated against signature rules and bounded stateful behavioral heuristics, and persisted into an optimized SQLite datastore. The system exposes a native low-latency HTTP/REST telemetry API and delivers real-time analytical visibility through a responsive web console.

> [!IMPORTANT]
> **Strict Passive Guarantee**: Centralized-NIDS operates strictly out-of-band as an unnumbered sensor. It does **not** inject packets, transmit resets (RST), drop or alter frames, modify system firewalls, execute active scans, or interfere with network topology and routing protocols.

---

## Architecture Overview

```
                        ┌─────────────────────────────────────────────────────────┐
                        │              Network Traffic Ingestion                  │
                        │   • Live Interface (Promiscuous Mode)                   │
                        │   • Switch SPAN / Port Mirroring Destination            │
                        │   • Hardware Network TAP (Aggregate / Non-Aggregate)    │
                        │   • PCAP Replay File (.pcap / .pcapng)                  │
                        └────────────────────────────┬────────────────────────────┘
                                                     │
                                                     ▼
                        ┌─────────────────────────────────────────────────────────┐
                        │             Packet Acquisition Layer                    │
                        │   • Linux libpcap / Windows Npcap Driver                │
                        │   • Sliding-window Duplicate Frame Filter               │
                        │   • 802.1Q / QinQ VLAN Tag Stripping & Extraction       │
                        │   • Ring Buffer (configurable up to 64+ MB)             │
                        └────────────────────────────┬────────────────────────────┘
                                                     │
                                                     ▼
                        ┌─────────────────────────────────────────────────────────┐
                        │           Dual-Stack Normalization & Decoding           │
                        │   • IPv4 / IPv6 Protocol Decoders                       │
                        │   • IPv6 Fragment Cache & Offset Reassembly             │
                        │   • TCP / UDP / ICMP / ICMPv6 Header Decoders           │
                        │   • Quoted-error ICMP Payload Tracking                  │
                        └────────────────────────────┬────────────────────────────┘
                                                     │
                                                     ▼
                        ┌─────────────────────────────────────────────────────────┐
                        │              Detection & Analytics Engine               │
                        │   ├─ Signature Rule Engine (Port Sets, Variables, PCRE) │
                        │   └─ Behavioral Heuristics (Sliding-window Stateful)    │
                        │       • TCP SYN / FIN / NULL / Xmas / ACK Port Scans   │
                        │       • UDP Port Probing & Scan Sweeps                  │
                        │       • Horizontal Host-Discovery Sweeps                │
                        │       • Outbound DNS Query-Rate Anomalies               │
                        │       • Repeated RST/FIN Connection Failure Patterns    │
                        │       • RFC-Violating TCP Flag Combinations             │
                        │       • Bare SYN Flooding Volumetrics                   │
                        └────────────────────────────┬────────────────────────────┘
                                                     │
                                                     ▼
                        ┌─────────────────────────────────────────────────────────┐
                        │           Correlation, Persistence & Egress             │
                        │   • Alert Fingerprint Deduplication                     │
                        │   • Multi-Signal Incident Correlation                   │
                        │   • Thread-Safe SQLite Event & Telemetry Datastore      │
                        │   • Native C++ High-Speed REST API (Port 8080)          │
                        │   • Flask Real-Time Operations Dashboard (Port 8081)    │
                        └─────────────────────────────────────────────────────────┘
```

---

## Core Capabilities

| Feature | Description |
| :--- | :--- |
| **Zero-Interference Monitoring** | Completely passive listening mode with interface unbinding, preventing host address revelation on monitored links. |
| **SPAN / Port Mirroring Support** | Native mode designed for switch mirror ports with automatic zero-traffic watchdog alerts, VLAN unwrapping, and mirror deduplication. |
| **802.1Q & QinQ VLAN Parsing** | Seamlessly strips single and nested VLAN tags, preserving tag IDs in metadata while inspecting inner IP/transport payloads. |
| **Dual-Stack IPv4 & IPv6** | First-class IPv6 decoder with fragment cache reassembly, extension header traversal, and ICMPv6 error correlation. |
| **Multi-Stage Detection** | Combines Snort-like signature rule evaluation (supporting canonical port variables like `$HTTP_PORTS`) with streaming behavioral detectors. |
| **Robust Scan Detection** | Distinguishes SYN, FIN, NULL, Xmas, and ACK probes, streaming alerts immediately upon threshold attainment without batch delays. |
| **Host Sweep Discrimination** | Differentiates local multi-target discovery sweeps from ordinary Internet egress and neighbor ARP resolution, eliminating false positives. |
| **Incident Correlation** | Correlates distinct alerts sharing source, target, protocol, and classification into unified incidents with drill-down forensics. |
| **Native API & Web Console** | High-performance C++ REST endpoints proxy-integrated with a responsive, live-updating analytical UI. |

---

## Repository Layout

```text
centralized-nids/
├── CMakeLists.txt              # Unified C++ CMake build specification
├── requirements.txt            # Python dependencies (Scapy, Flask, etc.)
├── run_project.py              # Production orchestrator (Capture + API + Dashboard)
├── main.py                     # Standalone Python capture and detection engine
│
├── core/                       # Python Detection Engine Core
│   ├── alert_manager.py        # Alert persistence and incident aggregation
│   ├── behavioral_detector.py  # Sliding-window behavioral scan/flood detectors
│   ├── packet_capture.py       # Live & PCAP capture driver with SPAN diagnostics
│   ├── packet_normalizer.py    # Protocol decoding and flow normalization
│   └── rule_management.py     # Port variable parser and signature compiler
│
├── src/                        # High-Performance C++ Engine
│   ├── alert/                  # Alert structures and event generation
│   ├── api/                    # Native HTTP REST API server
│   ├── behavioral/             # C++ stateful behavioral detectors
│   ├── capture/                # libpcap/Npcap driver, SPAN diagnostics, IPv6 cache
│   ├── flow/                   # Flow reassembly and TCP state tracking
│   ├── interface/              # Cross-platform interface discovery and scoring
│   ├── packet/                 # High-speed Ethernet/VLAN/IP/TCP/UDP decoders
│   ├── rule/                   # C++ signature rule evaluator
│   └── storage/                # Thread-safe SQLite persistence layer
│
├── dashboard/                  # Operations Web Console
│   ├── app.py                  # Flask reverse-proxy and dashboard backend
│   ├── static/                 # CSS styling, charting, and JavaScript application
│   └── templates/              # Jinja2 dashboard templates
│
├── rules/                      # Signature Definitions & Port Sets
│   ├── rules.json              # Canonical threat signatures
│   └── port_variables.json     # Predefined port groupings ($HTTP_PORTS, etc.)
│
├── docs/                       # Technical & Architectural Specifications
│   ├── architecture.md         # Comprehensive system architecture & data contracts
│   ├── building.md             # Compilation guidelines and toolchain options
│   ├── detection-coverage.md   # Behavioral matrix, SIDs, and tool analysis
│   ├── span_port_mirroring.md  # Switch configuration guide (Cisco, Arista, Juniper)
│   ├── nmap-validation.md      # Ground-truth Nmap validation and visibility triage
│   ├── security.md             # Threat model, input validation, and deployment security
│   ├── performance.md          # Benchmark metrics and throughput guidelines
│   ├── evaluation.md           # Detection quality metrics (Precision, Recall, F1)
│   ├── linux.md                # Linux-specific setup and operational manual
│   ├── windows.md              # Windows/Npcap configuration and driver management
│   └── pcap-regression.md      # Deterministic PCAP regression test harness
│
└── tests/                      # Automated Verification & Test Suites
    ├── unit/                   # C++ GoogleTest / CTest test binaries
    └── test_*.py               # Python unit, integration, and pipeline tests
```

---

## Installation & Prerequisites

### System Requirements

* **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+) or Windows 10/11 / Windows Server 2019+
* **Memory**: Minimum 1 GB RAM (4 GB recommended for high-volume SPAN feeds)
* **Storage**: 500 MB for binaries and test suites; expandable SQLite disk allocation for logs
* **Toolchains**: Python 3.10+ and C++17 compatible compiler (GCC 9+, Clang 10+, or MSVC 2022)

### 1. Linux Setup

```bash
# Install compilation toolchain and capture libraries
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev libsqlite3-dev python3 python3-venv

# Clone repository
git clone https://github.com/DavidKuriyan/centralized-nids.git
cd centralized-nids

# Initialize Python virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Windows Setup

1. **Install Python 3.10+**: Download from [python.org](https://www.python.org/downloads/). Ensure **"Add Python to PATH"** is selected.
2. **Install Npcap**: Download from [npcap.com](https://npcap.com/#download).
   * Check: **"Install Npcap in WinPcap API-compatible Mode"**.
   * Optional: Check **"Support raw 802.11 traffic (and monitor mode)"**.
3. **Install Build Tools**: Install [Visual Studio 2022 Build Tools](https://visualstudio.microsoft.com/downloads/) with the *Desktop development with C++* workload.
4. **Clone and Configure Environment**:
   ```powershell
   git clone https://github.com/DavidKuriyan/centralized-nids.git
   cd centralized-nids

   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   py -m pip install --upgrade pip
   py -m pip install -r requirements.txt
   ```

---

## Building C++ Native Engine

Building the native C++ engine provides maximum line-rate packet acquisition, standalone execution, and low-latency API handling.

```bash
# Configure build with tests enabled
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DDELTA_NIDS_BUILD_TESTS=ON

# Compile the binaries
cmake --build build --config Release

# Execute test suite
ctest --test-dir build --output-on-failure
```

*(On Windows, run within Developer PowerShell for VS 2022 or select Ninja with `-G Ninja`.)*

---

## Quick Start & Execution

The unified launcher (`run_project.py`) automatically orchestrates the capture engine, the native C++ backend API, and the Flask operations console.

### 1. Unified Operational Mode

#### Linux (Elevated for Live Capture):
```bash
sudo -E env HOME="$HOME" PATH="$PATH" .venv/bin/python run_project.py --interface eth0
```

#### Windows (Run PowerShell as Administrator):
```powershell
.\.venv\Scripts\Activate.ps1

# Launch auto-detecting the primary active network interface:
py run_project.py

# Or specify an interface explicitly:
py run_project.py --interface "Ethernet"
```

Once running, access the web console in your browser:
👉 **`http://127.0.0.1:8081`**

---

### 2. Switch SPAN / Port Mirroring Mode

When connected to a switch mirror port or network TAP, enable SPAN mode. This mode forces promiscuous capture, disables capture filters to allow all protocol families, expands socket buffers to 16 MB, strips 802.1Q VLAN tags, activates deduplication, and monitors link health via a zero-traffic watchdog:

```bash
# Linux
sudo -E env HOME="$HOME" PATH="$PATH" .venv/bin/python run_project.py --interface eth1 --capture-mode span

# Windows (Elevated PowerShell)
py run_project.py --interface "Ethernet 2" --capture-mode span
```

For complete switch provisioning examples (Cisco Catalyst/Nexus, Arista EOS, Juniper Junos, Linux OVS, and VMware vSphere), consult the **[SPAN Port Mirroring Deployment Guide](docs/span_port_mirroring.md)**.

---

### 3. Offline PCAP Replay Mode

Replay standard `.pcap` or `.pcapng` capture files for audit, evaluation, or regression testing without requiring root or elevated privileges:

```bash
# Run complete system over sample PCAP
python run_project.py --pcap captures/sample.pcap
```

---

## Detection Capabilities & Behavioral SIDs

Centralized-NIDS couples custom signature rules with high-performance, streaming stateful behavioral detectors:

| SID | Category | Name | Detection Logic | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **90001** | Visibility | ICMP Echo Request | Aggregates individual ICMP ping packets per source/target window into informational visibility records. | `INFO` |
| **90002** | Reconnaissance | Host Discovery Sweep | Detects ICMP/TCP sweep attempts across distinct non-public hosts; ignores normal Internet egress and L2 ARP neighbor resolution. | `HIGH` |
| **90003** | Reconnaissance | Port Scan | Identifies horizontal and vertical port scans across SYN, FIN, NULL, Xmas, Maimon, and UDP probes. Streams alert immediately upon threshold. | `HIGH` |
| **90004** | Anomaly | DNS Query Volumetrics | Emits alerts when an internal host exceeds normal outbound DNS query rate thresholds (indicating tunneling or scanning). | `MEDIUM` |
| **90005** | Credential Attack | Connection Failures | Identifies brute-force authentication attempts by tracking elevated rates of RST/FIN connection terminations toward a single service. | `MEDIUM` |
| **90006** | Protocol Violation | Invalid TCP Flags | Detects RFC 793/RFC 1323 protocol violations (e.g., SYN+FIN or SYN+RST). | `LOW` |
| **90014** | Denial of Service | TCP SYN Flood | Detects high-rate bare half-open SYN packet bursts directed against a single endpoint; ignores completed handshakes. | `HIGH` |
| **700000+**| Signature | Custom Rule Alerts | Matches cleartext application byte signatures, header fields, and regex expressions configured in `rules/rules.json`. | Configurable |

For complete evaluation metrics, false-positive mitigations, and scanner validation results (Nmap, Masscan, RustScan, etc.), see the **[Detection Coverage & Visibility Matrix](docs/detection-coverage.md)**.

---

## REST API Reference

The backend exposes an ultra-low latency REST API on port `8080` (reverse-proxied seamlessly through `8081` by the dashboard):

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/status` | `GET` | Reports operational health, loaded rule counts, active capture interface, and packet metrics. |
| `/api/stats` | `GET` | Summary statistics of total packets, alerts, incidents, and memory/flow utilization. |
| `/api/alerts` | `GET` | Paginated list of persisted threat alerts, filtered by severity, protocol, or time window. |
| `/api/alerts/{id}` | `GET` | Full forensic detail for a specific alert including packet-derived evidence and raw frame fields. |
| `/api/alerts/export`| `GET` | Export all recorded alerts in structured JSON or CSV format. |
| `/api/incidents` | `GET` | Correlated security incidents grouping related alerts by source, target, and threat class. |
| `/api/incidents/{id}`| `GET` | Drill-down view of an incident with embedded constituent alert records. |
| `/api/traffic` | `GET` | Real-time connection log with source, destination, protocol, ports, and byte counters. |
| `/api/rules` | `GET` | Lists all active signature rules and port grouping variables. |
| `/api/reset` | `DELETE`| Flushes runtime alerts and flow tables without interrupting the capture process. |

---

## Verification & Automated Testing

Centralized-NIDS includes comprehensive automated testing across both C++ and Python subsystems:

```bash
# 1. Run Python Unit & Pipeline Tests
python -m unittest discover -s tests -p "test_*.py"

# 2. Run C++ Native Unit Tests
ctest --test-dir build --output-on-failure

# 3. Run Offline Matrix Validation
python tools/validate_local.py
```

The offline validation harness (`validate_local.py`) generates deterministic traffic patterns representing each threat class and negative control (e.g., normal web browsing, ARP discovery, single pings) to ensure zero false positives and 100% detection fidelity.

---

## Documentation Index

Detailed architectural, operational, and configuration documentation is available in the [`docs/`](docs/) directory:

* 📐 **[System Architecture](docs/architecture.md)** — Architectural design, pipeline contracts, and evidence models.
* 🛠️ **[Building & Compilation](docs/building.md)** — Toolchain configuration, CMake options, and dependency strategies.
* 🛡️ **[Detection Coverage Matrix](docs/detection-coverage.md)** — Detailed detection taxonomy, SIDs, and behavioral benchmarks.
* 🔌 **[SPAN Port Mirroring Guide](docs/span_port_mirroring.md)** — Switch port mirroring guide for Cisco, Arista, Juniper, and Linux.
* 🔍 **[Nmap Validation Guide](docs/nmap-validation.md)** — Step-by-step triage guide for validating Nmap scans and visibility.
* 🔒 **[Security Hardening](docs/security.md)** — Threat model, security boundaries, and production hardening.
* ⚡ **[Performance Benchmarking](docs/performance.md)** — Throughput benchmarks, state limits, and tuning parameters.
* 📊 **[Quality Evaluation](docs/evaluation.md)** — Precision, recall, and F1 scoring methodology.
* 🐧 **[Linux Operations Manual](docs/linux.md)** — Linux-specific privilege delegation, systemd integration, and tuning.
* 🪟 **[Windows Operations Manual](docs/windows.md)** — Windows Npcap integration, adapter GUIDs, and administration.
* 🧪 **[PCAP Regression Harness](docs/pcap-regression.md)** — PCAP regression methodology and reproducible test sets.

---

## License & Contributing

Distributed under the [MIT License](LICENSE) (or organizational license as designated). Contributions, bug reports, and pull requests are welcome. Please ensure all unit tests pass before submitting code.