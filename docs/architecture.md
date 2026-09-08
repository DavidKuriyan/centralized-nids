# System Architecture & Technical Specification

Centralized-NIDS (Delta-NIDS engine) is an enterprise-grade, **passive**, cross-platform Network Intrusion Detection System. It observes live network traffic across standard NICs, hardware TAPs, or switch SPAN destination ports, as well as replaying offline PCAP dump files. Packets are parsed and normalized across dual-stack protocol layers, tracked via bounded flow state, evaluated against signature rules and behavioral heuristics, persisted into SQLite, and exposed through a high-performance REST API and real-time dashboard.

---

## 1. End-to-End Evidence Pipeline

```text
                  ┌─────────────────────────────────────────────────────────┐
                  │            Traffic Ingestion Sources                    │
                  │   • Live NIC (Linux libpcap / Windows Npcap)            │
                  │   • Switch SPAN / Port Mirroring Feeds                  │
                  │   • Offline PCAP Replay File                            │
                  └────────────────────────────┬────────────────────────────┘
                                               │
                                               ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │             Packet Acquisition Layer                    │
                  │   • Promiscuous raw socket driver                       │
                  │   • Sliding-window Duplicate Frame Filter               │
                  │   • Zero-traffic Link Watchdog                          │
                  │   • 802.1Q / QinQ VLAN Tag Stripping & Preservation     │
                  └────────────────────────────┬────────────────────────────┘
                                               │
                                               ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │             Protocol Normalization & Decoding           │
                  │   • Ethernet II / 802.3 Frame Decoders                  │
                  │   • IPv4 / IPv6 Dual-Stack Decoders                     │
                  │   • IPv6 Extension Headers & Fragment Reassembly Cache  │
                  │   • TCP / UDP / ICMP / ICMPv6 Decoders                  │
                  │   • Quoted-error ICMP Payload Tracking                  │
                  └────────────────────────────┬────────────────────────────┘
                                               │
                                               ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │             Flow Reassembly & State Tracking            │
                  │   • 5-Tuple Bounded Flow Tables                         │
                  │   • TCP State Machine Tracking (SYN/ACK/FIN/RST)        │
                  │   • Service & Port Group Classification                 │
                  └────────────────────────────┬────────────────────────────┘
                                               │
                                               ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │              Detection & Analytics Engine               │
                  │   ├─ Signature Engine (Port Sets, Variables, PCRE)      │
                  │   └─ Stateful Behavioral Analytics                      │
                  │       • Scan Probes (SYN, FIN, NULL, Xmas, ACK, UDP)    │
                  │       • Horizontal Host Discovery Sweeps                │
                  │       • Volumetric Floods (TCP SYN Floods)              │
                  │       • Protocol Anomaly Detection (RFC-violating flags)│
                  │       • Connection Failure Patterns (Brute-Force)       │
                  │       • Outbound DNS Query Anomaly Tracking             │
                  └────────────────────────────┬────────────────────────────┘
                                               │
                                               ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │           Correlation, Persistence & Operations         │
                  │   • Alert Fingerprint Deduplication                     │
                  │   • Multi-Signal Incident Correlation                   │
                  │   • Thread-Safe SQLite Event & Telemetry Datastore      │
                  │   • Native C++ High-Speed REST API (Port 8080)          │
                  │   • Flask Real-Time Operations Dashboard (Port 8081)    │
                  └─────────────────────────────────────────────────────────┘
```

---

## 2. Ingestion Modes & In-Depth SPAN Pipeline

Centralized-NIDS provides two primary capture operational modes:

### Standard (`normal`) Mode
Designed for host-level or single-segment listening:
* Utilizes OS socket layers via libpcap (Linux) or Npcap (Windows).
* Dynamically scores and binds to the primary active interface.
* Applies optional user-defined BPF filters.

### Port Mirroring (`span`) Mode
Specifically engineered for switch SPAN destination ports and network TAPs:
1. **Strict Promiscuous Enforcement**: Forces the underlying network adapter into promiscuous mode, bypassing hardware MAC filtering.
2. **Universal BPF Bypass**: Clears BPF capture filters to ensure unrestricted ingestion across IPv4, IPv6, ICMP, ICMPv6, ARP, and 802.1Q tagged frames.
3. **802.1Q & QinQ VLAN Parsing**: Mirror ports commonly forward tagged trunk traffic. The engine extracts outer and inner VLAN IDs into packet metadata and strips the 4-byte or 8-byte tag headers before handing off to L3/L4 decoders.
4. **Sliding-Window Duplicate Filter**: Switch mirror sessions often replicate both transmit (Tx) and receive (Rx) paths of the same conversation, causing artificial duplicate packets. A sliding deduplication cache calculates lightweight checksums over packet headers to filter mirror reflections.
5. **Zero-Traffic Watchdog**: If a mirror feed fails (cable disconnection, disabled SPAN session, or VLAN misconfiguration), the watchdog alerts operators when zero packets are observed within a 15–30 second window.

---

## 3. Protocol Decoding & Defragmentation

### Dual-Stack IPv4 and IPv6 Support
The engine parses IPv4 and IPv6 symmetrically. Protocol parsers validate:
* Minimum header lengths and version nibbles.
* Total length vs. wire length sanity checks.
* IPv6 Next Header extension chains (Hop-by-Hop, Routing, Fragment, Destination Options).

### IPv6 Fragment Cache
IPv6 fragmentation uses extension headers rather than IPv4 header bits. Centralized-NIDS implements an LRU-bounded fragment cache:
* Tracks fragment identification, source/destination IP, and next header.
* Reassembles fragmented payloads once all slices are present.
* Enforces strict expiration timers to thwart overlapping fragment evasion attacks.

---

## 4. Stateful Behavioral Detection Contract

Rather than relying purely on static signatures, Centralized-NIDS tracks behavioral evidence across configurable, sliding time windows.

### Port Scan Discrimination (SID 90003)
* **State Key**: `(Source IP, Destination IP, Protocol, Probe Class)`
* **Probe Classes**: SYN, FIN, NULL, Xmas, Maimon (FIN+ACK), ACK, and UDP.
* **Immediate Streaming**: An alert is emitted the instant the distinct destination port threshold is satisfied within the sliding window—no batch delays.
* **ACK Probe Constraint**: Plain ACK probes are only alerted if reverse RST/ICMP response evidence is observed, preventing false positives from out-of-order established sessions.

### Host Discovery Sweep Discrimination (SID 90002)
* **Scope Awareness**: Ordinary Internet egress (e.g. web browsing, CDN access, cloud APIs) connects to multiple public IPs. Host discovery sweeps correlate only against **non-public** (RFC 1918 / RFC 4193 / link-local) targets by default.
* **Protocol Segregation**: TCP sweeps are correlated strictly per destination port; ICMP sweeps track distinct echo targets.
* **ARP Exclusion**: ARP resolution is required for local network operation (gateway and neighbor lookups) and is deliberately excluded from host sweep correlation.

### Volumetric Flood Detection (SID 90014)
* Detects high-frequency bare half-open SYN packets targeting a specific service endpoint.
* Distinguishes attacks from legitimate traffic by never counting completed three-way handshakes, SYN-ACK replies, or FIN/RST teardown sequences.

---

## 5. Storage, Incident Correlation & State Boundaries

### Thread-Safe Persistence
* Persists traffic sessions, alerts, flow tables, and system telemetry into SQLite.
* Employs WAL (Write-Ahead Logging) and parameterized prepared statements to guard against injection and lock contention.

### Incident Correlation Model
Individual alerts are correlated into high-level incidents:
* **Correlation Keys**: `(Source IP, Target IP, Protocol, Threat Category, Time Window)`.
* Incidents maintain relational integrity with constituent alert records, providing full evidence drill-down without merging unrelated entities.

---

## 6. Strict Passive-Only Contract

Centralized-NIDS adheres to an uncompromised passive monitoring architecture:
* **Zero Packet Transmission**: Never injects packets or transmits TCP resets (RST).
* **Zero Network Disruption**: Does not modify routing tables, switch states, Spanning Tree BPDUs, or firewall policies.
* **Zero Active Scanning**: Never probes monitored endpoints.
* **Operator Safety**: Ensures compliance in zero-trust, critical infrastructure, and industrial control environments.
