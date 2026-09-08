# Delta-NIDS architecture

Delta-NIDS is a passive, cross-platform Network Intrusion Detection System. It observes authorized live traffic or replays PCAP input, decodes packets, tracks bounded state, evaluates rules and behavioral detectors, persists evidence in SQLite, exposes an HTTP API, and renders the API data in the dashboard.

## Evidence flow

```text
Npcap/libpcap (Host or Switch SPAN Mirror) or PCAP replay
        ↓
packet capture (Promiscuous, 802.1Q/QinQ VLAN stripping, deduplication)
        ↓
dual-stack IPv4 / IPv6 / TCP / UDP / ICMP / ICMPv6 decoding
        ↓
flow reassembly and bounded behavioral state
        ↓
rule and scan detection
        ↓
alerts with packet-derived evidence and endpoints
        ↓
SQLite traffic/alert/incident persistence with capture metadata
        ↓
native API → Flask proxy → dashboard (with live SPAN status panel)
```

## Capture Modes & SPAN Pipeline

Delta-NIDS supports two capture operational modes:
- **`normal` mode**: Captures from a standard endpoint interface using Npcap/libpcap and host socket layers.
- **`span` mode**: Configured specifically for passive tap or switch mirror destination interfaces. Promiscuous mode is strictly enforced, empty BPF filters capture all protocol families, socket receive buffers are expanded to 16+ MiB, 802.1Q/QinQ headers are extracted into packet metadata and stripped before layer 3/4 inspection, mirror duplicates are filtered via a sliding deduplication cache, and an automatic watchdog alerts operators if zero traffic is observed. See [docs/span_port_mirroring.md](span_port_mirroring.md) for switch configuration.

The common detection path receives normalized packets and does not depend on Linux or Windows APIs. Platform code is limited to interface enumeration, packet acquisition, privilege handling, filesystem paths, and system metrics.

## Scan detection contract

TCP/UDP scan detection uses a state key of source IP, destination IP, protocol, and probe class. TCP candidates are classified from observed flags (SYN, FIN, NULL, Xmas, Maimon/FIN+ACK); ACK-only probes require reverse response evidence in the Python path and remain conservative in the native path. Destination ports are deduplicated, state expires using a sliding window, and active keys/observations are bounded. Established ACK traffic, RST responses, unrelated destinations, and stale state must not create or inflate a scan event. Alert evidence contains the observed destination ports, not an inferred list of ports from scanner output.

## Incident correlation

Incidents retain their relationship to alert records. Correlation is evidence-based and constrained by source IP, destination IP, protocol, category, and the configured time window. The incident detail endpoint expands the related persisted alerts, including identifiers, rule metadata, timestamps, endpoints, ports, message, and evidence. Unrelated entities are not merged merely because they are temporally close.

## Runtime and storage

The dashboard consumes backend state and reports unavailable API data rather than generating placeholders. Reset operations clear persisted traffic, alerts, incidents, flows, and statistics while preserving schema and loaded rules; they do not stop capture or unload detection. Runtime counters are supplied by the capture/processing process when available.

## Passive-only contract

Delta-NIDS observes, analyzes, correlates, stores, and reports. It does not block, inject, modify, scan, exploit, reset connections, change firewall rules, or automatically respond to traffic.
