# Detection Coverage & Visibility Matrix

Centralized-NIDS operates strictly as a **passive** network intrusion detection system. Threat alerts are generated solely when packet-level evidence strictly supports the classification. Legitimate application traffic that exhibits superficial similarity to scan probes is evaluated conservatively to prevent operational alert fatigue.

---

## 1. Behavioral Detectors Active in Runtime Pipeline

The streaming behavioral analytics pipeline evaluates traffic across dual-stack protocol streams using bounded sliding windows:

| SID | Threat Category | Classification | Observable Wire Behavior | Severity | False-Positive Mitigation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **90001** | Visibility | ICMP Echo Activity | Periodic ICMP echo requests per `(Source, Target, Protocol)` tuple. | `INFO` | Aggregates repeated diagnostic pings into a single event with an incrementing packet counter; does not alarm as an attack. |
| **90002** | Reconnaissance | Host Discovery Sweep | Probing distinct non-public hosts via ICMP or TCP from a single source within the sliding window. | `HIGH` | Scoped to private IP space by default; ignores normal Internet client egress (web, CDN) and completely excludes local L2 ARP resolution. |
| **90003** | Reconnaissance | Port Scan Probes | Probing distinct destination ports using a specific probe class (SYN, FIN, NULL, Xmas, Maimon, UDP). | `HIGH` | Streams alert immediately upon threshold; ACK-only probes require reverse response evidence (RST/ICMP) to prevent false flags on established sessions. |
| **90004** | Anomaly | DNS Query Volume | Excessive outbound DNS query rate originating from an internal endpoint (excluding response traffic). | `MEDIUM` | Emitted only when the query frequency exceeds defined window thresholds. |
| **90005** | Credential Attack | Connection Failures | Repeated RST/FIN connection terminations toward a single target service endpoint. | `MEDIUM` | Serves as the passive analogue of brute-force authentication attempts; gated per `(Source, Target, Port)` tuple. |
| **90006** | Protocol Violation | Invalid TCP Flags | Probes carrying RFC 793/1323 illegal flag combinations (e.g., SYN+FIN, SYN+RST). | `LOW` | Objective protocol violation. |
| **90014** | Denial of Service | TCP SYN Flood | Burst of bare, half-open SYN attempts directed at a single service endpoint. | `HIGH` | Gated by sliding-window rate thresholds; ignores completed handshakes and graceful teardown traffic. |

---

## 2. Offline Deterministic Validation Matrix

The offline test harness (`tools/validate_local.py`) replays deterministic traffic for each threat pattern through the real capture → normalize → detect → alert pipeline:

| Test Scenario | Expected Outcome | Packets Captured | Detected SID | False Positives | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ICMP Echo Probing** | 1 INFO event per window | 5 / 5 | SID 90001 | None | **PASS** |
| **ICMP Host Sweep** | Visibility + Sweep event | 3 / 3 | SID 90001, 90002 | None | **PASS** |
| **TCP SYN Port Scan** | High-severity Port Scan | 8 / 8 | SID 90003 | None | **PASS** |
| **TCP Connect Scan** | SYN probes trigger Port Scan | 24 / 24 | SID 90003 | None | **PASS** |
| **UDP Port Scan** | High-severity UDP Port Scan | 8 / 8 | SID 90003 | None | **PASS** |
| **TCP ACK Scan (with responses)** | Possible ACK Scan | 16 / 16 | SID 90003 | None | **PASS** |
| **TCP FIN Scan** | High-severity FIN Port Scan | 8 / 8 | SID 90003 | None | **PASS** |
| **TCP NULL Scan** | High-severity NULL Port Scan | 8 / 8 | SID 90003 | None | **PASS** |
| **TCP Xmas Scan** | High-severity Xmas Port Scan | 8 / 8 | SID 90003 | None | **PASS** |
| **TCP Host Sweep** | Host sweep across internal IPs | 3 / 3 | SID 90002 | None | **PASS** |
| **DNS Query Rate Burst** | High DNS query anomaly | 55 / 55 | SID 90004 | None | **PASS** |
| **HTTP Path Traversal** | Signature rule match | 1 / 1 | SID 700001 | None | **PASS** |
| **Brute-Force Connection Failures** | Repeated RST/FIN closures | 32 / 32 | SID 90005 | None | **PASS** |
| **Invalid Flags (SYN+FIN)** | Protocol anomaly | 1 / 1 | SID 90006 | None | **PASS** |
| **TCP SYN Flood** | Half-open SYN flood alert | 100 / 100 | SID 90014 | None | **PASS** |
| **Normal Web Traffic (Negative)** | No alerts | 5 / 5 | None | None | **PASS** |
| **Internet Egress (Negative)** | No false host sweeps | 3 / 3 | None | None | **PASS** |
| **Gateway ARP Resolution (Negative)** | No false host sweeps | 3 / 3 | None | None | **PASS** |
| **Single Ping Diagnostic (Negative)** | INFO visibility only | 1 / 1 | SID 90001 | None | **PASS** |

---

## 3. Scanner Wire-Behavior Coverage

The engine evaluates raw packet characteristics on the wire rather than relying on scanner process names:

| Scanner Tool | Observable Probe Pattern | Classification | Detected SID | Validation Status |
| :--- | :--- | :--- | :--- | :--- |
| **Masscan** | Asynchronous SYN probes to randomized destination ports | TCP SYN Port Scan | SID 90003 | **Verified** |
| **RustScan** | High-speed multi-port SYN probing across port ranges | TCP SYN Port Scan | SID 90003 | **Verified** |
| **Unicornscan** | Async SYN probes with correlated reverse RST responses | TCP SYN Port Scan | SID 90003 | **Verified** |
| **Zmap (`tcp_synscan`)** | Single destination port probed across wide IP ranges | Host Discovery Sweep | SID 90002 | **Verified** |
| **Zmap (`icmp_echoscan`)** | ICMP echo requests across broad subnet addresses | Host Discovery Sweep | SID 90001, 90002 | **Verified** |
| **Angry IP Scanner** | Ping sweep accompanied by common service port checks | Host Sweep & Port Scan | SID 90001, 90002, 90003 | **Verified** |
| **Nmap (`-sS` / `-sT`)** | SYN probes / completed handshakes across target ports | TCP SYN Port Scan | SID 90003 | **Verified** |

---

## 4. Rule Syntax & Port Variables

Signature definitions (`rules/rules.json`) support flexible port syntax compiled into canonical port sets:

```text
80                        Single destination port
80,443                    Comma-separated list
[80,443]                  Bracketed port list
1:1024                    Port range definition
$HTTP_PORTS               Predefined variable
$HTTP_PORTS,$HTTPS_PORTS  Compound variable expression
```

Predefined port variables are loaded from `rules/port_variables.json` (`$HTTP_PORTS`, `$HTTPS_PORTS`, `$DNS_PORTS`, `$SSH_PORTS`, `$FTP_PORTS`, `$SMTP_PORTS`, `$DATABASE_PORTS`) or configured dynamically via `DELTA_NIDS_PORT_VARIABLES`.

---

## 5. Scope & Physical Visibility Constraints

Passive network intrusion detection systems operate under specific physical constraints:
* **Encrypted Payloads**: Transport Layer Security (TLS 1.2/1.3), SSH, and DNS-over-HTTPS (DoH) encrypt application payloads on the wire. Content matching requires unencrypted cleartext or upstream TLS offloading.
* **Switched Segments**: On non-mirrored, switched network segments, unicast traffic between third-party hosts does not reach the sensor NIC. SPAN / Port Mirroring or network TAPs are required for centralized visibility (see [docs/span_port_mirroring.md](span_port_mirroring.md)).
* **Local Loopback Routing**: Scans launched from the sensor host targeting its own IP address are routed internally over `lo` (Linux) and bypass physical network adapters. Live scanner evaluation must originate from a separate host.