# Detection coverage and visibility matrix

Delta-NIDS is passive. A status below describes behavior observable at the
capture point, not what a tool intended to do. **An alert is only generated
when packet evidence supports it.** Normal application traffic that merely
looks similar to a probe is evaluated conservatively and documented here.

## Behavioral detectors active in the runtime pipeline

The passive Python capture path (used by `run_project.py`/`main.py`) runs these
behavioral detectors, all keyed by complete observation scope and bounded with
sliding windows:

| SID | Detector | Observable behavior | Severity | False-positive posture |
|---|---|---|---|---|
| 90001 | ICMP echo visibility | One per (source, target, protocol) per window; ordinary echo requests are INFO visibility events, not attacks | INFO | Repeated ping traffic aggregates into one row whose count grows |
| 90002 | Host discovery sweep | Distinct **non-public** targets probed by ICMP/TCP from one source in a window; TCP sweeps are grouped by destination port; ARP is intentionally excluded (gateway/neighbor L2 resolution is normal housekeeping) | High | Requires the configured distinct-target threshold **and** scope awareness: Internet destinations are ordinary client egress and are excluded unless remote-sweep detection is explicitly enabled |
| 90003 | Port scan | Distinct destination ports probed by the same probe class (SYN, FIN, NULL, Xmas, Maimon, ACK-with-response, UDP) | High | ACK-only patterns require reverse RST/ICMP response evidence and are reported as *possible* |
| 90004 | DNS query-rate anomaly | High outbound DNS query volume from one source (replies excluded) | Medium | Emitted only above the per-window query threshold |
| 90005 | Repeated connection failures | RST/FIN closures toward one service endpoint; the passive analogue of brute-force-like behavior | Medium | Per (source, target, port) key, threshold-gated |
| 90006 | Invalid TCP flag combination | SYN+FIN and other RFC-invalid combinations | Low | Objective protocol violation |
| 90014 | SYN flood | Bare half-open SYN attempts toward one service endpoint; never counts completed handshakes, SYN-ACK replies, or teardown traffic | High | Per (source, target, port) key, threshold-gated within the sliding window |

Rule (signature) detection is provided by the configured `rules/rules.json`
plus runtime rules added through the Rules tab (content/pcre conditions on
cleartext payloads).

## Measured offline validation matrix

`tools/validate_local.py` replays deterministic traffic for each behavior
through the real capture → normalize → detect → alert pipeline and records
packets generated, packets captured (a measure of real evidence), detected
SIDs, and false-positive SIDs. Only rows with actual packet evidence can be
marked Detected. Results below are from the current codebase (offline replay
only; see the note at the end).

| Test | Expected | Captured | Detected | False Positive | Result |
|---|---|---|---|---|---|
| ICMP echo (single target, repeated ×5) | 1 INFO event per window | 5/5 | Yes (SID 90001) | None | PASS |
| ICMP host sweep | Per-target events + sweep | 3/3 | Yes (90001, 90002) | None | PASS |
| TCP SYN scan | High port scan | 8/8 | Yes (90003) | None | PASS |
| TCP connect scan (full handshake) | SYN probes → SYN scan | 24/24 | Yes (90003) | None | PASS |
| UDP scan | High UDP port scan | 8/8 | Yes (90003) | None | PASS |
| TCP ACK scan with responses | Possible ACK scan | 16/16 | Yes (90003) | None | PASS |
| TCP FIN scan | High FIN port scan | 8/8 | Yes (90003) | None | PASS |
| TCP NULL scan | High NULL port scan | 8/8 | Yes (90003) | None | PASS |
| TCP Xmas scan | High Xmas port scan | 8/8 | Yes (90003) | None | PASS |
| TCP host discovery sweep | Host sweep across targets | 3/3 | Yes (90002) | None | PASS |
| DNS query-rate anomaly | High DNS query rate | 55/55 | Yes (90004) | None | PASS |
| HTTP path traversal (content rule) | Signature alert | 1/1 | Yes (700001) | None | PASS |
| Repeated connection failures (brute-force-like) | Repeated RST/FIN closures | 32/32 | Yes (90005) | None | PASS |
| Invalid TCP flag combination (SYN+FIN) | Protocol anomaly | 1/1 | Yes (90006) | None | PASS |
| TCP SYN flood (half-open attempts at one endpoint) | High rate of bare half-open SYN attempts toward one service | 100/100 | Yes (90014) | None | PASS |
| Normal traffic (negatives) | No alerts | 5/5 | No | None | PASS |
| Internet browsing to public destinations (negatives) | No host-discovery sweep for ordinary client egress | 3/3 | No | None | PASS |
| Gateway neighbor ARP resolution (negatives) | No host-discovery sweep, ever: ARP is excluded from sweep correlation | 3/3 | No | None | PASS |
| Single ICMP ping (negatives) | INFO visibility event only, no sweep | 1/1 | Yes (90001) | None | PASS |

```bash
.venv/bin/python tools/validate_local.py           # human-readable table
.venv/bin/python tools/validate_local.py --json    # machine-readable report
```

## Measured scanner coverage (wire-behavior validation)

The engine does not identify tools by name, so each scanner was evaluated by
replaying the specific probe pattern it emits at the NIC (see
`tools/validate_local.py`, scanner-emulation rows; all rows PASS). The live
scanner binaries also require root for raw sockets (`masscan`/`unicornscan`
installed on the sensor both refuse unprivileged runs), and scan traffic must
originate from a second host for the sensor NIC to see it — see
`docs/nmap-validation.md` § 4.5.

| Scanner | Observable probe pattern | Detected as | SID | Measured | Note |
|---|---|---|---|---|---|
| Masscan | SYN probes to many ports, random source ports, one source | TCP SYN port scan | 90003 | PASS | Evidence stays bounded at 65k-port scale (`port_threshold` high) |
| RustScan | Fast SYN probes to the full port range | TCP SYN port scan | 90003 | PASS | Same probe class as Masscan rows; not installed on sensor, wire pattern emulated |
| Unicornscan | Async SYN probes + correlated RST replies | TCP SYN port scan | 90003 | PASS | Response evidence recorded; ACK-mode still requires response evidence |
| Zmap (tcp_synscan) | One port, many hosts | Host discovery sweep | 90002 | PASS | Horizontal sweep, not a per-host port scan; targets list bounded at subnet scale |
| Zmap (icmp_echoscan) | ICMP echo across many hosts | Visibility + host sweep | 90001, 90002 | PASS | Per-target INFO events plus the sweep event |
| Angry IP Scanner | ICMP ping sweep + small TCP port list | Visibility + sweep + port scan | 90001, 90002, 90003 | PASS | With ≥ `port_threshold` distinct ports per host |
| Nmap (-sS/-sT) | SYN / connect probes across ports | TCP SYN port scan | 90003 | PASS | SYNs and connect handshakes share the SYN probe class |

`packets_captured` equals `packets_generated` for every row and `packets_failed`
is 0, so each PASS is grounded in packets the pipeline actually processed.

## Rule port syntax and variables

The canonical rule parser (`core/rule_management.py`) accepts user-friendly port expressions:

```text
80                        single port
80,443                    comma list
[80,443]                  bracketed list
1:1024                    port range
$HTTP_PORTS               pre-defined variable
$HTTP_PORTS,$HTTPS_PORTS  multiple variables
```

Rules added through the dashboard, through the API, loaded from `rules/rules.json`,
or refreshed from the runtime database are all compiled through the same parser,
so a rule behaves identically on every path. Pre-defined variables are defined
in `rules/port_variables.json` (`$HTTP_PORTS`, `$HTTPS_PORTS`, `$DNS_PORTS`,
`$SSH_PORTS`, `$FTP_PORTS`, `$SMTP_PORTS`, `$DATABASE_PORTS`) and can be
overridden per deployment with the `DELTA_NIDS_PORT_VARIABLES` JSON environment
variable. An unknown variable (`$XYZ_PORTS`) produces a user-facing validation
error listing the available variables instead of a low-level parser message.

## Tool compatibility assessment

The engine does not identify tools by name. The relevant observable behaviors
are:

- **Nmap, Masscan, RustScan, and Naabu:** covered when they emit multi-port TCP
  or UDP probes visible at the sensor. Tool speed, source IP, and packet order
  are not used as identity signals.
- **Nikto, Burp Suite, and OWASP ZAP:** cleartext HTTP content can match
  configured rules. HTTPS request paths and bodies require TLS termination or
  endpoint telemetry and are not claimed as visible here.
- **OpenVAS/Greenbone and Nessus:** their network probes are covered only where
  they produce the same observable TCP/UDP/ICMP or cleartext application
  behavior. Vulnerability conclusions generally require application responses
  and authenticated/endpoint context.
- **Hydra and similar credential testers:** repeated connection failures
  (RST/FIN closure patterns) are detected behaviorally, but authentication
  success/failure is not universally visible from encrypted protocols. The
  practical limit is documented under Limitations.
- **DNS reconnaissance tools:** outbound DNS volume and query content are
  observable when DNS is unencrypted and captured. DoH/DoT hides query names;
  endpoint or resolver telemetry is required.

The Python normalizer accepts IPv4 and IPv6 TCP, UDP, and ICMPv6 echo
traffic, including packets carried after common Scapy IPv6 extension-header
layers, and preserves quoted error headers (IPv4 type 3, ICMPv6 type 1/3) for
passive UDP-scan correlation.

## Observable-behavior coverage per category

| Technique | Subtype | Protocol | Observable behavior | Status | False-positive risk | Test method |
|---|---|---|---|---|---|---|
| Host discovery | ICMP echo sweep | ICMP/ICMPv6 | Echo requests to multiple distinct non-public targets in a bounded window | Supported (Python path, IPv4 and IPv6) | Medium on monitoring/health-check networks; public destinations excluded | Offline matrix, ICMP host sweep row |
| Host discovery | TCP discovery | TCP | SYN probes to multiple distinct non-public targets on the same destination port | Supported as host sweep; grouped per destination port | Low for Internet browsing by design (public scope excluded) | Offline matrix, TCP host sweep row |
| Host discovery | ARP discovery | ARP | ARP requests for many distinct locals on the local L2 segment | **Removed** (no longer a rule): gateway/neighbor ARP resolution is normal L2 housekeeping, so ARP never correlates into a host-discovery sweep | N/A — rule removed | Negative row: no sweep for ARP bursts |
| TCP scanning | SYN / connect-style probing | TCP | SYN probes to multiple destination ports | Supported, streamed at threshold | Low to medium depending on threshold | Offline matrix, SYN and connect rows |
| TCP scanning | FIN | TCP | FIN-only probes to multiple destination ports | Supported as behavioral FIN probing | Medium | Offline matrix, FIN row |
| TCP scanning | NULL | TCP | No-flag probes to multiple ports | Supported as behavioral NULL probing | Medium | Offline matrix, NULL row |
| TCP scanning | Xmas | TCP | FIN+PSH+URG probes to multiple ports | Supported as behavioral Xmas probing | Medium | Offline matrix, Xmas row |
| TCP scanning | Maimon | TCP | FIN+ACK probes to multiple ports | Supported | Medium/high; ACK semantics are ambiguous | Replay FIN+ACK packets |
| TCP scanning | ACK / window | TCP | ACK-only probes across ports plus response evidence | Supported (possible scan, requires responses) | High without response correlation | Offline matrix, ACK row |
| TCP anomalies | Invalid flags (SYN+FIN) | TCP | Invalid flag combinations | Supported (SID 90006) | Low; objectively invalid per RFC 793 | Offline matrix, anomaly row |
| DoS/flooding | TCP SYN flood | TCP | High rate of bare half-open SYN attempts from one source toward one service endpoint | Supported (SID 90014) | Low; only bare SYN packets count, so completed handshakes and normal client traffic never accumulate | Offline matrix, SYN flood row |
| UDP scanning | UDP port scan | UDP | Distinct outbound UDP destination ports | Supported | Medium; service discovery can look identical | Offline matrix, UDP row |
| UDP scanning | Closed-port inference | ICMP/ICMPv6+UDP | Quoted-error headers carry the original UDP probe | Supported when quoted headers are captured; IPv6 coverage narrower than IPv4 | Medium | Replay ICMP type 3 / ICMPv6 type 1/3 with quoted UDP |
| Service discovery | Version/banner probing | TCP/UDP | Application payload, banners, protocol metadata | Signature/protocol inspection dependent | Medium | Replay protocol-specific test PCAP |
| Web attacks | Suspicious URI/content | TCP/HTTP | Cleartext HTTP request bytes | Supported only for matching configured content rules | Medium | Offline matrix, HTTP traversal row |
| DNS anomalies | Query-rate behavior | UDP/DNS | Repeated outbound DNS queries from one source | Supported (SID 90004) | Medium; resolver-heavy hosts can look similar | Offline matrix, DNS row |
| Credential attacks | Repeated failures | TCP services | Repeated RST/FIN connection closures | Supported (SID 90005) as the observable analogue | Medium | Offline matrix, brute-force row |
| Malware/C2 | Encrypted C2 | TLS/other | Timing, endpoints, and metadata only | Not reliably attributable without additional telemetry | High | Requires labeled traffic and endpoint correlation |
| Endpoint-only attacks | Local process, file, memory, host auth state | N/A | Not present on the wire | Not detectable from passive packets alone | N/A | Requires endpoint agent/logs |

## Honest limitations of passive visibility

The following are *not* claimed as detectable from packets alone:

- Encrypted payload content (HTTPS, DoH/DoT, SSH application data).
- Authentication success/failure for encrypted protocols; only the
  connection-failure behaviour analogue is reported.
- Fragmentation anomalies in the native seam: fragmented datagrams require
  reassembly/defragmentation support that is not wired into the passive
  runtime; IP fragments are decoded but not reassembled for inspection.
- Malware/C2 attribution: repeated beacon-like timing can only be recognized
  with endpoint-side telemetry and labelled ground truth.
- Physical-layer visibility: a passive sensor on a switched, non-mirrored
  segment cannot see traffic that never reaches its NIC. See
  [`docs/nmap-validation.md`](nmap-validation.md) for the network-topology
  checklist.

## Evidence contract

Every active Python alert must include packet-derived source, destination,
protocol, and either payload/packet condition or behavioral evidence. A scan
alert includes the probe class, bounded time window, distinct observed ports
or targets, and response counts where available. An alert is not evidence that
an attack succeeded.

MAC addresses are capture-plane metadata: they are parsed internally where
required but are never rendered in user-facing alert or traffic views, which
present IPv4/IPv6 addresses and protocol fields only.

## Local validation environment

`tools/validate_local.py` provides a repeatable, isolated PCAP-replay
validation environment. It generates only documentation-addressed test traffic
in temporary storage, exercises every row of the matrix above, and reports
capture failures. It does not imitate kernel capture and therefore cannot
certify Npcap, VM visibility, `eth0` loss, or live dashboard behavior.

Live acceptance still requires an authorized test network. The correct evidence
for those tests is the captured PCAP, selected interface, capture counters,
packet-loss counters, API/database records, and dashboard response—not a
synthetic pass result.

The native C++ pipeline contains richer decoder, flow, reassembly, inspector,
and detector components, but it is not currently orchestrated by the launcher.
Those components must not be counted as active runtime coverage until an
integration pipeline connects them to capture and persistence.