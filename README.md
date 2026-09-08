# Delta-NIDS

Delta-NIDS is a **passive**, cross-platform Network Intrusion Detection System. It captures authorized live traffic or replays PCAP files, decodes packets, tracks flows, applies supported rules and behavioral detectors, persists results in SQLite, exposes a local HTTP API, and displays results in a Flask dashboard.

Delta-NIDS does not block, inject, modify, scan, exploit, reset, or automatically respond to traffic.

## Project layout

- `core/` — Python capture, packet normalization, alert persistence, and behavioral coordination.
- `src/` — C++ packet, flow, protocol, detection, storage, API, telemetry, and platform components.
- `dashboard/` — Flask same-origin dashboard and static client.
- `rules/` — configured rule data.
- `tests/` — Python and C++ regression/unit tests.
- `run_project.py` — starts capture, API, and dashboard together.

## Requirements

### Linux

```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev libsqlite3-dev python3 python3-venv
```

### Windows

1. **Python 3.10+**: Install from [python.org](https://www.python.org/) or Microsoft Store (ensure *Add Python to PATH* is checked).
2. **Npcap**: Download and install from [npcap.com](https://npcap.com/#download). During installation, ensure:
   - ✅ **"Install Npcap in WinPcap API-compatible Mode"** is checked.
   - ✅ **"Support raw 802.11 traffic (and monitor mode) for wireless adapters"** (optional but recommended).
3. **Visual Studio 2022 / Build Tools**: Install the *Desktop development with C++* workload with CMake and MSVC tools.

## Build & Setup

### Linux

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cmake -S . -B build -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build
```

### Windows (PowerShell)

1. **Set up Python Virtual Environment**:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

2. **Build C++ Engine (Optional / Native API)**:

```powershell
cmake -S . -B build -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build --config Release
```

*(If using Ninja: `cmake -S . -B build -G Ninja -DDELTA_NIDS_BUILD_TESTS=ON && cmake --build build`)*

## Run the complete application

The launcher starts the capture process, C++ API, and Flask dashboard. Press `Ctrl+C` to stop them.

### Live capture

#### Linux
Live capture may require elevation:

```bash
sudo -E env HOME="$HOME" .venv/bin/python run_project.py --interface eth0
```

#### Windows
> [!IMPORTANT]
> **Run PowerShell as Administrator** for complete packet capture 

```powershell
# Open PowerShell as Administrator
cd "path\to\delta-ids"
.\.venv\Scripts\Activate.ps1

# Run on Wi-Fi interface (name matching is flexible: "Wi-Fi", "wifi", "Wifi" all work)
py run_project.py --interface "Wi-Fi"

# Or run on Ethernet
py run_project.py --interface "Ethernet"

# Or let Delta-NIDS auto-detect the active interface
py run_project.py
```

### SPAN / Port Mirroring Capture Mode

Delta-NIDS supports passive monitoring directly from a switch SPAN (mirror) destination port:

```bash
# Linux
sudo -E env HOME="$HOME" .venv/bin/python run_project.py --interface eth1 --capture-mode span

# Windows (Elevated PowerShell)
py run_project.py --interface "Ethernet 2" --capture-mode span

# Direct Python capture engine
python main.py -i eth1 --capture-mode span --snap-length 65535 --buffer-size 16777216

# Direct Native C++ engine
./delta-nids -i eth1 --capture-mode span
```

In SPAN mode:
- **Promiscuous mode** is strictly enforced.
- **Empty BPF filter** captures all protocols (IPv4, IPv6, ICMP, ICMPv6, ARP, VLAN).
- **802.1Q and QinQ** tags are extracted and stripped before transport analysis.
- **Deduplication** absorbs mirror-induced duplicates across symmetric monitor sessions.
- **Zero-traffic watchdog** alerts operators if the switch SPAN feed stops sending frames.
- See [docs/span_port_mirroring.md](docs/span_port_mirroring.md) for full switch configuration examples (Cisco, Arista, Juniper, Linux OVS).


### PCAP replay

PCAP replay does not require capture privileges:

#### Linux:

```bash
.venv/bin/python run_project.py --pcap captures/sample.pcap
```

#### Windows:

```powershell
py run_project.py --pcap captures\sample.pcap
```

Open the dashboard in your browser:

```text
http://127.0.0.1:8081
```

The default database is user-owned at `$HOME/.local/share/delta-nids/nids.sqlite`; the API listens on `8080` and the dashboard on `8081`.

## Launcher options

```text
python run_project.py [--interface NAME | --pcap FILE]
                       [--db PATH] [--filter BPF] [--count N]
                       [--capture-mode normal|span]
                       [--api-port PORT] [--dashboard-port PORT]
                       [--no-capture]
```

Examples:

```bash
python run_project.py
python run_project.py --pcap captures/sample.pcap
python run_project.py --no-capture --db database/nids.sqlite
```

## Manual operation

```bash
# Capture and persist to SQLite
.venv/bin/python main.py --pcap captures/sample.pcap --persist --db database/nids.sqlite

# Start the native API
./build/delta-nids --api database/nids.sqlite

# Start the dashboard
.venv/bin/python dashboard/app.py
```

Python capture options include `--interface`, `--pcap`, `--config`, `--filter`, `--count`, `--db`, `--persist`, and `--quiet`. The default rule file is `rules/rules.json`; the default live BPF filter is empty so all protocols are captured. Port groups are read from `rules/port_variables.json`. For a clean Nmap validation run, use a dedicated writable database and record the selected adapter; see [`docs/nmap-validation.md`](docs/nmap-validation.md) for the host-discovery/visibility root-cause checklist.

## Detection behavior

- Supported explicit rule conditions are matched by the Python rule engine. Rule port expressions accept `80`, `80,443`, `[80,443]`, `1:1024`, and pre-defined port variables such as `$HTTP_PORTS` or `$HTTP_PORTS,$HTTPS_PORTS`; the parser normalizes every accepted form into one canonical port set, so rules behave identically when added through the dashboard, through the API, loaded from `rules/rules.json`, or refreshed from the runtime database.
- Pre-defined port groups are centrally configurable in `rules/port_variables.json` (`$HTTP_PORTS`, `$HTTPS_PORTS`, `$DNS_PORTS`, `$SSH_PORTS`, `$FTP_PORTS`, `$SMTP_PORTS`, `$DATABASE_PORTS`) and can be overridden with the `DELTA_NIDS_PORT_VARIABLES` JSON environment variable. Unknown variables fail validation with a message listing the available variables.
- Metadata-only or legacy `heuristic_payload` entries are reported as unsupported and are not treated as payload signatures.
- Behavioral port scans require distinct destination ports for the same source, destination, and protocol within the configured window; the alert is emitted as soon as the threshold is reached (no batch waiting).
- Duplicate UDP/DNS packets and a single DNS request do not constitute a port scan.
- Ordinary ICMP echo requests are bounded per-window INFO visibility events, not attacks. Host-discovery sweeps (SID 90002) require multiple **distinct non-public** targets within the window, so normal Internet browsing, CDN traffic, and gateway ARP resolution do not alarm. Sweep correlation covers ICMP and TCP only; TCP sweeps are correlated per destination port. ARP requests are intentionally excluded (gateway/neighbor L2 resolution is normal housekeeping), so the former ARP host-discovery sweep rule no longer fires and `DELTA_NIDS_ARP_SWEEP_THRESHOLD` has been removed. The window and thresholds are configurable via `DELTA_NIDS_SCAN_WINDOW`, `DELTA_NIDS_PING_THRESHOLD` (ICMP/TCP host discovery), `DELTA_NIDS_REMOTE_SWEEP_THRESHOLD`, and `DELTA_NIDS_REMOTE_SWEEP_ENABLED`.
- ICMP/UDP/TCP anomalies are detected as RFC-invalid behaviour only. Behavioral detectors also cover outbound DNS query-rate anomalies, repeated RST/FIN connection failures, and invalid TCP flag combinations.
- Alerts use `[gid:sid:rev]` identity and are deduplicated in SQLite by fingerprint.
- Stored host-sweep alerts produced with a weaker pre-fix threshold can be removed by revalidating them against the current evidence contract:
  `python main.py --db <path> --purge-false-positives`.

## Dashboard and API

The browser talks only to Flask on port `8081`; Flask proxies `/api/*` to the native API. The dashboard displays live API data and polls every three seconds. It reports unavailable backends instead of presenting mock values.

Important endpoints:

```text
GET    /api/status
GET    /api/stats
GET    /api/system
GET    /api/config
GET    /api/alerts
GET    /api/alerts/{id}
GET    /api/alerts/export
DELETE /api/alerts
GET    /api/traffic
GET    /api/traffic/{id}
GET    /api/traffic/export
DELETE /api/traffic
GET    /api/incidents
GET    /api/incidents/{id}
GET    /api/flows
GET    /api/rules
GET    /api/detection-events
GET    /api/statistics
DELETE /api/reset
```

`/api/status` includes API state, loaded-rule count, capture state, interface, captured/processed packet counts, and the last packet time when the capture process is reporting runtime data.

`DELETE /api/reset` clears alerts, traffic, incidents, flows, and statistics while preserving the schema and loaded rules. It does not stop or restart packet capture; the next heartbeat repopulates runtime status. `GET /api/incidents/{id}` includes an expanded `alerts` array with persisted alert evidence and `alert_count`.

## Database and permissions

Do not create the shared database as root and then access it as another user. Prefer the launcher’s user-owned database. For an existing root-owned database:

```bash
sudo chown "$USER:$USER" database/nids.db
chmod 600 database/nids.db
chmod u+rwx database
```

Stop all Delta-NIDS processes before removing SQLite journal files. The correct executable path is `./build/delta-nids`, not `/build/delta-nids`.

## Verification

Run the complete native suite:

```bash
cmake --build build
ctest --test-dir build --output-on-failure
```

Run Python tests and syntax checks:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
.venv/bin/python -m py_compile core/*.py database/*.py main.py run_project.py dashboard/app.py
```

Offline validation harness:

```bash
.venv/bin/python tools/validate_local.py
.venv/bin/python tools/validate_local.py --json
.venv/bin/python tools/validate_local.py --pcap captures/authorized-test.pcap
```

The default mode replays a controlled detection matrix (SYN/connect/UDP/ACK/FIN/
NULL/Xmas scans, host sweeps, DNS anomalies, HTTP content rules, connection
failures, TCP anomalies, and negative controls) through the real capture→
detect→alert pipeline and reports captured/detected/false-positive per case. It
is intentionally isolated and does not claim real Nmap, Npcap, VM, `eth0`, or
live-dashboard validation.

Useful native checks:

```bash
./build/delta-nids --list-interfaces
./build/delta-nids --validate-rules tests/fixtures/valid.rules.json
./build/delta-nids --stats
```

## Troubleshooting

- **API unavailable:** start the native API or run `run_project.py`; if using a custom API port, ensure `DELTA_NIDS_API_URL` points to it.
- **Dashboard shows `STALE`:** verify the capture process is alive, using the same database as the API, and has permission to write runtime statistics.
- **Readonly database:** correct ownership/permissions or choose a writable `--db` path; do not run only one component as root.
- **No alerts:** confirm `--persist` is enabled, the expected database is selected, rules are supported, and the traffic matches a rule or behavioral threshold.
- **False UDP scan concerns:** inspect the alert evidence; SID `90003` lists the distinct destination ports observed in its window. A single DNS query is not sufficient.
- **Live capture permission denied:** verify libpcap/Npcap installation, adapter availability, and required privileges. PCAP replay avoids live-capture permissions.
- **Wrong interface:** use `--list-interfaces` and pass the exact adapter name to `--interface`.
- **Port conflict:** use `--api-port` or `--dashboard-port` with the launcher.

## Additional documentation

- [`docs/architecture.md`](docs/architecture.md) — component boundaries and passive-only contract.
- [`docs/building.md`](docs/building.md) — build prerequisites and commands.
- [`docs/linux.md`](docs/linux.md) — Linux capture and interface operations.
- [`docs/windows.md`](docs/windows.md) — Windows/Npcap operations.
- [`docs/security.md`](docs/security.md) — security guarantees and deployment guidance.
- [`docs/performance.md`](docs/performance.md) — benchmark and bounded-state guidance.
- [`docs/nmap-validation.md`](docs/nmap-validation.md) — reproducible Kali-to-Windows Npcap/Nmap validation and evidence criteria.

## License

No license file is currently declared. Add and review a license before distribution.
#   c e n t r a l i z e d - n i d s  
 