# Nmap SYN-Scan Investigation & Visibility Validation Manual

This technical manual details the root-cause analysis and verification procedure for diagnosing live scanner behavior against Centralized-NIDS. It documents the investigation of why certain scans may not trigger expected alerts due to upstream network topology constraints rather than engine detection deficiencies.

---

## 1. Case Study: Anatomy of an Inactive Scan

### Incident Summary
```text
Scanner Host (Windows):        Executed: nmap -sS 10.35.194.204
NIDS Sensor Host (Kali Linux): Running Centralized-NIDS
Observed Outcome:              Alerts generated for ICMP discovery probes (SID 90001),
                               but zero TCP SYN port-scan alerts (SID 90003).
```

### Transcript Analysis
```text
Nmap 7.99 ( https://nmap.org ) at 2026-09-01 09:04 +0530
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 1.65 seconds
```

### Root Cause Identification
1. By default, `nmap -sS` performs **pre-scan host discovery** (ICMP echo, TCP SYN to 443, TCP ACK to 80).
2. If the target does not reply to discovery probes, Nmap aborts execution with `0 hosts up` and **never transmits the multi-port SYN scan**.
3. The sensor alert queue recorded SID 90001 (`ICMP echo request`), confirming discovery probes were captured. Because no multi-port probes were sent, generating a port-scan alert would constitute a fabricated detection.

### Resolution: Forcing the Port-Scan Phase
To bypass discovery when testing against silent or firewall-protected targets:
```bash
nmap -Pn -sS 10.35.194.204          # Skip host discovery; execute SYN scan
nmap -Pn -sT 10.35.194.204          # Full TCP connect scan
nmap -Pn -sU --top-ports 50 ...     # UDP scan
nmap -Pn -sF ... -sN ... -sX ...   # FIN / NULL / Xmas scans
```

---

## 2. Network Visibility Triage Checklist

Before modifying detection rules, verify the end-to-end packet path:

```text
Scanner Host
  └─ Did the scanner emit raw frames?               tcpdump / pktmon on scanner host
       └─ Did virtual or physical network carry it? Promiscuous adapter mode / Bridge vs NAT
            └─ Did sensor NIC see the packets?      tcpdump on sensor interface
                 └─ Did capture driver open NIC?    delta-nids --list-interfaces
                      └─ Did decoder normalize?     /api/status packet counters
                           └─ Did detectors fire?   /api/alerts and database verification
```

### 2.1 Independent Packet Capture Verification
Run an independent sniffer on the sensor host during scan execution:

```bash
# Verify SYN packets reaching the sensor interface
sudo tcpdump -i eth0 -nn 'tcp[tcpflags] & tcp-syn != 0' -c 50

# Check interface hardware drop counters
ip -s link show eth0
```

If `tcpdump` observes SYN frames but Centralized-NIDS does not, inspect the capture driver and BPF filter configuration. If `tcpdump` observes zero frames, the issue lies upstream in switch provisioning or hypervisor networking.

### 2.2 Virtualization Topology Checklist

| Network Mode | Traffic Visibility | Action Required |
| :--- | :--- | :--- |
| **NAT** | Sensor cannot see outbound host traffic. | Switch adapter to **Bridged** mode. |
| **Bridged** | Sensor sees host traffic if adapter supports promiscuous mode. | Set Promiscuous Mode to **Allow All** in hypervisor settings. |
| **Host-Only** | Only VM-to-VM traffic within the isolated host network is visible. | Target the dedicated host-only IP address. |
| **Switched Port** | Only broadcast/multicast and sensor-directed unicast frames visible. | Configure switch **SPAN / Port Mirroring** (see [docs/span_port_mirroring.md](span_port_mirroring.md)). |

---

## 3. End-to-End Controlled Validation

### Step 1: Start Centralized-NIDS Sensor
```bash
# Terminal A (Sensor):
sudo -E env HOME="$HOME" .venv/bin/python run_project.py --interface eth0 --db /tmp/nmap-test.sqlite
```

### Step 2: Independent Sniffer
```bash
# Terminal B (Independent Sniffer):
sudo tcpdump -i eth0 -nn -s 0 -w /tmp/nmap-groundtruth.pcap
```

### Step 3: Execute Authorized Scan from Separate Host
```powershell
# Terminal C (Scanner Host):
nmap -Pn -sS <sensor-ip> --top-ports 100
```

### Step 4: Validate Database Records
```bash
python - <<'EOF'
import sqlite3
con = sqlite3.connect('/tmp/nmap-test.sqlite')
rows = con.execute("SELECT sid, message, evidence FROM alerts WHERE sid=90003 ORDER BY id DESC").fetchall()
assert rows, "Validation Failed: No SID 90003 alert recorded"
for sid, message, evidence in rows:
    print(f"[PASS] SID {sid}: {message}")
    print(f"       Evidence: {evidence}")
EOF
```

---

## 4. Architectural Enhancements Derived from Root-Cause Analysis

1. **Sliding-Window Streaming Detection**: Alerts trigger immediately upon distinct-port threshold attainment without batch-waiting.
2. **Protocol Anomaly Separation**: RFC-violating flag combinations (e.g. SYN+FIN) trigger dedicated protocol anomaly alerts (SID 90006) rather than silent drops.
3. **Scope-Aware Host Sweep Correlation**: Host discovery sweeps (SID 90002) ignore ordinary public Internet egress and neighbor ARP resolution, eliminating false alerts during regular web browsing.