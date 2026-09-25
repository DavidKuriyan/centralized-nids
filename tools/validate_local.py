"""Controlled, authorized offline detection matrix for Delta-NIDS.

This tool constructs deterministic layer-3/layer-4 packets and replays them
through the *actual* Delta-NIDS pipeline (PacketCapture -> packet_to_info ->
DeltaCore -> DetectionEngine -> AlertManager). It generates only
documentation-addressed test traffic in temporary storage and never scans
external hosts. Results are labelled as offline validation; they cannot prove
Npcap, VM, eth0, or live-dashboard behavior.

Each matrix row replays one attack/behavior class in isolation so the
evaluation is auditable:

    ATTACK -> NETWORK BEHAVIOR -> CAPTURED by the pipeline? -> ALERT SIDS ->
    EXPECTED SIDS -> false positives? -> PASS / FAIL

Usage:
    python tools/validate_local.py            # full detection matrix
    python tools/validate_local.py --pcap FILE  # replay one PCAP
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import ARP, Ether, ICMP, IP, TCP, UDP, IPv6, ICMPv6EchoRequest, Raw, wrpcap

from core.alert_manager import AlertManager
from core.delta_core import DeltaCore
from core.detection_engine import DetectionEngine
from core.packet_capture import PacketCapture

SCANNER = "198.51.100.10"
TARGET = "198.51.100.20"
UDP_SCANNER_PORT = 40000
TCP_SCANNER_PORT = 41000
TEST_SRC_MAC = "02:00:00:00:00:01"
TEST_DST_MAC = "02:00:00:00:00:02"


def _ether():
    """Explicit deterministic L2 addressing so replay never needs ARP resolution."""
    return Ether(src=TEST_SRC_MAC, dst=TEST_DST_MAC)


def _ip(src=SCANNER, dst=TARGET):
    return _ether() / IP(src=src, dst=dst)

def icmp_echo_same_target(count: int = 5):
    return [_ip() / ICMP(type=8, id=7, seq=index) for index in range(1, count + 1)]


def icmp_sweep(targets: int = 3):
    return [_ip(dst=f"198.51.100.{index}") / ICMP(type=8, id=7, seq=index)
            for index in (2, 3, 4)][:targets]


def tcp_scan(ports, flags="S", dst=TARGET, sport=TCP_SCANNER_PORT):
    return [_ip(dst=dst) / TCP(sport=sport, dport=port, flags=flags) for port in ports]


def connect_scan(ports):
    packets = []
    for port in ports:
        packets.append(_ip() / TCP(sport=TCP_SCANNER_PORT, dport=port, flags="S"))
        packets.append(_ip(src=TARGET, dst=SCANNER) / TCP(sport=port, dport=TCP_SCANNER_PORT, flags="SA"))
        packets.append(_ip() / TCP(sport=TCP_SCANNER_PORT, dport=port, flags="A"))
    return packets


def udp_scan(ports):
    return [_ip() / UDP(sport=UDP_SCANNER_PORT, dport=port) / Raw(b"probe") for port in ports]


def ack_scan_with_responses(ports):
    packets = tcp_scan(ports, flags="A")
    for port in ports:
        packets.append(_ip(src=TARGET, dst=SCANNER) / TCP(sport=port, dport=TCP_SCANNER_PORT, flags="R"))
    return packets


def tcp_host_sweep(targets: int = 3):
    return [_ip(dst=f"198.51.100.{index}") / TCP(sport=TCP_SCANNER_PORT, dport=443, flags="S")
            for index in (2, 3, 4)][:targets]


def dns_flood(queries: int = 55):
    packets = []
    for index in range(queries):
        # Distinct query payloads so capture-level duplicate suppression cannot
        # collapse the volume into a single observation.
        payload = b"\xab\xcd" + bytes([index % 256]) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + \
                  bytes([0x05]) + b"host" + bytes([index % 256]) + b"\x00\x00\x01\x00\x01"
        packets.append(_ip(dst="198.51.100.53") / UDP(sport=53000, dport=53) / Raw(payload))
    return packets


def masscan_style_syn_sweep(ports):
    """Masscan/RustScan-class wire pattern: raw SYN probes to many destination
    ports, randomized TCP source ports, single source address, no handshake."""
    return [_ip() / TCP(sport=10000 + (index % 60000), dport=port, flags="S")
            for index, port in enumerate(ports)]


def unicornscan_style_async_syn(ports):
    """Unicornscan-class wire pattern: async SYN probes plus the RST replies it
    correlates for closed ports."""
    packets = [_ip() / TCP(sport=31000 + index, dport=port, flags="S")
               for index, port in enumerate(ports)]
    for port in ports:
        packets.append(_ip(src=TARGET, dst=SCANNER) / TCP(sport=port, dport=31000, flags="RA"))
    return packets


def zmap_style_tcp_syn_sweep(hosts):
    """Zmap-class tcp_synscan wire pattern: one destination port, many hosts."""
    return [_ip(dst=f"198.51.100.{index}") / TCP(sport=49152 + index, dport=443, flags="S")
            for index in hosts]


def zmap_style_icmp_sweep(hosts):
    """Zmap-class icmp_echoscan wire pattern: echo requests across many hosts."""
    return [_ip(dst=f"198.51.100.{index}") / ICMP(type=8, id=9, seq=index)
            for index in hosts]


def angry_ip_style(hosts, ports):
    """Angry IP Scanner-class wire pattern: ICMP ping sweep across a range, then
    TCP probe (connect/SYN) on a small fixed port list for discovered hosts."""
    packets = [_ip(dst=f"198.51.100.{index}") / ICMP(type=8, id=10, seq=index)
               for index in hosts]
    for index, port in enumerate(ports):
        packets.append(_ip() / TCP(sport=41000 + index, dport=port, flags="S"))
    return packets


def http_path_traversal():
    return [_ip() / TCP(sport=40001, dport=80, flags="PA") /
            Raw(b"GET /cgi-bin/../../etc/passwd HTTP/1.1\r\nHost: lab\r\n\r\n")]


def brute_force_pattern(attempts: int = 32, flags="R"):
    return [_ip() / TCP(sport=42000 + index, dport=22, seq=index, flags=flags)
            for index in range(attempts)]


def tcp_anomaly_syn_fin():
    return [_ip() / TCP(sport=43000, dport=443, seq=99, flags="SF")]


def syn_flood_pattern(attempts: int = 100, port: int = 8080):
    """SYN-flood wire pattern: bare half-open SYNs from one source to one
    service endpoint, distinct source ports, no handshake completion."""
    return [_ip() / TCP(sport=46000 + index, dport=port, seq=index, flags="S")
            for index in range(attempts)]


def normal_traffic():
    return [
        _ip() / TCP(sport=45000, dport=443, flags="S"),
        _ip(src=TARGET, dst=SCANNER) / TCP(sport=443, dport=45000, flags="SA"),
        _ip() / TCP(sport=45000, dport=443, flags="A"),
        _ip(dst="198.51.100.53") / UDP(sport=53000, dport=53) / Raw(b"ordinary dns"),
        _ip() / TCP(sport=45001, dport=80, flags="PA") /
        Raw(b"GET /index.html HTTP/1.1\r\nHost: lab\r\n\r\n"),
        _ip() / TCP(sport=45002, dport=443, flags="FA"),
        _ip(src=TARGET, dst=SCANNER) / TCP(sport=443, dport=45002, flags="FA"),
    ]


def internet_browsing_public_destinations():
    """A private host opening connections to several *public* destinations.

    Regression case: pre-scope-fix detectors flagged this as "TCP host
    discovery sweep". Contacting multiple ordinary Internet destinations is
    client egress, not host discovery.
    """
    return [_ip(dst="142.250.183.170") / TCP(sport=45001 + index, dport=443, flags="S")
            for index in range(3)]


def gateway_arp_neighbor_resolution():
    """A gateway ARPing a handful of neighbors (normal L2 resolution)."""
    return [Ether(src="02:00:00:00:00:fe", dst="ff:ff:ff:ff:ff:ff") /
            ARP(psrc="192.168.68.1", pdst=f"192.168.68.{host}", op=1)
            for host in (103, 150, 200)]


def single_ping():
    return [_ip() / ICMP(type=8, id=1, seq=1)]


# ---------------------------------------------------------------------------
# Matrix runner
# ---------------------------------------------------------------------------

class Recorder:
    """In-memory alert sink used by matrix rows (no persistence required)."""
    session = None

    def __init__(self):
        self.alerts = []
        self.traffic = []

    def log_traffic(self, packet):
        self.traffic.append(packet)
        return None

    def log_alert(self, alert):
        self.alerts.append(alert)


HTTP_TEST_RULES = [
    {
        "gid": 1, "sid": 700001, "rev": 1, "action": "ALERT", "protocol": "TCP",
        "dst_port": 80, "content": "/etc/passwd", "nocase": False,
        "severity": "HIGH", "priority": 1, "classification": "web-attack",
        "message": "HTTP path traversal target",
    }
]


def _engine_for(case: dict) -> DetectionEngine:
    """Real DetectionEngine when the case needs rules, otherwise a stub."""
    if case.get("rules"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "matrix-rules.json"
            path.write_text(json.dumps([{**rule, "rule_text": ""} for rule in case["rules"]]), encoding="utf-8")
            return DetectionEngine(str(path))
    engine = DetectionEngine.__new__(DetectionEngine)
    engine.analyze_packet = lambda packet: []
    return engine


def run_case(case: dict) -> dict:
    packets = case["packets"]()
    recorder = Recorder()
    engine = _engine_for(case)
    core = DeltaCore(recorder, engine, scan_window=case.get("scan_window", 30.0),
                     port_threshold=case.get("port_threshold", 8),
                     ping_threshold=case.get("ping_threshold", 3),
                     dns_threshold=case.get("dns_threshold", 50),
                     brute_force_threshold=case.get("brute_force_threshold", 30))
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "matrix-case.pcap"
        wrpcap(str(path), packets)
        capture = PacketCapture(core.process_packet, pcap_path=str(path))
        capture.run()

    alert_sids = [int(alert.get("sid", 0)) for alert in recorder.alerts]
    expected = set(case["expected_sids"])
    unexpected = [sid for sid in alert_sids if sid not in expected]
    captured = capture.packets_seen > 0
    if expected:
        detected = any(sid in expected for sid in alert_sids)
        ok = detected and not unexpected and captured
    else:
        # Negative-control case: the expected outcome is that nothing alerts.
        detected = False
        ok = not alert_sids and captured
    evidence_checks = case.get("assert_evidence", [])
    missing_evidence = [text for text in evidence_checks
                        if not any(text in str(alert.get("evidence", "")) for alert in recorder.alerts)]
    if ok:
        ok = not missing_evidence
    result = "PASS" if ok else "FAIL"
    return {
        "test": case["name"],
        "expected": case["expected"],
        "packets_generated": len(packets),
        "packets_captured": capture.packets_seen,
        "packets_failed": capture.packets_failed,
        "detected": detected,
        "alert_sids": alert_sids,
        "expected_sids": sorted(expected),
        "false_positive_sids": unexpected,
        "missing_evidence": missing_evidence,
        "result": result,
    }


def build_matrix() -> list[dict]:
    scan_ports = list(range(2001, 2001 + 8))
    return [
        {"name": "ICMP echo (single target, repeated)", "expected": "One INFO visibility event per window, not one per ping",
         "packets": lambda: icmp_echo_same_target(), "expected_sids": [90001]},
        {"name": "ICMP host sweep", "expected": "Per-target visibility events plus host discovery sweep",
         "packets": icmp_sweep, "expected_sids": [90001, 90002], "ping_threshold": 3},
        {"name": "TCP SYN scan", "expected": "High port scan on distinct destination ports",
         "packets": lambda: tcp_scan(scan_ports), "expected_sids": [90003]},
        {"name": "TCP connect scan (full handshake)", "expected": "SYN probes across ports classified as SYN scan",
         "packets": lambda: connect_scan(scan_ports), "expected_sids": [90003]},
        {"name": "UDP scan", "expected": "High UDP port scan on distinct destination ports",
         "packets": lambda: udp_scan(scan_ports), "expected_sids": [90003]},
        {"name": "TCP ACK scan with responses", "expected": "Possible ACK scan (requires RST response evidence)",
         "packets": lambda: ack_scan_with_responses(scan_ports), "expected_sids": [90003]},
        {"name": "TCP FIN scan", "expected": "High FIN port scan on distinct destination ports",
         "packets": lambda: tcp_scan(scan_ports, flags="F"), "expected_sids": [90003]},
        {"name": "TCP NULL scan", "expected": "High NULL port scan on distinct destination ports",
         "packets": lambda: tcp_scan(scan_ports, flags=""), "expected_sids": [90003]},
        {"name": "TCP Xmas scan", "expected": "High Xmas port scan on distinct destination ports",
         "packets": lambda: tcp_scan(scan_ports, flags="FPU"), "expected_sids": [90003]},
        {"name": "TCP host discovery sweep", "expected": "Host discovery sweep across distinct targets",
         "packets": tcp_host_sweep, "expected_sids": [90002], "ping_threshold": 3},
        {"name": "DNS query-rate anomaly", "expected": "High DNS query rate from one source",
         "packets": dns_flood, "expected_sids": [90004]},
        {"name": "HTTP path traversal (content rule)", "expected": "Signature alert from the real rule engine",
         "packets": http_path_traversal, "expected_sids": [700001], "rules": HTTP_TEST_RULES},
        {"name": "Repeated connection failures (brute-force-like)", "expected": "Repeated RST/FIN closures toward one service",
         "packets": brute_force_pattern, "expected_sids": [90005]},
        {"name": "Invalid TCP flag combination (SYN+FIN)", "expected": "Protocol anomaly for invalid flags",
         "packets": tcp_anomaly_syn_fin, "expected_sids": [90006]},
        {"name": "TCP SYN flood (half-open attempts at one endpoint)", "expected": "High rate of bare half-open SYN attempts toward one service",
         "packets": syn_flood_pattern, "expected_sids": [90014],
         "assert_evidence": ["half_open_syn_attempts=100"]},
        {"name": "Masscan-style SYN sweep (full port range, random src ports)", "expected": "SYN port scan; evidence stays bounded at full-port scale",
         "packets": lambda: masscan_style_syn_sweep(range(2001, 2201)), "expected_sids": [90003],
         "port_threshold": 150,
         "assert_evidence": ["distinct_destination_ports=150", "(+54 more)"]},
        {"name": "RustScan-style fast SYN scan (full port range)", "expected": "SYN port scan; evidence stays bounded at full-port scale",
         "packets": lambda: masscan_style_syn_sweep(range(1, 301)), "expected_sids": [90003],
         "port_threshold": 250,
         "assert_evidence": ["distinct_destination_ports=250", "(+154 more)"]},
        {"name": "Unicornscan-style async SYN + response correlation", "expected": "SYN port scan with response evidence",
         "packets": lambda: unicornscan_style_async_syn(range(3001, 3017)), "expected_sids": [90003],
         "assert_evidence": ["probe_class=syn"]},
        {"name": "Zmap-style TCP SYN host sweep (one port, many hosts)", "expected": "Host discovery sweep; evidence stays bounded at subnet scale",
         "packets": lambda: zmap_style_tcp_syn_sweep(range(2, 82)), "expected_sids": [90002],
         "ping_threshold": 70,
         "assert_evidence": ["distinct_targets=70", "(+6 more)"]},
        {"name": "Zmap-style ICMP echo host sweep", "expected": "Visibility events plus host discovery sweep",
         "packets": lambda: zmap_style_icmp_sweep(range(2, 10)), "expected_sids": [90001, 90002],
         "ping_threshold": 8,
         "assert_evidence": ["distinct_targets=8"]},
        {"name": "Angry IP Scanner-style ping sweep + TCP probes", "expected": "Visibility events, host sweep, and TCP port scan",
         "packets": lambda: angry_ip_style(range(2, 8), [21, 22, 23, 80, 443, 445, 3389, 8080, 8443, 5900]),
         "expected_sids": [90001, 90002, 90003], "ping_threshold": 3},
        {"name": "Normal traffic (negatives)", "expected": "No alerts for ordinary single-shot traffic",
         "packets": normal_traffic, "expected_sids": []},
        {"name": "Internet browsing to public destinations (negatives)", "expected": "No host-discovery sweep for ordinary client egress",
         "packets": internet_browsing_public_destinations, "expected_sids": []},
        {"name": "Gateway neighbor ARP resolution (negatives)", "expected": "No host-discovery sweep for a few ARP requests",
         "packets": gateway_arp_neighbor_resolution, "expected_sids": []},
        {"name": "Single ICMP ping (negatives)", "expected": "INFO visibility event only, no sweep",
         "packets": single_ping, "expected_sids": [90001]},
    ]


def run_matrix() -> dict:
    rows = [run_case(case) for case in build_matrix()]
    passed = sum(1 for row in rows if row["result"] == "PASS")
    return {
        "mode": "offline-matrix",
        "generated_at_epoch": int(time.time()),
        "summary": {"rows": len(rows), "passed": passed, "failed": len(rows) - passed},
        "note": ("Offline PCAP replay only; not evidence of Npcap, VM, eth0, or live "
                 "dashboard behavior. 'Captured' means the packets were seen and "
                 "processed by the real Delta-NIDS capture pipeline."),
        "report": rows,
    }


# ---------------------------------------------------------------------------
# Single-file replay (kept for compatibility)
# ---------------------------------------------------------------------------

def run(pcap_path: str | None = None) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(pcap_path) if pcap_path else Path(directory) / "delta-local-validation.pcap"
        if not pcap_path:
            wrpcap(str(path), icmp_echo_same_target(3) + tcp_scan([21, 22, 23, 80, 443, 8080, 8443, 9000])[:8])
        database = Path(directory) / "validation.sqlite"
        manager = AlertManager(str(database), terminal=False, persist=True)
        engine = DetectionEngine("rules/rules.json", runtime_db_path=str(database))
        core = DeltaCore(manager, engine, port_threshold=3, ping_threshold=3)
        capture = PacketCapture(core.process_packet, pcap_path=str(path))
        capture.run()
        result = {
            "mode": "offline-pcap",
            "pcap": str(path),
            "packets_seen": capture.packets_seen,
            "packets_failed": capture.packets_failed,
            "packets_processed": core.packets_sniffed,
            "alerts": len(manager.get_recent_alerts()),
            "note": "Offline replay only; not evidence of Npcap, VM, eth0, or live dashboard behavior.",
        }
        manager.close()
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", help="replay an existing authorized PCAP instead of running the matrix harness")
    parser.add_argument("--json", action="store_true", help="print the matrix report as JSON only")
    args = parser.parse_args()
    if args.pcap:
        print(json.dumps(run(args.pcap), indent=2))
        return 0
    report = run_matrix()
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print(f"Delta-NIDS offline detection matrix ({report['summary']['rows']} cases, "
          f"{report['summary']['passed']} passed, {report['summary']['failed']} failed)")
    print(f"{'Test':<52}{'Pkts':>5}{'Cap':>5}  {'Detected':<9}{'SIDs':<34}{'FP SIDs':<12}Result")
    print("-" * 130)
    for row in report["report"]:
        print(f"{row['test'][:52]:<52}{row['packets_generated']:>5}{row['packets_captured']:>5}  "
              f"{str(row['detected']):<9}{str(row['alert_sids']):<34}{str(row['false_positive_sids']):<12}{row['result']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())