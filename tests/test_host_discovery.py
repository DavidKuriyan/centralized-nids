import unittest
import time

from core.delta_core import DeltaCore


class RecordingAlerts:
    session = None

    def __init__(self):
        self.alerts = []
        self.traffic = []

    def log_traffic(self, packet):
        self.traffic.append(packet)
        return None

    def log_alert(self, alert):
        self.alerts.append(alert)


class _Engine:
    def analyze_packet(self, packet):
        return []

    def refresh_if_changed(self):
        return False


def _packet(src, dst, protocol="TCP", **extra):
    base = {"src_ip": src, "dst_ip": dst, "protocol": protocol, "length": 60,
            "icmp_type": None, "icmp_code": None, "tcp_flags": None, "payload": b"",
            "details": {}}
    base.update(extra)
    return base


def _run(packets, **kwargs):
    recorder = RecordingAlerts()
    core = DeltaCore(recorder, _Engine(), **kwargs)
    for packet in packets:
        core.process_packet(packet)
    return recorder.alerts


class NormalTrafficNegativeTests(unittest.TestCase):
    """Ordinary single-shot traffic must never produce a host-discovery sweep."""

    def test_single_arp_request_is_not_a_sweep(self):
        alerts = _run([_packet("192.168.68.110", "192.168.68.1", "ARP",
                               details={"arp_op": 1})])
        self.assertEqual([a["sid"] for a in alerts], [])

    def test_normal_arp_resolution_of_few_neighbors_is_not_a_sweep(self):
        # A gateway ARPing a handful of neighbors inside the window (the exact
        # false-positive from the incident) is ordinary resolution.
        packets = [_packet("192.168.68.1", "192.168.68.103", "ARP", details={"arp_op": 1}),
                   _packet("192.168.68.1", "192.168.68.150", "ARP", details={"arp_op": 1}),
                   _packet("192.168.68.1", "192.168.68.200", "ARP", details={"arp_op": 1})]
        alerts = _run(packets)
        self.assertEqual([a["sid"] for a in alerts], [])

    def test_single_icmp_ping_is_only_informational(self):
        alerts = _run([_packet("192.168.68.1", "192.168.68.112", "ICMP", icmp_type=8)])
        self.assertEqual([a["sid"] for a in alerts], [90001])

    def test_normal_tcp_syn_connection_to_one_target_is_not_a_sweep(self):
        alerts = _run([_packet("192.168.68.110", "192.168.68.20", "TCP",
                               src_port=50000, dst_port=443, tcp_flags="S")])
        self.assertEqual([a["sid"] for a in alerts], [])

    def test_normal_https_browsing_to_three_public_destinations_is_not_a_sweep(self):
        # The exact false-positive pattern: a private host opening connections
        # to multiple *Internet* destinations must not be host discovery.
        packets = [_packet("192.168.68.112", "142.250.183.170", "TCP", src_port=50000, dst_port=443, tcp_flags="S"),
                   _packet("192.168.68.112", "142.250.183.171", "TCP", src_port=50001, dst_port=443, tcp_flags="S"),
                   _packet("192.168.68.112", "142.250.183.172", "TCP", src_port=50002, dst_port=443, tcp_flags="S")]
        alerts = _run(packets)
        self.assertEqual([a["sid"] for a in alerts], [])

    def test_normal_internet_traffic_with_completed_handshake_is_not_a_sweep(self):
        packets = [
            _packet("192.168.68.110", "172.192.176.118", "TCP", src_port=40000, dst_port=443, tcp_flags="S"),
            _packet("172.192.176.118", "192.168.68.110", "TCP", src_port=443, dst_port=40000, tcp_flags="SA"),
            _packet("192.168.68.110", "172.192.176.118", "TCP", src_port=40000, dst_port=443, tcp_flags="A"),
            _packet("192.168.68.110", "198.51.100.53", "UDP", src_port=53000, dst_port=53, payload=b"dns"),
        ]
        alerts = _run(packets)
        self.assertEqual([a["sid"] for a in alerts], [])

    def test_normal_dns_queries_are_not_host_discovery(self):
        alerts = _run([_packet("192.168.68.110", "8.8.8.8", "UDP", src_port=53000, dst_port=53, payload=b"q"),
                       _packet("8.8.8.8", "192.168.68.110", "UDP", src_port=53, dst_port=53000, payload=b"r")])
        self.assertEqual([a["sid"] for a in alerts], [])

    def test_retransmitted_probe_to_same_target_does_not_inflate(self):
        # Retransmissions and duplicate packets must not multiply the target
        # count: many packets to ONE target never satisfy the threshold.
        packets = [_packet("192.168.68.110", "192.168.68.20", "TCP", src_port=50000, dst_port=445, tcp_flags="S")
                   for _ in range(12)]
        alerts = _run(packets, ping_threshold=5)
        self.assertEqual([a["sid"] for a in alerts], [])

    def test_different_ports_same_host_is_port_scan_not_host_sweep(self):
        # Multiple services on ONE host are port scanning, not host discovery.
        packets = [_packet("192.168.68.110", "192.168.68.20", "TCP", src_port=50000, dst_port=port, tcp_flags="S")
                   for port in (21, 22, 80, 443, 445, 3389)]
        alerts = _run(packets, ping_threshold=5)
        self.assertEqual([a["sid"] for a in alerts], [])


class ActualDiscoveryTests(unittest.TestCase):
    """Controlled multi-target traffic must trigger SID 90002."""

    def test_tcp_same_port_sweep_across_local_hosts(self):
        packets = [_packet("192.168.68.110", f"192.168.68.{host}", "TCP", src_port=40000, dst_port=445, tcp_flags="S")
                   for host in range(20, 30)]
        alerts = _run(packets, ping_threshold=5)
        sweep = [a for a in alerts if a["sid"] == 90002]
        self.assertEqual(len(sweep), 1)
        self.assertEqual(sweep[0]["severity"], "High")
        # Streamed emission: the alert fires the moment the 5th distinct
        # target is observed, and the evidence records the actual count.
        self.assertIn("distinct_targets=5", sweep[0]["evidence"])
        self.assertIn("scope=local", sweep[0]["evidence"])
        self.assertIn("detection_type=host_discovery", sweep[0]["evidence"])
        # Target list reflects exactly the targets that were counted.
        self.assertIn("192.168.68.24", sweep[0]["evidence"])

    def test_arp_requests_never_trigger_host_discovery_sweep(self):
        # The ARP host-discovery sweep rule was removed: ARP request bursts
        # (even many targets) are gateway/neighbor L2 housekeeping, not scans,
        # so ARP must never produce a SID 90002 host-discovery sweep.
        packets = [_packet("192.168.68.110", f"192.168.68.{host}", "ARP", details={"arp_op": 1})
                   for host in range(20, 40)]
        alerts = _run(packets)
        self.assertEqual([a["sid"] for a in alerts], [])

    def test_icmp_echo_sweep_across_local_hosts(self):
        packets = [_packet("192.168.68.110", f"192.168.68.{host}", "ICMP", icmp_type=8)
                   for host in range(20, 30)]
        alerts = _run(packets, ping_threshold=5)
        sweep = [a for a in alerts if a["sid"] == 90002]
        self.assertEqual(len(sweep), 1)
        self.assertIn("scope=local", sweep[0]["evidence"])

    def test_multiple_targets_within_window_trigger_once_per_window(self):
        now = time.monotonic()
        packets = []
        for host in range(20, 26):
            packets.append(_packet("192.168.68.110", f"192.168.68.{host}", "TCP",
                                   src_port=40000, dst_port=22, tcp_flags="S", _monotonic=now))
        alerts = _run(packets, ping_threshold=5)
        sweep = [a for a in alerts if a["sid"] == 90002]
        self.assertEqual(len(sweep), 1)

    def test_targets_in_private_documentation_space_still_count(self):
        # Scanning private documentation ranges (as used by the offline matrix)
        # is still host-discovery evidence because it is not Internet egress.
        packets = [_packet("192.0.2.1", f"198.51.100.{host}", "TCP", src_port=40000, dst_port=443, tcp_flags="S")
                   for host in range(2, 9)]
        alerts = _run(packets, ping_threshold=3)
        sweep = [a for a in alerts if a["sid"] == 90002]
        self.assertEqual(len(sweep), 1)

    def test_window_expiry_prevents_stale_correlation(self):
        # Probes far outside the window must not combine into a sweep.
        packets = [
            _packet("192.168.68.110", "192.168.68.20", "TCP", src_port=40000, dst_port=80, tcp_flags="S", _monotonic=1.0),
            _packet("192.168.68.110", "192.168.68.21", "TCP", src_port=40001, dst_port=80, tcp_flags="S", _monotonic=1.1),
            _packet("192.168.68.110", "192.168.68.22", "TCP", src_port=40002, dst_port=80, tcp_flags="S", _monotonic=1.2),
            _packet("192.168.68.110", "192.168.68.23", "TCP", src_port=40003, dst_port=80, tcp_flags="S", _monotonic=500.0),
        ]
        alerts = _run(packets, ping_threshold=4, scan_window=30.0)
        self.assertEqual([a["sid"] for a in alerts], [])


if __name__ == "__main__":
    unittest.main()