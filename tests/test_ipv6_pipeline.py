"""Unit tests for the IPv6 packet parsing, normalization, and detection pipeline."""

import unittest
from unittest.mock import MagicMock
from scapy.all import (
    Ether, IPv6, TCP, UDP, Raw,
    IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, IPv6ExtHdrFragment,
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6EchoRequest
)

from core.packet_capture import packet_to_info
from core.alert_manager import format_endpoint
from core.delta_core import DeltaCore


class TestIPv6Pipeline(unittest.TestCase):
    def test_ipv6_tcp_packet_to_info(self):
        pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=54321, dport=80, flags="S") / Raw(b"GET / HTTP/1.1\r\n\r\n")
        info = packet_to_info(pkt)
        self.assertIsNotNone(info)
        self.assertEqual(info["src_ip"], "2001:db8::1")
        self.assertEqual(info["dst_ip"], "2001:db8::2")
        self.assertEqual(info["protocol"], "TCP")
        self.assertEqual(info["src_port"], 54321)
        self.assertEqual(info["dst_port"], 80)
        self.assertEqual(info["ip_version"], 6)
        self.assertEqual(info["source"], "[2001:db8::1]:54321")
        self.assertEqual(info["destination"], "[2001:db8::2]:80")

    def test_ipv6_udp_packet_to_info(self):
        pkt = Ether() / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=5353, dport=5353)
        info = packet_to_info(pkt)
        self.assertIsNotNone(info)
        self.assertEqual(info["src_ip"], "fe80::1")
        self.assertEqual(info["dst_ip"], "fe80::2")
        self.assertEqual(info["protocol"], "UDP")
        self.assertEqual(info["src_port"], 5353)
        self.assertEqual(info["dst_port"], 5353)
        self.assertEqual(info["ip_version"], 6)

    def test_ipv6_icmpv6_echo_request(self):
        pkt = Ether() / IPv6(src="2001:db8::10", dst="2001:db8::20") / ICMPv6EchoRequest()
        info = packet_to_info(pkt)
        self.assertIsNotNone(info)
        self.assertEqual(info["protocol"], "ICMPV6")
        self.assertEqual(info["ip_version"], 6)
        self.assertIsNone(info["src_port"])
        self.assertIsNone(info["dst_port"])

    def test_ipv6_extension_headers(self):
        pkt = (
            Ether() /
            IPv6(src="2001:db8::100", dst="2001:db8::200") /
            IPv6ExtHdrHopByHop() /
            IPv6ExtHdrRouting() /
            TCP(sport=8080, dport=9090, flags="A")
        )
        info = packet_to_info(pkt)
        self.assertIsNotNone(info)
        self.assertEqual(info["src_ip"], "2001:db8::100")
        self.assertEqual(info["dst_ip"], "2001:db8::200")
        self.assertEqual(info["protocol"], "TCP")
        self.assertEqual(info["src_port"], 8080)
        self.assertEqual(info["dst_port"], 9090)

    def test_format_endpoint_ipv6(self):
        self.assertEqual(format_endpoint("2001:db8::1", 443), "[2001:db8::1]:443")
        self.assertEqual(format_endpoint("2001:db8::1", None), "[2001:db8::1]")
        self.assertEqual(format_endpoint("192.168.1.1", 80), "192.168.1.1:80")
        self.assertEqual(format_endpoint("192.168.1.1", None), "192.168.1.1")
        self.assertEqual(format_endpoint(None), "-")

    def test_icmpv6_nd_filtered_from_port_scan(self):
        mock_alerts = MagicMock()
        mock_engine = MagicMock()
        core = DeltaCore(alert_manager=mock_alerts, detection_engine=mock_engine, port_threshold=3, ping_threshold=3)
        # Neighbor solicitation packets should not trigger host sweep / port scan
        ns_pkt = {
            "timestamp": 1000.0,
            "src_ip": "fe80::1",
            "dst_ip": "ff02::1:ff00:2",
            "protocol": "ICMPV6",
            "src_port": None,
            "dst_port": None,
            "length": 64,
            "flags": "",
            "icmpv6_nd": True,
            "ip_version": 6,
        }
        for _ in range(5):
            core.process_packet(ns_pkt)
        self.assertEqual(mock_alerts.log_alert.call_count, 0)


if __name__ == "__main__":
    unittest.main()
