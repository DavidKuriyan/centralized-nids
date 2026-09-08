"""Unit tests for SPAN / Port Mirroring capture mode."""

import unittest
from unittest.mock import MagicMock
import time

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, Dot1Q, Raw

from core.packet_capture import PacketCapture
from main import build_parser


class TestSpanCapture(unittest.TestCase):
    def test_cli_parser_capture_mode_default(self):
        parser = build_parser()
        args = parser.parse_args(["-i", "eth0"])
        self.assertEqual(args.capture_mode, "normal")
        self.assertFalse(args.no_promiscuous)
        self.assertEqual(args.snap_length, 65535)

    def test_cli_parser_capture_mode_span(self):
        parser = build_parser()
        args = parser.parse_args(["-i", "eth0", "--capture-mode", "span", "--snap-length", "9216", "--buffer-size", "33554432"])
        self.assertEqual(args.capture_mode, "span")
        self.assertEqual(args.snap_length, 9216)
        self.assertEqual(args.buffer_size, 33554432)

    def test_span_mode_initialization(self):
        handler = MagicMock()
        capture = PacketCapture(on_packet=handler, interface="eth0", capture_mode="span")
        self.assertEqual(capture.capture_mode, "span")
        self.assertTrue(capture.promiscuous)
        self.assertEqual(capture.snap_length, 65535)
        self.assertEqual(capture._duplicate_window_seconds, 2.0)

    def test_normal_mode_initialization(self):
        handler = MagicMock()
        capture = PacketCapture(on_packet=handler, interface="eth0", capture_mode="normal", promiscuous=False)
        self.assertEqual(capture.capture_mode, "normal")
        self.assertFalse(capture.promiscuous)
        self.assertEqual(capture._duplicate_window_seconds, 1.0)

    def test_span_protocol_accounting(self):
        handler = MagicMock()
        capture = PacketCapture(on_packet=handler, interface="eth0", capture_mode="span")

        # Ingest IPv4 TCP
        pkt_tcp = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=80)
        capture._dispatch(pkt_tcp)

        # Ingest IPv6 UDP
        pkt_udp = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=5353, dport=53)
        capture._dispatch(pkt_udp)

        # Ingest VLAN packet
        pkt_vlan = Ether() / Dot1Q(vlan=100) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        capture._dispatch(pkt_vlan)

        stats = capture.capture_statistics()
        self.assertEqual(stats["packets_seen"], 3)
        self.assertEqual(stats["ipv4_packets"], 2)
        self.assertEqual(stats["ipv6_packets"], 1)
        self.assertEqual(stats["tcp_packets"], 1)
        self.assertEqual(stats["udp_packets"], 1)
        self.assertEqual(stats["icmp_packets"], 1)
        self.assertEqual(stats["vlan_packets"], 1)
        self.assertEqual(stats["capture_mode"], "span")

    def test_span_duplicate_filtering(self):
        handler = MagicMock()
        capture = PacketCapture(on_packet=handler, interface="eth0", capture_mode="span")

        pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.20", id=42) / TCP(sport=12345, dport=80, seq=100) / Raw(b"test payload")

        # First packet should be forwarded
        capture._dispatch(pkt)
        self.assertEqual(handler.call_count, 1)

        # Exact duplicate packet arriving immediately should be deduplicated in SPAN mode
        capture._dispatch(pkt)
        self.assertEqual(handler.call_count, 1)
        self.assertEqual(capture.duplicate_count, 1)


if __name__ == "__main__":
    unittest.main()
