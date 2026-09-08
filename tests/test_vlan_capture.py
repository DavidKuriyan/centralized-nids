"""Unit tests for 802.1Q / QinQ VLAN tag stripping and extraction in capture pipeline."""

import unittest
from scapy.all import Ether, Dot1Q, IP, IPv6, TCP, UDP, Raw

from core.packet_capture import packet_to_info


class TestVlanCapture(unittest.TestCase):
    def test_single_vlan_tagged_packet(self):
        pkt = (
            Ether() /
            Dot1Q(vlan=100, prio=3) /
            IP(src="10.10.10.5", dst="10.20.20.5") /
            TCP(sport=3000, dport=80, flags="S") /
            Raw(b"GET / HTTP/1.1\r\n\r\n")
        )
        info = packet_to_info(pkt)
        self.assertIsNotNone(info)
        self.assertEqual(info["vlan_id"], 100)
        self.assertEqual(info["src_ip"], "10.10.10.5")
        self.assertEqual(info["dst_ip"], "10.20.20.5")
        self.assertEqual(info["src_port"], 3000)
        self.assertEqual(info["dst_port"], 80)
        self.assertEqual(info["protocol"], "TCP")

    def test_double_vlan_qinq_packet(self):
        # Outer VLAN 200, Inner VLAN 100
        pkt = (
            Ether() /
            Dot1Q(vlan=200, prio=5) /
            Dot1Q(vlan=100, prio=2) /
            IP(src="172.16.1.1", dst="172.16.1.2") /
            UDP(sport=53, dport=5353)
        )
        info = packet_to_info(pkt)
        self.assertIsNotNone(info)
        # Inner VLAN or primary VLAN should be preserved
        self.assertIn(info["vlan_id"], [100, 200])
        self.assertEqual(info["src_ip"], "172.16.1.1")
        self.assertEqual(info["dst_ip"], "172.16.1.2")
        self.assertEqual(info["protocol"], "UDP")

    def test_untagged_packet_vlan_id_is_none(self):
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1000, dport=2000)
        info = packet_to_info(pkt)
        self.assertIsNotNone(info)
        self.assertIsNone(info.get("vlan_id"))

    def test_vlan_tagged_ipv6_packet(self):
        pkt = (
            Ether() /
            Dot1Q(vlan=400) /
            IPv6(src="2001:db8::10", dst="2001:db8::20") /
            TCP(sport=443, dport=12345)
        )
        info = packet_to_info(pkt)
        self.assertIsNotNone(info)
        self.assertEqual(info["vlan_id"], 400)
        self.assertEqual(info["src_ip"], "2001:db8::10")
        self.assertEqual(info["dst_ip"], "2001:db8::20")
        self.assertEqual(info["ip_version"], 6)


if __name__ == "__main__":
    unittest.main()
