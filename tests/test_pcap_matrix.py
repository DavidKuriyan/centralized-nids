import tempfile
import unittest
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, wrpcap

from core.delta_core import DeltaCore
from core.packet_capture import PacketCapture
from core.detection_engine import DetectionEngine


class Recorder:
    session = None

    def __init__(self):
        self.alerts = []
        self.traffic = []

    def log_traffic(self, packet):
        self.traffic.append(packet)
        return None

    def log_alert(self, alert):
        self.alerts.append(alert)


class PcapMatrixTests(unittest.TestCase):
    def run_packets(self, packets, **kwargs):
        recorder = Recorder()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case.pcap"
            wrpcap(str(path), packets)
            capture = PacketCapture(core.process_packet, pcap_path=str(path))
            capture.run()
        return capture, core, recorder

    def test_empty_and_normal_tcp_udp(self):
        capture, core, recorder = self.run_packets([])
        self.assertEqual((capture.packets_seen, core.packets_sniffed, len(recorder.alerts)), (0, 0, 0))
        packets = [Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=40000, dport=80),
                   Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / UDP(sport=53000, dport=53) / Raw(b"dns")]
        capture, core, recorder = self.run_packets(packets)
        self.assertEqual((capture.packets_seen, core.packets_sniffed, len(recorder.traffic)), (2, 2, 2))
        self.assertEqual(recorder.alerts, [])

    def test_duplicate_packets_do_not_inflate_port_scan(self):
        packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / UDP(sport=53000, dport=53)
        _, core, recorder = self.run_packets([packet] * 20, port_threshold=3)
        self.assertEqual(len(recorder.alerts), 0)
        self.assertEqual(len(core.flows), 1)

    def test_distinct_ports_trigger_scan(self):
        packets = [Ether() / IP(src="203.0.113.1", dst="198.51.100.1") /
                   TCP(sport=40000, dport=port) for port in (20, 21, 22)]
        _, _, recorder = self.run_packets(packets, port_threshold=3)
        self.assertEqual(len(recorder.alerts), 1)
        self.assertEqual(recorder.alerts[0]["sid"], 90003)

    def test_icmp_sweep_triggers_once(self):
        packets = [Ether() / IP(src="203.0.113.1", dst=f"198.51.100.{index}") /
                   ICMP(type=8) for index in (1, 2, 3)]
        _, _, recorder = self.run_packets(packets, ping_threshold=3)
        self.assertEqual([item["sid"] for item in recorder.alerts], [90001, 90001, 90001, 90002])

    def test_truncated_packet_is_ignored_without_crash(self):
        # A raw byte payload models a truncated Ethernet frame without asking
        # Scapy to dissect an invalid constructor payload.
        _, core, recorder = self.run_packets([b"\x00" * 10])
        self.assertEqual(core.packets_sniffed, 0)
        self.assertEqual(recorder.alerts, [])


if __name__ == "__main__":
    unittest.main()
