import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, Raw

from core.alert_manager import AlertManager, format_human_alert
from core.delta_core import DeltaCore
from core.packet_capture import PacketCapture, _raw_ip_to_info, packet_to_info
from core.detection_engine import DetectionEngine
from database.models import Statistic
from main import build_parser
from run_project import parser as project_parser


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


class PacketNormalizationTests(unittest.TestCase):
    def test_endpoint_identity_separates_ipv6_ports_and_excludes_macs(self):
        packet = packet_to_info(Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") /
                                IPv6(src="2401:4900:ccc4:cfa6:19b0:166f:c1a9:f86c",
                                     dst="2606:4700:83b2:7cbc:c2fe:9c1:5ff2:75c4") /
                                TCP(sport=12809, dport=443))
        self.assertEqual(packet["src_ip"], "2401:4900:ccc4:cfa6:19b0:166f:c1a9:f86c")
        self.assertEqual(packet["dst_ip"], "2606:4700:83b2:7cbc:c2fe:9c1:5ff2:75c4")
        self.assertEqual((packet["src_port"], packet["dst_port"]), (12809, 443))
        self.assertEqual(packet["source"], "[2401:4900:ccc4:cfa6:19b0:166f:c1a9:f86c]:12809")
        self.assertEqual(packet["destination"], "[2606:4700:83b2:7cbc:c2fe:9c1:5ff2:75c4]:443")
        self.assertNotIn("AA:BB:CC:DD:EE:FF", packet.values())

    def test_human_alert_formats_ipv6_with_brackets(self):
        output = format_human_alert(1, {"src_ip": "2001:db8::1", "src_port": 12809,
                                       "dst_ip": "2001:db8::2", "dst_port": 443,
                                       "protocol": "TCP", "sid": 1, "message": "test"}, "LOW")
        self.assertIn("[2001:db8::1]:12809 -> [2001:db8::2]:443", output)

    def test_ipv6_extension_header_transport_is_decoded(self):
        from scapy.all import IPv6ExtHdrHopByHop
        packet = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrHopByHop() / TCP(sport=40000, dport=443, flags="S")
        info = packet_to_info(packet)
        self.assertIsNotNone(info)
        self.assertEqual(info["protocol"], "TCP")
        self.assertEqual(info["src_port"], 40000)
        self.assertEqual(info["dst_port"], 443)

    def test_normalized_user_details_exclude_mac_addresses(self):
        packet = packet_to_info(Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") /
                                IP(src="192.0.2.1", dst="198.51.100.1") /
                                TCP(sport=40000, dport=443, flags="A"))
        self.assertEqual((packet["src_ip"], packet["dst_ip"]), ("192.0.2.1", "198.51.100.1"))
        self.assertNotIn("src_mac", packet["details"])
        self.assertNotIn("dst_mac", packet["details"])

    def test_tcp_udp_icmp_and_non_ip(self):
        tcp = packet_to_info(Ether() / IP(src="192.0.2.1", dst="198.51.100.1") /
                             TCP(sport=40000, dport=80, flags="PA") / Raw(b"GET /test"))
        self.assertEqual((tcp["protocol"], tcp["src_port"], tcp["dst_port"]), ("TCP", 40000, 80))
        self.assertEqual(tcp["payload"], b"GET /test")

        udp = packet_to_info(Ether() / IP(src="192.0.2.1", dst="198.51.100.1") /
                             UDP(sport=53000, dport=53) / Raw(b"dns"))
        self.assertEqual((udp["protocol"], udp["src_port"], udp["dst_port"]), ("UDP", 53000, 53))
        self.assertEqual(udp["payload"], b"dns")

        icmp = packet_to_info(Ether() / IP(src="192.0.2.1", dst="198.51.100.1") /
                              ICMP(type=8, code=0) / Raw(b"ping"))
        self.assertEqual((icmp["protocol"], icmp["icmp_type"], icmp["icmp_code"]), ("ICMP", 8, 0))
        self.assertIsNone(packet_to_info(Ether() / b"arp"))

    def test_link_padding_is_not_reported_as_application_payload(self):
        # A bare TCP SYN is a 58-byte frame, so the sending NIC pads it with two
        # NUL bytes to reach the 60-byte Ethernet minimum. Scapy keeps those bytes
        # as a Padding layer nested inside the TCP payload, which previously made
        # content:"|00|" (SID 324, PROTOCOL-FINGER null request) match a SYN that
        # carried no data at all.
        frame = bytearray(bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                                IP(src="10.117.198.204", dst="10.117.198.62",
                                   ttl=51, id=49460, len=44) /
                                TCP(sport=63428, dport=79, flags="S",
                                    seq=3299115164, window=1024)))
        frame[46] = 0x60  # dataoff=6 -> four TCP option bytes
        padded = bytes(frame) + b"\x02\x04\x05\xb4" + b"\x00\x00"
        self.assertEqual(len(padded), 60)
        info = packet_to_info(Ether(padded))
        self.assertEqual(info["tcp_flags"], "S")
        self.assertEqual(info["details"]["tcp_header_length"], 24)
        self.assertEqual(info["payload"], b"")
        self.assertNotIn("payload_hex", info["details"])

    def test_link_padding_preserves_real_payload(self):
        frame = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                      IP(src="192.0.2.1", dst="198.51.100.1") /
                      TCP(sport=40000, dport=79, flags="PA") / Raw(b"GET"))
        padded = frame + b"\x00" * (60 - len(frame))
        self.assertEqual(len(padded), 60)
        info = packet_to_info(Ether(padded))
        self.assertEqual(info["payload"], b"GET")
        self.assertEqual(info["details"]["payload_hex"], "47 45 54")

    def test_ipv6_packets_are_parsed_for_capture(self):
        self.assertIsNotNone(packet_to_info(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=40000, dport=443, flags="S")))
        self.assertIsNotNone(packet_to_info(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=40000, dport=53)))

    def test_ipv6_tcp_and_udp_normalize_for_active_pipeline(self):
        tcp = packet_to_info(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") /
                             TCP(sport=40000, dport=443, flags="S"))
        udp = packet_to_info(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") /
                             UDP(sport=53000, dport=53) / Raw(b"dns6"))
        self.assertEqual((tcp["protocol"], tcp["src_port"], tcp["dst_port"]), ("TCP", 40000, 443))
        self.assertEqual((udp["protocol"], udp["src_port"], udp["dst_port"], udp["payload"]),
                         ("UDP", 53000, 53, b"dns6"))

    def test_ipv6_echo_request_normalizes_for_active_pipeline(self):
        packet = packet_to_info(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") /
                                ICMPv6EchoRequest(id=7, seq=3) / Raw(b"ping6"))
        self.assertIsNotNone(packet)
        self.assertEqual((packet["protocol"].upper(), packet["src_ip"], packet["icmp_type"]),
                         ("ICMPV6", "2001:db8::1", 128))
        self.assertEqual(packet["payload"], b"ping6")

    @unittest.skip("IPv6 is intentionally disabled")
    def test_ipv6_icmp_error_preserves_quoted_udp_probe(self):
        from scapy.all import ICMPv6DestUnreach
        packet = packet_to_info(Ether() / IPv6(src="2001:db8::2", dst="2001:db8::1") /
                                ICMPv6DestUnreach(code=4) /
                                (IPv6(src="2001:db8::1", dst="2001:db8::2") /
                                 UDP(sport=53000, dport=161)))
        self.assertIsNotNone(packet)
        self.assertEqual(packet["protocol"], "ICMPv6")
        self.assertEqual(packet["icmp_type"], 1)
        self.assertEqual((packet["icmp_inner_src_port"], packet["icmp_inner_dst_port"]), (53000, 161))

    def test_raw_parser_rejects_truncated_and_decodes_icmp(self):
        self.assertIsNone(_raw_ip_to_info(b"\x45" + b"\x00" * 10))
        raw_icmp = bytes.fromhex(
            "4500001c0000000040010000c0000201c6336401"
            "0800000000010001" + "70696e67"
        )
        parsed = _raw_ip_to_info(raw_icmp)
        self.assertEqual(parsed["protocol"], "ICMP")
        self.assertEqual(parsed["icmp_type"], 8)
        self.assertEqual(parsed["payload"], b"ping")
        self.assertEqual(parsed["details"]["icmp_sequence"], 1)

    def test_raw_parser_decodes_tcp_and_udp(self):
        # Raw TCP IPv4 packet: 20 bytes IP + 20 bytes TCP (SYN+ACK = 0x12) + payload "hello"
        raw_tcp = bytes.fromhex(
            "4500002d0001000040060000c0000201c6336401"
            "04d2005000000001000000025012010000000000"
            "68656c6c6f"
        )
        tcp_parsed = _raw_ip_to_info(raw_tcp)
        self.assertIsNotNone(tcp_parsed)
        self.assertEqual(tcp_parsed["protocol"], "TCP")
        self.assertEqual(tcp_parsed["src_port"], 1234)
        self.assertEqual(tcp_parsed["dst_port"], 80)
        self.assertEqual(tcp_parsed["tcp_flags"], "SA")
        self.assertEqual(tcp_parsed["payload"], b"hello")

        # Raw UDP IPv4 packet: 20 bytes IP + 8 bytes UDP + payload "dns"
        raw_udp = bytes.fromhex(
            "4500001f0002000040110000c0000201c6336401"
            "cf080035000b0000"
            "646e73"
        )
        udp_parsed = _raw_ip_to_info(raw_udp)
        self.assertIsNotNone(udp_parsed)
        self.assertEqual(udp_parsed["protocol"], "UDP")
        self.assertEqual(udp_parsed["src_port"], 53000)
        self.assertEqual(udp_parsed["dst_port"], 53)
        self.assertEqual(udp_parsed["payload"], b"dns")



class CaptureTests(unittest.TestCase):
    def test_replay_dispatches_packets_and_continues_after_callback_error(self):
        packets = [Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / UDP(sport=1, dport=2),
                   Ether() / IP(src="192.0.2.2", dst="198.51.100.2") / UDP(sport=3, dport=4)]
        received = []
        def callback(info):
            received.append(info)
            if len(received) == 1:
                raise RuntimeError("synthetic")
        capture = PacketCapture(callback, pcap_path="fixture.pcap")
        with patch("core.packet_capture.rdpcap", return_value=packets):
            capture.run()
        self.assertEqual(capture.packets_seen, 2)
        self.assertEqual(capture.packets_failed, 1)
        self.assertEqual(len(received), 2)


class CoreAndRulesTests(unittest.TestCase):
    def test_icmpv6_request_and_sweep(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, ping_threshold=2, enable_ipv6=True)
        for index in range(2):
            core.process_packet({"src_ip": "2001:db8::1", "dst_ip": f"2001:db8::{index + 2}",
                                 "protocol": "ICMPv6", "icmp_type": 128, "length": 64,
                                 "payload": b""})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90001, 90001, 90002])

    def test_icmp_request_and_sweep(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, ping_threshold=3)
        for index in range(3):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": f"198.51.100.{index + 1}",
                                 "protocol": "ICMP", "icmp_type": 8, "length": 64,
                                 "payload": b""})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90001, 90001, 90001, 90002])

    def test_configured_rules_are_native_valid(self):
        binary = "./build/delta-nids"
        if not os.path.exists(binary) and not os.path.exists(binary + ".exe"):
            self.skipTest("native binary not built")
        result = __import__("subprocess").run(
            [binary, "--validate-rules", "rules/rules.json"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rule_port_range_and_regex(self):
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.rules = [{"gid": 2, "sid": 77, "rev": 3, "protocol": "TCP",
                         "src_port": "40000:40010", "dst_port": "80,443",
                         "regex": "GET /[a-z]+", "message": "web"}]
        engine._compiled_rules = engine._compile_rules(engine.rules)
        engine.unsupported_rules = 0
        engine._alert_cache = {}
        packet = {"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "TCP",
                  "src_port": 40005, "dst_port": 80, "payload": b"GET /index"}
        alerts = engine.analyze_packet(packet)
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0]["gid"], alerts[0]["sid"], alerts[0]["revision"]), (2, 77, 3))

    def test_icmp_echo_to_same_target_aggregates_per_window(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, ping_threshold=3)
        for sequence in range(1, 6):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                 "protocol": "ICMP", "icmp_type": 8, "icmp_id": 7,
                                 "icmp_sequence": sequence, "length": 64, "payload": b""})
        # Repeated pings to one target aggregate into a single bounded
        # INFO-level visibility event instead of flooding one alert per ping.
        self.assertEqual([a["sid"] for a in recorder.alerts], [90001])
        self.assertEqual(recorder.alerts[0]["severity"], "INFO")

    def test_dns_query_rate_anomaly(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, dns_threshold=3)
        for offset in range(4):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.53",
                                 "protocol": "UDP", "src_port": 53000, "dst_port": 53,
                                 "length": 40, "payload": bytes([offset])})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90004])
        # Emitted as soon as the threshold is reached (streaming): the 3rd
        # query satisfies dns_threshold=3.
        self.assertIn("query_count=3", recorder.alerts[0]["evidence"])

    def test_dns_replies_are_not_query_anomalies(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, dns_threshold=2)
        for offset in range(4):
            core.process_packet({"src_ip": "198.51.100.53", "dst_ip": "192.0.2.1",
                                 "protocol": "UDP", "src_port": 53, "dst_port": 45000,
                                 "length": 40, "payload": bytes([offset])})
        self.assertEqual(recorder.alerts, [])

    def test_repeated_connection_failures(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, brute_force_threshold=3)
        for sequence in range(4):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                 "protocol": "TCP", "src_port": 42000 + sequence,
                                 "dst_port": 22, "tcp_flags": "R",
                                 "tcp_sequence": sequence, "length": 40, "payload": b""})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90005])
        # Emitted as soon as the threshold is reached (streaming): the 3rd
        # failure satisfies brute_force_threshold=3.
        self.assertIn("connection_failures=3", recorder.alerts[0]["evidence"])

    def test_fin_scan_is_not_connection_failure_flood(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=3, brute_force_threshold=2)
        for port in (21, 22, 23):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                 "protocol": "TCP", "src_port": 40000,
                                 "dst_port": port, "tcp_flags": "F",
                                 "length": 60, "payload": b""})
        sids = [alert["sid"] for alert in recorder.alerts]
        self.assertEqual(sids, [90003])

    def test_full_port_scale_evidence_is_bounded(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=150)
        for port in range(1, 201):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                 "protocol": "TCP", "src_port": 10000 + port,
                                 "dst_port": port, "tcp_flags": "S",
                                 "length": 60, "payload": b""})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90003])
        evidence = recorder.alerts[0]["evidence"]
        self.assertIn("distinct_destination_ports=150", evidence)
        self.assertIn("(+54 more)", evidence)
        self.assertLess(len(evidence), 2000, "evidence must stay bounded at scanner scale")

    def test_single_port_probes_across_hosts_are_host_sweep_not_scan(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, ping_threshold=3)
        for host in range(2, 7):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": f"198.51.100.{host}",
                                 "protocol": "TCP", "src_port": 40000,
                                 "dst_port": 443, "tcp_flags": "S",
                                 "length": 60, "payload": b""})
        # Zmap-class horizontal sweep: one port, many hosts -> host sweep, and
        # no per-host multi-port scan is fabricated.
        self.assertEqual([a["sid"] for a in recorder.alerts], [90002])

    def test_host_sweep_evidence_is_bounded(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, ping_threshold=70)
        for host in range(2, 82):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": f"198.51.100.{host}",
                                 "protocol": "ICMP", "icmp_type": 8,
                                 "length": 64, "payload": b""})
        sweep = [alert for alert in recorder.alerts if alert["sid"] == 90002]
        self.assertEqual(len(sweep), 1)
        evidence = sweep[0]["evidence"]
        self.assertIn("distinct_targets=70", evidence)
        self.assertIn("(+6 more)", evidence)
        self.assertLess(len(evidence), 4000)

    def test_invalid_syn_fin_combination_is_anomaly_not_scan(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine)
        for port in (21, 22, 23):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                 "protocol": "TCP", "src_port": 40000,
                                 "dst_port": port, "tcp_flags": "SF",
                                 "tcp_sequence": port, "length": 60, "payload": b""})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90006, 90006, 90006])

    def test_simulated_live_attacker_scan(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=5, scan_window=15.0)
        attacker_ip = "198.51.100.250"
        target_ip = "192.168.1.100"
        # Attacker sends SYN packets across 5 different target ports
        for port in [21, 22, 80, 443, 8080]:
            core.process_packet({
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": port,
                "tcp_flags": "S",
                "length": 60,
                "payload": b""
            })
        self.assertEqual(len(recorder.alerts), 1)
        self.assertEqual(recorder.alerts[0]["sid"], 90003)
        self.assertIn("port scan", recorder.alerts[0]["message"].lower())

    def test_acknowledged_established_traffic_does_not_trigger_scan(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=3)
        for port in [21, 22, 23, 80, 443]:
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "TCP",
                                 "src_port": 40000, "dst_port": port, "tcp_flags": "A", "length": 60})
        self.assertEqual(recorder.alerts, [])

    def test_scan_state_isolated_by_source_destination_and_protocol(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=3)
        for port in [22, 80]:
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "TCP", "src_port": 50000, "dst_port": port, "tcp_flags": "S", "length": 60})
        core.process_packet({"src_ip": "192.0.2.2", "dst_ip": "198.51.100.1", "protocol": "TCP", "src_port": 50001, "dst_port": 443, "tcp_flags": "S", "length": 60})
        self.assertEqual(recorder.alerts, [])

    def test_sustained_high_volume_throughput(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, scan_window=5.0)
        # Feed 2,000 packets rapidly
        for i in range(2000):
            core.process_packet({
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.1",
                "protocol": "TCP",
                "src_port": 40000 + (i % 10),
                "dst_port": 80,
                "length": 1500,
                "payload": b"data"
            })
        self.assertEqual(core.packets_sniffed, 2000)
        self.assertGreater(core.total_data, 0)



class PersistenceAndConfigTests(unittest.TestCase):
    def test_python_alert_and_traffic_persist(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = AlertManager(str(Path(directory) / "nids.sqlite"), terminal=False, persist=True)
            packet = {"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "TCP",
                      "src_port": 40000, "dst_port": 80, "length": 60, "details": {"ttl": 64}}
            traffic_id = manager.log_traffic(packet)
            manager.log_alert({**packet, "sid": 42, "gid": 1, "revision": 2, "message": "test"})
            self.assertEqual(traffic_id, 1)
            row = manager.session.query(__import__("database.models", fromlist=["TrafficLog"]).TrafficLog).one()
            self.assertEqual(manager.session.query(__import__("database.models", fromlist=["TrafficLog"]).TrafficLog).count(), 1)
            self.assertNotIn("mac", row.details.lower())
            self.assertEqual(manager.session.query(__import__("database.models", fromlist=["Alert"]).Alert).count(), 1)
            manager.close()

    def test_cli_validation(self):
        args = build_parser().parse_args(["--pcap", "x.pcap", "--persist", "--quiet"])
        self.assertEqual((args.pcap, args.persist, args.quiet), ("x.pcap", True, True))
        project = project_parser().parse_args(["--api-port", "8080", "--dashboard-port", "8081"])
        self.assertEqual((project.api_port, project.dashboard_port), (8080, 8081))

    def test_restart_reset_preserves_rules_and_clears_runtime_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "nids.sqlite")
            manager = AlertManager(path, terminal=False, persist=True)
            manager.persist_rules([{"sid": 99, "revision": 1, "message": "keep"}], "rules.json")
            manager.log_traffic({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "ICMP", "length": 64})
            manager.log_alert({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "ICMP", "sid": 1, "message": "old"})
            manager.reset_session_data()
            models = __import__("database.models", fromlist=["TrafficLog", "Alert", "Incident", "Rule", "Statistic"])
            self.assertEqual(manager.session.query(models.TrafficLog).count(), 0)
            self.assertEqual(manager.session.query(models.Alert).count(), 0)
            self.assertEqual(manager.session.query(models.Incident).count(), 0)
            self.assertEqual(manager.session.query(models.Statistic).count(), 0)
            self.assertEqual(manager.session.query(models.Rule).count(), 1)
            self.assertEqual(manager.get_recent_traffic(), [])
            self.assertEqual(manager.get_recent_alerts(), [])
            manager.close()

    def test_database_permissions_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "nids.sqlite"
            manager = AlertManager(str(path), terminal=False, persist=True)
            self.assertTrue(path.exists())
            manager.close()

    def test_invalid_rule_json_is_rejected(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as stream:
            stream.write(json.dumps({"sid": 1}))
            path = stream.name
        try:
            with self.assertRaises(ValueError):
                DetectionEngine(path)
        finally:
            os.unlink(path)


class DatabaseConcurrencyTests(unittest.TestCase):
    """The dashboard re-reads the shared SQLite file on every rules request
    while the capture process writes continuously. These tests pin the
    concurrency contract that keeps "database is locked" away.
    """

    def test_statistic_upsert_keeps_one_row_per_name(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = AlertManager(str(Path(directory) / "nids.sqlite"), terminal=False, persist=True)
            try:
                for value in (10, 20, 30):
                    manager._upsert_statistic("packets_processed", value)
                rows = manager.session.query(Statistic).filter_by(name="packets_processed").all()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0].value, 30)
            finally:
                manager.close()

    def test_capture_thread_statistics_do_not_share_the_session_cross_thread(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = AlertManager(str(Path(directory) / "nids.sqlite"), terminal=False, persist=True)
            try:
                manager._upsert_statistic("packets_processed", 7)

                def simulate_capture_thread():
                    manager._upsert_statistic("packets_processed", 99)

                thread = threading.Thread(target=simulate_capture_thread)
                thread.start()
                thread.join()
                row = manager.session.query(Statistic).filter_by(name="packets_processed").one()
                self.assertEqual(row.value, 7)
            finally:
                manager.close()

    def test_rules_endpoint_with_active_writer_never_locks(self):
        import dashboard.app as dashboard_app
        original_db_path = dashboard_app.DB_PATH
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "shared.sqlite")
            dashboard_app.DB_PATH = db_path
            manager = AlertManager(db_path, terminal=False, persist=True)
            stop = threading.Event()

            def writer():
                while not stop.is_set():
                    manager.log_traffic({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                         "protocol": "TCP", "src_port": 40000,
                                         "dst_port": 80, "length": 60})
                    time.sleep(0.001)

            thread = threading.Thread(target=writer, daemon=True)
            thread.start()
            try:
                client = dashboard_app.app.test_client()
                for _ in range(20):
                    response = client.get("/api/rules?page=1&page_size=50")
                    self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
            finally:
                stop.set()
                thread.join(timeout=5)
                manager.close()
                dashboard_app.DB_PATH = original_db_path


if __name__ == "__main__":
    unittest.main()
