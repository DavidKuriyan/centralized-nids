"""Detection matrix validation: SSH brute force, FTP banner grabbing, reverse
shell / Metasploit callback behaviour, HTTP enumeration, NetBIOS sweeps, DNS
enumeration, masscan endurance, and PCAP replay determinism.

Every scenario is exercised with deterministic packet-level traffic (synthetic
packets with explicit `_monotonic` clocks and real PCAP replay), so results are
reproducible without wall-clock dependency.
"""
import tempfile
import unittest
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

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


class _Engine:
    def analyze_packet(self, packet):
        return []

    def refresh_if_changed(self):
        return False


ATTACK_SIDS = {90002, 90003, 90005, 90007, 90008, 90009, 90010, 90011, 90012}


def make_core(recorder=None, **kwargs):
    recorder = recorder or Recorder()
    core = DeltaCore(recorder, _Engine(), **kwargs)
    return core, recorder


def tcp(src, sport, dst, dport, flags, payload=b"", t=None, seq=0):
    packet = {
        "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
        "protocol": "TCP", "tcp_flags": flags, "payload": payload,
        "length": 60 + len(payload), "tcp_sequence": seq,
        "tcp_acknowledgment": 0, "icmp_type": None, "icmp_code": None,
        "details": {},
    }
    if t is not None:
        packet["_monotonic"] = t
    return packet


def udp(src, sport, dst, dport, payload=b"", t=None):
    packet = {
        "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
        "protocol": "UDP", "payload": payload, "length": 40 + len(payload),
        "icmp_type": None, "icmp_code": None, "details": {},
    }
    if t is not None:
        packet["_monotonic"] = t
    return packet


def ssh_connection(client, sport, server, dport=22, t=0.0):
    """One full SSH session: handshake + banner exchange + close."""
    return [
        tcp(client, sport, server, dport, "S", t=t),
        tcp(server, dport, client, sport, "SA", t=t + 0.01),
        tcp(client, sport, server, dport, "A", t=t + 0.02),
        tcp(client, sport, server, dport, "PA",
            payload=b"SSH-2.0-OpenSSH_9.0p1 Kali\r\n", t=t + 0.03),
        tcp(server, dport, client, sport, "PA",
            payload=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n", t=t + 0.04),
        tcp(client, sport, server, dport, "FA", t=t + 0.05),
    ]


def ftp_grab_connection(client, sport, server, dport=21, banner=b"220 (vsFTPd 3.0.3)\r\n",
                        client_command=b"", t=0.0):
    packets = [
        tcp(client, sport, server, dport, "S", t=t),
        tcp(server, dport, client, sport, "SA", t=t + 0.01),
        tcp(client, sport, server, dport, "A", t=t + 0.02),
        tcp(server, dport, client, sport, "PA", payload=banner, t=t + 0.03),
    ]
    if client_command:
        packets.append(tcp(client, sport, server, dport, "PA", payload=client_command, t=t + 0.04))
    packets.append(tcp(client, sport, server, dport, "FA", t=t + 0.05))
    return packets


def ftp_login_connection(client, sport, server, dport=21, password=b"wrong",
                         server_reply=b"530 Login incorrect.\r\n", t=0.0):
    """One complete FTP login attempt with cleartext USER/PASS exchange."""
    return [
        tcp(client, sport, server, dport, "S", t=t),
        tcp(server, dport, client, sport, "SA", t=t + 0.01),
        tcp(client, sport, server, dport, "A", t=t + 0.02),
        tcp(server, dport, client, sport, "PA", payload=b"220 (vsFTPd 3.0.3)\r\n", t=t + 0.03),
        tcp(client, sport, server, dport, "PA", payload=b"USER attacker\r\n", t=t + 0.04),
        tcp(server, dport, client, sport, "PA", payload=b"331 Please specify the password.\r\n", t=t + 0.05),
        tcp(client, sport, server, dport, "PA", payload=b"PASS " + password + b"\r\n", t=t + 0.06),
        tcp(server, dport, client, sport, "PA", payload=server_reply, t=t + 0.07),
        tcp(client, sport, server, dport, "FA", t=t + 0.08),
    ]


def reverse_shell_connection(client, sport, server, dport, t0, client_payloads, server_payloads, t_end):
    packets = [
        tcp(client, sport, server, dport, "S", t=t0),
        tcp(server, dport, client, sport, "SA", t=t0 + 0.01),
        tcp(client, sport, server, dport, "A", t=t0 + 0.02),
    ]
    t = t0 + 0.1
    for payload in client_payloads:
        packets.append(tcp(client, sport, server, dport, "PA", payload=payload, t=t))
        t += 0.05
    for payload in server_payloads:
        packets.append(tcp(server, dport, client, sport, "PA", payload=payload, t=t))
        t += 0.05
    packets.append(tcp(server, dport, client, sport, "FA", t=t_end))
    return packets


def dns_query(name, t):
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    return udp("10.0.0.5", 53000, "8.8.8.8", 53,
               payload=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01",
               t=t)


class SshBruteForceTests(unittest.TestCase):
    def test_ten_failed_attempts_trigger_alert(self):
        # Brute force must fire once failed authentication attempts reach the
        # configured threshold (default 10), matching the other brute-force
        # detectors.
        core, recorder = make_core(ssh_brute_force_threshold=10, ssh_brute_force_window=60.0)
        packets = []
        for index in range(10):
            packets.extend(ssh_connection("192.0.2.10", 40000 + index, "198.51.100.20", t=float(index)))
        for packet in packets:
            core.process_packet(packet)
        sids = [alert["sid"] for alert in recorder.alerts]
        self.assertEqual(sids, [90007])
        alert = recorder.alerts[0]
        self.assertIn("SSH brute force", alert["message"])
        self.assertIn("failed_authentication_attempts=10", alert["evidence"])
        self.assertIn("destination_port=22", alert["evidence"])
        self.assertEqual(alert["severity"], "High")
        self.assertEqual(alert["detection_type"], "ssh_brute_force")

    def test_more_attempts_after_alert_do_not_duplicate(self):
        core, recorder = make_core(ssh_brute_force_threshold=10, ssh_brute_force_window=60.0)
        for index in range(14):
            for packet in ssh_connection("192.0.2.10", 40000 + index, "198.51.100.20", t=float(index)):
                core.process_packet(packet)
        self.assertEqual(len([alert for alert in recorder.alerts if alert["sid"] == 90007]), 1)

    def test_nine_failed_attempts_do_not_trigger(self):
        core, recorder = make_core(ssh_brute_force_threshold=10, ssh_brute_force_window=60.0)
        for index in range(9):
            for packet in ssh_connection("192.0.2.10", 40000 + index, "198.51.100.20", t=float(index)):
                core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [])

    def test_normal_single_ssh_login_is_not_brute_force(self):
        core, recorder = make_core(ssh_brute_force_threshold=10)
        for packet in ssh_connection("192.0.2.10", 40000, "198.51.100.20", t=1.0):
            core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [])

    def test_non_standard_ssh_port_detected_via_banner(self):
        core, recorder = make_core(ssh_brute_force_threshold=5, ssh_brute_force_window=60.0)
        for index in range(6):
            for packet in ssh_connection("192.0.2.10", 50000 + index, "198.51.100.20", dport=2222, t=float(index)):
                core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90007])
        self.assertIn("destination_port=2222", recorder.alerts[0]["evidence"])

    def test_new_campaign_after_window_expiry_re_alerts(self):
        core, recorder = make_core(ssh_brute_force_threshold=5, ssh_brute_force_window=60.0)
        for index in range(6):
            for packet in ssh_connection("192.0.2.10", 40000 + index, "198.51.100.20", t=float(index)):
                core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90007])
        # Second campaign long after the window has expired must be detected
        # again: deduplication must never permanently suppress a new attack.
        for index in range(6):
            for packet in ssh_connection("192.0.2.10", 41000 + index, "198.51.100.20", t=float(500 + index)):
                core.process_packet(packet)
        self.assertEqual(len(recorder.alerts), 2)
        self.assertNotEqual(recorder.alerts[0]["event_id"], recorder.alerts[1]["event_id"])

    def test_attempts_from_different_sources_do_not_aggregate(self):
        # Brute-force state is keyed per source: one connection from each of
        # several distinct sources is not a single-source brute-force campaign.
        core, recorder = make_core(ssh_brute_force_threshold=4, ssh_brute_force_window=60.0)
        for index in range(5):
            client = f"192.0.2.{index + 10}"
            for packet in ssh_connection(client, 40000 + index, "198.51.100.20", t=float(index)):
                core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [])


class FtpBannerGrabTests(unittest.TestCase):
    def test_bare_banner_grab_is_detected(self):
        core, recorder = make_core(ftp_grab_threshold=1)
        for packet in ftp_grab_connection("203.0.113.50", 51000, "10.0.0.21", t=1.0):
            core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90008])
        alert = recorder.alerts[0]
        self.assertIn("FTP banner", alert["message"])
        self.assertIn("vsFTPd 3.0.3", alert["evidence"])
        self.assertIn("version=vsFTPd 3.0.3", alert["evidence"])
        self.assertEqual(alert["severity"], "Medium")
        self.assertEqual(alert["service"], "ftp")

    def test_legitimate_ftp_session_with_user_command_is_not_a_grab(self):
        core, recorder = make_core(ftp_grab_threshold=1)
        for packet in ftp_grab_connection("203.0.113.50", 51000, "10.0.0.21",
                                          client_command=b"USER anonymous\r\n", t=1.0):
            core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [])

    def test_non_standard_ftp_port_detected_via_banner(self):
        core, recorder = make_core(ftp_grab_threshold=1)
        for packet in ftp_grab_connection("203.0.113.50", 51000, "10.0.0.21", dport=2121, t=1.0):
            core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90008])
        self.assertIn("destination_port=2121", recorder.alerts[0]["evidence"])

    def test_repeated_grabs_do_not_flood_alerts(self):
        core, recorder = make_core(ftp_grab_threshold=1, ftp_enum_window=60.0)
        for index in range(5):
            for packet in ftp_grab_connection("203.0.113.50", 51000 + index, "10.0.0.21", t=float(index)):
                core.process_packet(packet)
        # One alert per window epoch for the same target; later grabs in the
        # same window merge instead of flooding the alert stream.
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90008])
        self.assertEqual(len(recorder.alerts), 1)


class FtpBruteForceTests(unittest.TestCase):
    """FTP login brute force must alert when failed logins reach the threshold."""

    def test_ten_failed_logins_trigger_alert(self):
        core, recorder = make_core(ftp_brute_force_threshold=10, ftp_brute_force_window=60.0)
        for index in range(10):
            for packet in ftp_login_connection("203.0.113.60", 52000 + index, "10.0.0.31", t=float(index)):
                core.process_packet(packet)
        sids = [alert["sid"] for alert in recorder.alerts]
        self.assertEqual(sids, [90013])
        alert = recorder.alerts[0]
        self.assertIn("FTP brute force", alert["message"])
        self.assertIn("failed_authentication_attempts=10", alert["evidence"])
        self.assertIn("destination_port=21", alert["evidence"])
        self.assertEqual(alert["service"], "ftp")
        self.assertEqual(alert["severity"], "Medium")

    def test_nine_failed_logins_do_not_trigger(self):
        core, recorder = make_core(ftp_brute_force_threshold=10)
        for index in range(9):
            for packet in ftp_login_connection("203.0.113.60", 52000 + index, "10.0.0.31", t=float(index)):
                core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [])

    def test_successful_logins_do_not_trigger(self):
        core, recorder = make_core(ftp_brute_force_threshold=3)
        for index in range(5):
            for packet in ftp_login_connection("203.0.113.60", 52000 + index, "10.0.0.31",
                                                password=b"correct",
                                                server_reply=b"230 Login successful.\r\n",
                                                t=float(index)):
                core.process_packet(packet)
        # A 230 reply after PASS is a success: never a brute-force failure.
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [])

    def test_new_campaign_after_window_re_alerts(self):
        core, recorder = make_core(ftp_brute_force_threshold=5, ftp_brute_force_window=60.0)
        for index in range(5):
            for packet in ftp_login_connection("203.0.113.60", 52000 + index, "10.0.0.31", t=float(index)):
                core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90013])
        for index in range(5):
            for packet in ftp_login_connection("203.0.113.60", 53000 + index, "10.0.0.31", t=float(500 + index)):
                core.process_packet(packet)
        self.assertEqual(len([alert for alert in recorder.alerts if alert["sid"] == 90013]), 2)


class SynFloodTests(unittest.TestCase):
    """SID 90014: bare half-open SYN rate toward one service endpoint."""

    @staticmethod
    def syn_flood(source="203.0.113.66", target="10.0.0.60", port=8080,
                  count=100, t0=0.0, step=0.1):
        return [tcp(source, 40000 + index, target, port, "S", t=t0 + index * step)
                for index in range(count)]

    def test_syn_flood_at_threshold_triggers_alert(self):
        core, recorder = make_core(syn_flood_threshold=100)
        for packet in self.syn_flood(count=100):
            core.process_packet(packet)
        sids = [alert["sid"] for alert in recorder.alerts]
        self.assertEqual(sids, [90014])
        alert = recorder.alerts[0]
        self.assertIn("TCP SYN flood", alert["message"])
        self.assertIn("half_open_syn_attempts=100", alert["evidence"])
        self.assertIn("destination_port=8080", alert["evidence"])
        self.assertEqual(alert["detection_type"], "syn_flood")
        self.assertEqual(alert["severity"], "High")

    def test_syn_flood_below_threshold_does_not_trigger(self):
        core, recorder = make_core(syn_flood_threshold=100)
        for packet in self.syn_flood(count=99):
            core.process_packet(packet)
        sids = [alert["sid"] for alert in recorder.alerts]
        self.assertEqual([sid for sid in sids if sid == 90014], [])
        self.assertEqual(set(sids) & ATTACK_SIDS, set())

    def test_completed_handshake_burst_is_not_a_flood(self):
        """Many rapid but *completed* connections to one service are normal
        browsing/load behavior; only half-open bare-SYN attempts count."""
        core, recorder = make_core(syn_flood_threshold=20)
        for index in range(25):
            sport, t0 = 50000 + index, index * 0.05
            for packet in [
                tcp("198.51.100.40", sport, "10.0.0.90", 443, "S", t=t0),
                tcp("10.0.0.90", 443, "198.51.100.40", sport, "SA", t=t0 + 0.01),
                tcp("198.51.100.40", sport, "10.0.0.90", 443, "A", t=t0 + 0.02),
                tcp("198.51.100.40", sport, "10.0.0.90", 443, "PA",
                    payload=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", t=t0 + 0.03),
                tcp("10.0.0.90", 443, "198.51.100.40", sport, "A", t=t0 + 0.04),
                tcp("198.51.100.40", sport, "10.0.0.90", 443, "FA", t=t0 + 0.05),
                tcp("10.0.0.90", 443, "198.51.100.40", sport, "FA", t=t0 + 0.06),
            ]:
                core.process_packet(packet)
        sids = [alert["sid"] for alert in recorder.alerts]
        self.assertEqual([sid for sid in sids if sid == 90014], [])
        self.assertEqual(set(sids) & ATTACK_SIDS, set())

    def test_new_flood_after_window_re_alerts(self):
        core, recorder = make_core(syn_flood_threshold=20)
        for packet in self.syn_flood(count=20, t0=0.0):
            core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90014])
        for packet in self.syn_flood(count=20, t0=1000.0):
            core.process_packet(packet)
        self.assertEqual(len([alert for alert in recorder.alerts if alert["sid"] == 90014]), 2)


class ReverseShellTests(unittest.TestCase):
    def test_outbound_interactive_callback_to_unusual_port(self):
        core, recorder = make_core(reverse_shell_min_duration=30.0)
        packets = reverse_shell_connection(
            "10.0.0.5", 44000, "203.0.113.9", 4444, t0=100.0,
            client_payloads=[b"id;\n", b"whoami\n", b"ls -la\n"],
            server_payloads=[b"uid=0(root)\n", b"root\n", b"total 8\n"],
            t_end=135.0,
        )
        for packet in packets:
            core.process_packet(packet)
        sids = [alert["sid"] for alert in recorder.alerts]
        self.assertEqual(sids, [90009])
        alert = recorder.alerts[0]
        self.assertIn("reverse shell", alert["message"].lower())
        self.assertIn("destination_port=4444", alert["evidence"])
        self.assertIn("interactive=True", alert["evidence"])
        self.assertIn("shell_markers=", alert["evidence"])
        self.assertEqual(alert["severity"], "High")

    def test_reverse_shell_over_common_port_443(self):
        # Shell + interactive + long-lived over a common port must still fire:
        # reverse shells do not require an unusual destination port.
        core, recorder = make_core(reverse_shell_min_duration=30.0)
        packets = reverse_shell_connection(
            "10.0.0.5", 44000, "93.184.216.34", 443, t0=200.0,
            client_payloads=[b"bash -i\n", b"id;\n", b"whoami\n"],
            server_payloads=[b"uid=0(root)\n", b"root\n", b"# \n"],
            t_end=240.0,
        )
        for packet in packets:
            core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90009])

    def test_web_protocol_session_with_shell_text_is_not_a_reverse_shell(self):
        # Regression for a false positive class: a long-lived, bidirectional
        # TLS/HTTP session to a public web host (for example a Render/onrender
        # app on port 443) must never be reported as a reverse shell, even when
        # the HTTP bodies carry shell-like text. Web framing means it is a
        # protocol conversation, not a raw interactive shell.
        core, recorder = make_core(reverse_shell_min_duration=30.0)
        packets = [
            tcp("192.168.68.119", 50000, "216.24.57.7", 443, "S", t=800.0),
            tcp("216.24.57.7", 443, "192.168.68.119", 50000, "SA", t=800.01),
            tcp("192.168.68.119", 50000, "216.24.57.7", 443, "A", t=800.02),
            tcp("192.168.68.119", 50000, "216.24.57.7", 443, "PA",
                payload=b"\x16\x03\x01\x00\x0b\x01\x00\x00\x07\x03\x03\x00", t=800.03),
            tcp("216.24.57.7", 443, "192.168.68.119", 50000, "PA",
                payload=b"\x16\x03\x03\x00\x2a\x02\x00\x00\x26\x03\x03", t=800.04),
        ]
        t = 800.1
        for index in range(6):
            packets.append(tcp("192.168.68.119", 50000, "216.24.57.7", 443, "PA",
                               payload=f"GET /search?q=whoami+id%3B+bash+-i HTTP/1.1\r\nHost: app.onrender.com\r\n\r\n".encode(),
                               t=t))
            t += 0.05
            packets.append(tcp("216.24.57.7", 443, "192.168.68.119", 50000, "PA",
                               payload=f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>uid=0(root) whoami ls -la /bin/bash</html>".encode(),
                               t=t))
            t += 0.05
        packets.append(tcp("216.24.57.7", 443, "192.168.68.119", 50000, "PA",
                           payload=b"\x17\x03\x03\x00\x15" + bytes(range(21)), t=t))
        packets.append(tcp("192.168.68.119", 50000, "216.24.57.7", 443, "FA", t=860.0))
        for packet in packets:
            core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [])

    def test_normal_https_traffic_is_not_a_reverse_shell(self):
        core, recorder = make_core(reverse_shell_min_duration=30.0)
        packets = [
            tcp("10.0.0.5", 44000, "93.184.216.34", 443, "S", t=300.0),
            tcp("93.184.216.34", 443, "10.0.0.5", 44000, "SA", t=300.01),
            tcp("10.0.0.5", 44000, "93.184.216.34", 443, "A", t=300.02),
            tcp("10.0.0.5", 44000, "93.184.216.34", 443, "PA",
                payload=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", t=300.1),
        ]
        t = 300.2
        for _ in range(10):
            packets.append(tcp("93.184.216.34", 443, "10.0.0.5", 44000, "PA",
                               payload=b"\x16\x03\x03\x00\x20" + bytes(range(32)), t=t))
            t += 0.01
        packets.append(tcp("93.184.216.34", 443, "10.0.0.5", 44000, "FA", t=t))
        for packet in packets:
            core.process_packet(packet)
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [])

    def test_multi_stage_recon_then_callback_correlation(self):
        core, recorder = make_core(port_threshold=8, scan_window=30.0,
                                   reverse_shell_min_duration=30.0, correlation_window=600.0)
        # Phase 1: reconnaissance (SYN port scan) from attacker to victim.
        for port in range(21, 31):
            core.process_packet(tcp("203.0.113.9", 40000, "10.0.0.5", port, "S", t=10.0))
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90003])
        # Phase 2: exploitation payload toward a service port.
        for packet in [
            tcp("203.0.113.9", 40001, "10.0.0.5", 80, "S", t=50.0),
            tcp("10.0.0.5", 80, "203.0.113.9", 40001, "SA", t=50.01),
            tcp("203.0.113.9", 40001, "10.0.0.5", 80, "A", t=50.02),
            tcp("203.0.113.9", 40001, "10.0.0.5", 80, "PA",
                payload=b"GET /cgi-bin/x?y=;bash+-i HTTP/1.1\r\n\r\n", t=50.03),
        ]:
            core.process_packet(packet)
        self.assertIn(90011, [alert["sid"] for alert in recorder.alerts])
        # Phase 3: outbound interactive callback victim -> attacker.
        for packet in reverse_shell_connection(
                "10.0.0.5", 44000, "203.0.113.9", 4444, t0=60.0,
                client_payloads=[b"id;\n", b"whoami\n", b"ls -la\n"],
                server_payloads=[b"uid=0(root)\n", b"root\n", b"total 8\n"],
                t_end=95.0):
            core.process_packet(packet)
        sids = [alert["sid"] for alert in recorder.alerts]
        self.assertIn(90009, sids)
        self.assertIn(90012, sids)
        multi = next(alert for alert in recorder.alerts if alert["sid"] == 90012)
        self.assertIn("multi-stage", multi["message"].lower())
        self.assertEqual(multi["severity"], "Critical")


class HttpEnumerationTests(unittest.TestCase):
    def test_many_distinct_paths_trigger_enumeration(self):
        core, recorder = make_core(http_enum_threshold=40, http_enum_window=60.0)
        for index in range(40):
            core.process_packet(tcp("203.0.113.50", 52000, "10.0.0.80", 80, "PA",
                                    payload=f"GET /path-{index} HTTP/1.1\r\nHost: x\r\n\r\n".encode(),
                                    t=1.0 + index * 0.1))
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90010])
        self.assertIn("distinct_paths=40", recorder.alerts[0]["evidence"])

    def test_normal_browsing_does_not_trigger(self):
        core, recorder = make_core(http_enum_threshold=40, http_enum_window=60.0)
        for index in range(5):
            core.process_packet(tcp("203.0.113.50", 52000, "10.0.0.80", 80, "PA",
                                    payload=b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n",
                                    t=1.0 + index * 5.0))
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [])


class NetBiosAndDnsTests(unittest.TestCase):
    def test_udp_137_sweep_across_hosts_is_detected(self):
        core, recorder = make_core(ping_threshold=5)
        for host in range(2, 9):
            core.process_packet(udp("10.0.0.50", 40000, f"10.0.0.{host}", 137,
                                    payload=b"\x00\x00\x00\x01", t=1.0))
        sweep = [alert for alert in recorder.alerts if alert["sid"] == 90002]
        self.assertEqual(len(sweep), 1)
        self.assertIn("UDP host discovery sweep", sweep[0]["message"])
        self.assertIn("distinct_targets=5", sweep[0]["evidence"])

    def test_distinct_dns_query_names_trigger_enumeration(self):
        core, recorder = make_core(dns_threshold=5)
        for index in range(6):
            core.process_packet(dns_query(f"sub-{index}.example.com", float(index)))
        self.assertEqual([alert["sid"] for alert in recorder.alerts], [90004])
        self.assertIn("distinct_query_names=5", recorder.alerts[0]["evidence"])


class MasscanEnduranceTests(unittest.TestCase):
    """Masscan-class bursts must remain detectable after prolonged runtime."""

    def _campaign(self, core, start, port_offset):
        for port in range(1, 13):
            core.process_packet(tcp("192.0.2.99", 40000 + port, "198.51.100.200", port_offset + port,
                                    "S", t=start + port * 0.001))

    def test_detection_continues_after_minutes_of_runtime(self):
        core, recorder = make_core(port_threshold=8, scan_window=30.0)
        # Background traffic keeps the engine busy between campaigns.
        for minute in range(0, 26):
            background_t = minute * 60.0 + 30.0
            core.process_packet(tcp("10.0.0.10", 45000, "192.168.1.5", 443, "A", t=background_t))
        # Campaign immediately after startup.
        self._campaign(core, 1.0, 1000)
        self.assertEqual(len([a for a in recorder.alerts if a["sid"] == 90003]), 1)
        # 1 minute, 5 minutes, 10 minutes, and 25 minutes later. Each
        # campaign is separated by far more than the 30s window, so every
        # campaign must produce its own alert (no permanent dedup).
        expected = 2
        for minute, port_offset in ((1, 2000), (5, 3000), (10, 4000), (25, 5000)):
            self._campaign(core, minute * 60.0 + 5.0, port_offset)
            scans = [a for a in recorder.alerts if a["sid"] == 90003]
            self.assertEqual(len(scans), expected,
                             f"campaign at minute {minute} not detected")
            expected += 1
        self.assertEqual(len([a for a in recorder.alerts if a["sid"] == 90003]), 5)
        # State remains bounded after the whole timeline.
        self.assertLessEqual(len(core._ports), core._max_scan_states)
        self.assertLessEqual(len(core._conns), core._max_conn_states)

    def test_campaign_after_long_gap_is_detected_again(self):
        core, recorder = make_core(port_threshold=8, scan_window=30.0)
        self._campaign(core, 1.0, 1000)
        self.assertEqual(len([a for a in recorder.alerts if a["sid"] == 90003]), 1)
        self._campaign(core, 3600.0, 6000)  # one hour later
        self.assertEqual(len([a for a in recorder.alerts if a["sid"] == 90003]), 2)


class PcapReplayDeterminismTests(unittest.TestCase):
    def test_replay_honors_pcap_timestamps_for_window_expiry(self):
        """Two scan campaigns five minutes apart in pcap time must both alert.

        Before the fix, replay used wall-clock time so the second campaign was
        processed within the same 30-second window and suppressed as a
        duplicate, making detection stop after the first campaign.
        """
        packets = []
        for port in range(1, 13):
            syn = Ether() / IP(src="192.0.2.99", dst="198.51.100.200") / TCP(sport=40000 + port, dport=1000 + port, flags="S")
            syn.time = 100.0 + port * 0.001
            packets.append(syn)
        for port in range(1, 13):
            syn = Ether() / IP(src="192.0.2.99", dst="198.51.100.200") / TCP(sport=50000 + port, dport=2000 + port, flags="S")
            syn.time = 400.0 + port * 0.001  # 5 minutes after the first campaign
            packets.append(syn)
        recorder = Recorder()
        core = DeltaCore(recorder, _Engine(), port_threshold=8, scan_window=30.0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "two_campaigns.pcap"
            wrpcap(str(path), packets)
            capture = PacketCapture(core.process_packet, pcap_path=str(path))
            capture.run()
        scans = [alert for alert in recorder.alerts if alert["sid"] == 90003]
        self.assertEqual(len(scans), 2, [alert["sid"] for alert in recorder.alerts])
        self.assertEqual(len({alert["event_id"] for alert in scans}), 2)

    @staticmethod
    def replay(packets, **kwargs):
        recorder = Recorder()
        core = DeltaCore(recorder, _Engine(), **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case.pcap"
            wrpcap(str(path), packets)
            capture = PacketCapture(core.process_packet, pcap_path=str(path))
            capture.run()
        return core, recorder

    @staticmethod
    def ssh_session(client, sport, server, dport, t):
        return [
            Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="S"),
            Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="SA"),
            Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="A"),
            Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="PA") /
            Raw(b"SSH-2.0-OpenSSH_9.0p1 Kali\r\n"),
            Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="PA") /
            Raw(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"),
            Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="FA"),
        ]

    def test_ssh_brute_force_pcap_replay(self):
        """SSH brute force written to a PCAP must alert identically on replay."""
        packets = []
        for index in range(11):
            for offset, packet in enumerate(self.ssh_session(
                    "192.0.2.10", 40000 + index, "198.51.100.20", 22, 1.0 + index * 2.0)):
                packet.time = 1.0 + index * 2.0 + offset * 0.01
                packets.append(packet)
        core, recorder = self.replay(packets, ssh_brute_force_threshold=10, ssh_brute_force_window=60.0)
        ssh_alerts = [alert for alert in recorder.alerts if alert["sid"] == 90007]
        self.assertEqual(len(ssh_alerts), 1, [alert["sid"] for alert in recorder.alerts])
        self.assertIn("failed_authentication_attempts=10", ssh_alerts[0]["evidence"])

    def test_ftp_banner_grab_pcap_replay(self):
        """FTP banner grabbing written to a PCAP must alert on replay."""
        packets = []
        grab = [
            Ether() / IP(src="203.0.113.50", dst="10.0.0.21") / TCP(sport=51000, dport=21, flags="S"),
            Ether() / IP(src="10.0.0.21", dst="203.0.113.50") / TCP(sport=21, dport=51000, flags="SA"),
            Ether() / IP(src="203.0.113.50", dst="10.0.0.21") / TCP(sport=51000, dport=21, flags="A"),
            Ether() / IP(src="10.0.0.21", dst="203.0.113.50") / TCP(sport=21, dport=51000, flags="PA") /
            Raw(b"220 (vsFTPd 3.0.3)\r\n"),
            Ether() / IP(src="203.0.113.50", dst="10.0.0.21") / TCP(sport=51000, dport=21, flags="FA"),
        ]
        for offset, packet in enumerate(grab):
            packet.time = 10.0 + offset * 0.01
            packets.append(packet)
        core, recorder = self.replay(packets, ftp_grab_threshold=1)
        ftp_alerts = [alert for alert in recorder.alerts if alert["sid"] == 90008]
        self.assertEqual(len(ftp_alerts), 1, [alert["sid"] for alert in recorder.alerts])
        self.assertIn("vsFTPd 3.0.3", ftp_alerts[0]["evidence"])

    def test_reverse_shell_pcap_replay(self):
        """A long interactive callback written to a PCAP must alert on replay."""
        packets = []
        steps = [
            ("S", b"", "10.0.0.5", 44000, "203.0.113.9", 4444),
            ("SA", b"", "203.0.113.9", 4444, "10.0.0.5", 44000),
            ("A", b"", "10.0.0.5", 44000, "203.0.113.9", 4444),
            ("PA", b"bash -i\n", "10.0.0.5", 44000, "203.0.113.9", 4444),
            ("PA", b"id;\n", "10.0.0.5", 44000, "203.0.113.9", 4444),
            ("PA", b"whoami\n", "10.0.0.5", 44000, "203.0.113.9", 4444),
            ("PA", b"uid=0(root)\n", "203.0.113.9", 4444, "10.0.0.5", 44000),
            ("PA", b"root\n", "203.0.113.9", 4444, "10.0.0.5", 44000),
            ("FA", b"", "203.0.113.9", 4444, "10.0.0.5", 44000),
        ]
        for index, (flags, payload, src, sport, dst, dport) in enumerate(steps):
            packet = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
            if payload:
                packet = packet / Raw(payload)
            packet.time = 60.0 + index * 0.05
            packets.append(packet)
        packets[-1].time = 100.0  # close ~40s later: long-lived session
        core, recorder = self.replay(packets, reverse_shell_min_duration=30.0)
        shell_alerts = [alert for alert in recorder.alerts if alert["sid"] == 90009]
        self.assertEqual(len(shell_alerts), 1, [alert["sid"] for alert in recorder.alerts])
        self.assertIn("destination_port=4444", shell_alerts[0]["evidence"])


class PassiveToolNoFalsePositiveTests(unittest.TestCase):
    """tcpdump/tshark are passive: observing traffic must not create alerts."""

    def test_observation_of_normal_traffic_produces_no_attack_alerts(self):
        core, recorder = make_core(ssh_brute_force_threshold=10, ftp_grab_threshold=1,
                                   http_enum_threshold=40, dns_threshold=50,
                                   ping_threshold=5, port_threshold=8)
        packets = []
        packets.extend(ssh_connection("192.0.2.10", 40000, "198.51.100.20", t=1.0))
        packets.extend(ftp_grab_connection("203.0.113.50", 51000, "10.0.0.21",
                                           client_command=b"USER anonymous\r\n", t=5.0))
        for index in range(5):
            packets.append(tcp("203.0.113.50", 52000, "10.0.0.80", 80, "PA",
                               payload=b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n",
                               t=10.0 + index))
        for index in range(3):
            packets.append(dns_query(f"host-{index}.example.com", 20.0 + index))
        packets.append(udp("10.0.0.50", 40000, "10.0.0.1", 137, payload=b"\x00\x00\x00\x01", t=30.0))
        for index in range(2):
            packets.append({"src_ip": "10.0.0.50", "dst_ip": "10.0.0.1", "protocol": "ICMP",
                            "icmp_type": 8, "icmp_code": 0, "length": 64, "payload": b"",
                            "tcp_flags": None, "icmp_id": 1, "icmp_sequence": index,
                            "details": {}, "_monotonic": 40.0 + index})
        for packet in packets:
            core.process_packet(packet)
        sids = [alert["sid"] for alert in recorder.alerts]
        # Only the bounded ICMP visibility INFO event (90001) may appear.
        self.assertEqual(set(sids) & ATTACK_SIDS, set())


if __name__ == "__main__":
    unittest.main()