from __future__ import annotations

import argparse
import os
import sys
import threading
import time

if os.name == "nt":
    npcap_dir = r"C:\Windows\System32\Npcap"
    if os.path.exists(npcap_dir) and npcap_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = npcap_dir + os.pathsep + os.environ.get("PATH", "")

    # Check for Administrator privileges early so we can warn the user.
    # SIO_RCVALL (used by the supplementary ICMP capture thread) requires admin.
    import ctypes as _ctypes
    _is_admin = bool(_ctypes.windll.shell32.IsUserAnAdmin())
    if not _is_admin:
        import warnings as _warnings
        _warnings.warn(
            "Delta-NIDS is running WITHOUT Administrator privileges on Windows. "
            "ICMP traffic (pings) cannot be captured. "
            "Re-run from an elevated (Administrator) PowerShell/CMD for full capture.",
            RuntimeWarning, stacklevel=1
        )

from core.alert_manager import AlertManager
from core.delta_core import DeltaCore
from core.packet_capture import PacketCapture, auto_detect_interface, interface_address
from core.detection_engine import DetectionEngine


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Delta IDS - terminal-only network intrusion detection")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-i", "--interface", help="live interface to monitor")
    source.add_argument("-r", "--pcap", metavar="FILE", help="read packets from a PCAP file")
    parser.add_argument("-c", "--config", default="rules/rules.json", help="JSON rules file")
    parser.add_argument("--capture-mode", choices=["normal", "span", "pcap"],
                        default="normal",
                        help="capture mode: normal (default), span (SPAN/port-mirror), or pcap (replay)")
    parser.add_argument("--no-promiscuous", action="store_true",
                        help="disable promiscuous mode (not recommended for SPAN)")
    parser.add_argument("--snap-length", type=int, default=65535,
                        help="libpcap/Npcap snap length in bytes (default: 65535)")
    parser.add_argument("--buffer-size", type=int, default=0,
                        help="capture socket buffer size in bytes (0 = use default 16 MiB)")
    parser.add_argument("--filter", default="", help="libpcap/BPF filter for live capture (default: empty = all protocols)")
    parser.add_argument("-n", "--count", type=int, default=0, help="stop after N live packets; 0 means unlimited")
    parser.add_argument("--db", help="optional SQLite database path")
    parser.add_argument("--persist", action="store_true", help="persist traffic and alerts to SQLite")
    parser.add_argument("--quiet", action="store_true", help="do not print alerts")
    parser.add_argument("--purge-false-positives", action="store_true",
                        help="remove stored SID 90002 alerts whose evidence cannot justify a host-discovery sweep (uses current thresholds)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.interface and not args.pcap:
        args.interface = auto_detect_interface()

    root = os.path.dirname(os.path.abspath(__file__))
    rules_path = args.config if os.path.isabs(args.config) else os.path.join(root, args.config)
    db_path = args.db or os.path.join(root, "database", "nids.db")

    try:
        engine = DetectionEngine(rules_path, runtime_db_path=db_path if args.persist else None)
        manager = AlertManager(db_path=db_path, terminal=not args.quiet,
                               persist=args.persist or args.purge_false_positives)
        if args.purge_false_positives:
            removed = manager.purge_false_sweep_alerts(
                host_threshold=_env_int("DELTA_NIDS_PING_THRESHOLD", 30),
            )
            print(f"purged {removed} non-justifiable host-discovery sweep alerts")
            return 0
        if manager.session:
            # A process restart starts a new capture session. Preserve rules, but
            # never allow historical evidence or runtime state to reappear.
            manager.reset_session_data()
        if manager.session:
            manager.persist_rules(engine.rules, rules_path)
        core = DeltaCore(
            manager, engine,
            scan_window=_env_float("DELTA_NIDS_SCAN_WINDOW", 30.0),
            port_threshold=_env_int("DELTA_NIDS_PORT_SCAN_THRESHOLD", 8),
            ping_threshold=_env_int("DELTA_NIDS_PING_THRESHOLD", 30),
            remote_sweep_threshold=_env_int("DELTA_NIDS_REMOTE_SWEEP_THRESHOLD", 200),
            remote_sweep_enabled=_env_bool("DELTA_NIDS_REMOTE_SWEEP_ENABLED", False),
            dns_threshold=_env_int("DELTA_NIDS_DNS_QUERY_THRESHOLD", 50),
            brute_force_threshold=_env_int("DELTA_NIDS_BRUTE_FORCE_THRESHOLD", 10),
            syn_flood_threshold=_env_int("DELTA_NIDS_SYN_FLOOD_THRESHOLD", 100),
            ssh_brute_force_threshold=_env_int("DELTA_NIDS_SSH_BRUTE_FORCE_THRESHOLD", 10),
            ssh_brute_force_window=_env_float("DELTA_NIDS_SSH_BRUTE_FORCE_WINDOW", 60.0),
            ftp_grab_threshold=_env_int("DELTA_NIDS_FTP_BANNER_THRESHOLD", 1),
            ftp_enum_window=_env_float("DELTA_NIDS_FTP_ENUM_WINDOW", 60.0),
            ftp_brute_force_threshold=_env_int("DELTA_NIDS_FTP_BRUTE_FORCE_THRESHOLD", 10),
            ftp_brute_force_window=_env_float("DELTA_NIDS_FTP_BRUTE_FORCE_WINDOW", 60.0),
            http_enum_threshold=_env_int("DELTA_NIDS_HTTP_ENUM_THRESHOLD", 40),
            http_enum_window=_env_float("DELTA_NIDS_HTTP_ENUM_WINDOW", 60.0),
            reverse_shell_min_duration=_env_float("DELTA_NIDS_REVERSE_SHELL_MIN_DURATION", 30.0),
            connection_idle_timeout=_env_float("DELTA_NIDS_CONNECTION_IDLE_TIMEOUT", 120.0),
            correlation_window=_env_float("DELTA_NIDS_CORRELATION_WINDOW", 600.0),
            enable_ipv6=_env_bool("DELTA_NIDS_ENABLE_IPV6", False),
        )
        capture_mode = args.capture_mode if hasattr(args, "capture_mode") else "normal"
        if args.pcap:
            capture_mode = "pcap"
        promiscuous = not getattr(args, "no_promiscuous", False)
        snap_length = getattr(args, "snap_length", 65535)
        buffer_size = getattr(args, "buffer_size", 0)

        # Print SPAN mode startup banner.
        if capture_mode == "span" and args.interface:
            print(
                "\n"
                "╔══════════════════════════════════════════════════════════════╗\n"
                "║        DELTA-NIDS  —  SPAN / PORT MIRROR MODE ACTIVE         ║\n"
                "╚══════════════════════════════════════════════════════════════╝\n"
                f"\n  Interface  : {args.interface}\n"
                "  Promiscuous: " + ("YES" if promiscuous else "NO") + "\n"
                "  BPF filter : " + (args.filter or "NONE (all EtherTypes including IPv6)") + "\n"
                "\n  Expected topology:\n"
                "   [Source ports] ──── Switch SPAN session ────> [Mirror port]\n"
                "                                                     |\n"
                f"                                             [{args.interface}]\n"
                "\n  Delta-NIDS is PASSIVE: it never transmits, routes, or blocks.\n",
                flush=True
            )

        capture = PacketCapture(core.process_packet, interface=args.interface, pcap_path=args.pcap,
                                bpf_filter=args.filter, count=args.count,
                                capture_mode=capture_mode, promiscuous=promiscuous,
                                snap_length=snap_length, buffer_size=buffer_size)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if isinstance(exc, PermissionError):
            print("hint: run capture as the database owner, or choose a writable path with --db", file=sys.stderr)
        return 2

    source_name = args.interface or f"PCAP:{args.pcap}"
    manager.persist_runtime_status("STARTING", source_name)
    heartbeat_stop = threading.Event()

    def heartbeat() -> None:
        while not heartbeat_stop.wait(2.0):
            last_packet = capture.last_packet_time
            age = time.time() - last_packet if last_packet is not None else None
            activity = "ACTIVE" if age is not None and age <= 10 else "IDLE"
            stats = capture.capture_statistics() if hasattr(capture, "capture_statistics") else {}
            manager.persist_runtime_status(
                activity, source_name, capture.packets_seen,
                core.packets_sniffed, last_packet,
                packets_failed=capture.packets_failed,
                capture_mode=stats.get("capture_mode", "normal"),
                capture_interface=stats.get("capture_interface", ""),
                bytes_captured=stats.get("bytes_captured", 0),
                duplicate_packets=stats.get("duplicate_packets", 0),
                malformed_packets=stats.get("malformed_packets", 0),
                ipv4_packets=stats.get("ipv4_packets", 0),
                ipv6_packets=stats.get("ipv6_packets", 0),
                vlan_packets=stats.get("vlan_packets", 0),
                tcp_packets=stats.get("tcp_packets", 0),
                udp_packets=stats.get("udp_packets", 0),
                icmp_packets=stats.get("icmp_packets", 0),
                icmpv6_packets=stats.get("icmpv6_packets", 0),
                zero_traffic_warning=stats.get("zero_traffic_warning", False),
            )

    heartbeat_thread = threading.Thread(target=heartbeat, name="delta-nids-heartbeat", daemon=True)
    heartbeat_thread.start()
    print(f"Delta IDS | rules discovered={len(engine.rules)} loaded={len(engine._compiled_rules) - engine.unsupported_rules} unsupported={engine.unsupported_rules} | source={'PCAP ' + args.pcap if args.pcap else 'interface ' + args.interface}")
    if engine.unsupported_rules:
        print("warning: legacy or unsupported rule fields are excluded from matching; use native rule syntax for detection")
    if args.interface:
        address = interface_address(args.interface)
        if address:
            print(f"local IPv4: {address}")
        print("capturing; press Ctrl+C to stop")
    else:
        print("replaying PCAP")
    try:
        manager.persist_runtime_status("STARTING", source_name, capture.packets_seen,
                                       core.packets_sniffed, capture.last_packet_time,
                                       packets_failed=capture.packets_failed)
        capture.run()
    except KeyboardInterrupt:
        print("\nstopped")
    except PermissionError:
        print("error: live capture requires root/Administrator privileges", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"capture error: {exc}", file=sys.stderr)
        return 1
    finally:
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=3)
        capture.stop()
        manager.persist_runtime_status(capture.state, source_name, capture.packets_seen,
                                       core.packets_sniffed, capture.last_packet_time,
                                       packets_failed=capture.packets_failed)
    print(f"packets={core.packets_sniffed} alerts={manager.get_alert_counts()['total']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
