from __future__ import annotations

import os
import socket
import struct
import threading
import hashlib
from typing import Callable, Optional
import logging
import time

if os.name == "nt":
    npcap_dir = r"C:\Windows\System32\Npcap"
    if os.path.exists(npcap_dir) and npcap_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = npcap_dir + os.pathsep + os.environ.get("PATH", "")

from scapy.all import ARP, Ether, IP, ICMP, IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrRouting, IPv6ExtHdrFragment, ICMPv6EchoRequest, ICMPv6DestUnreach, TCP, UDP, conf, get_if_addr, get_if_list, rdpcap, sniff

logger = logging.getLogger("delta-ids.capture")


def _format_endpoint(ip: str | None, port: int | None) -> str:
    """Format an IP endpoint without ambiguously concatenating IPv6 colons."""
    if not ip:
        return "-"
    value = str(ip)
    if port is None:
        return value
    return f"[{value}]:{int(port)}" if ":" in value else f"{value}:{int(port)}"

try:
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None


# ---------------------------------------------------------------------------
# Interface discovery helpers
# ---------------------------------------------------------------------------

def auto_detect_interface() -> str:
    """Return a usable non-loopback interface, preferring Scapy's default route."""
    try:
        default = conf.iface
        address = get_if_addr(default)
        if address and not address.startswith("127.") and address != "0.0.0.0":
            return str(default)
    except Exception:
        pass

    for interface in get_if_list():
        if interface == "lo" or interface.startswith("lo"):
            continue
        try:
            address = get_if_addr(interface)
            if address and not address.startswith("127.") and address != "0.0.0.0":
                return str(interface)
        except Exception:
            continue
    return str(conf.iface)


def interface_address(interface: str) -> Optional[str]:
    if fcntl is None:
        try:
            addr = get_if_addr(interface)
            return addr if addr and addr != "0.0.0.0" else None
        except Exception:
            return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            return socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(), 0x8915,
                struct.pack("256s", interface[:15].encode("utf-8")),
            )[20:24])
    except (OSError, struct.error):
        return None


# ---------------------------------------------------------------------------
# Packet parsing helpers
# ---------------------------------------------------------------------------

def _safe_int(value) -> Optional[int]:
    """Convert a Scapy field value to int, returning None when unavailable."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _decoded_details(packet, info: dict) -> dict:
    """Collect decoded header fields from a Scapy packet."""
    details: dict = {}
    if Ether in packet:
        details["src_mac"] = packet[Ether].src
        details["dst_mac"] = packet[Ether].dst
        details["ethertype"] = hex(int(packet[Ether].type))
    if IPv6 in packet:
        ip_layer = packet[IPv6]
        details.update({
            "ip_version": _safe_int(ip_layer.version),
            "ip_header_length": 40,
            "ip_hop_limit": _safe_int(ip_layer.hlim),
            "ip_next_header": _safe_int(ip_layer.nh),
            "ip_payload_length": _safe_int(ip_layer.plen),
        })
    if IP in packet:
        ip_layer = packet[IP]
        details.update({
            "ip_version": _safe_int(ip_layer.version),
            "ip_header_length": (_safe_int(ip_layer.ihl) or 0) * 4,
            "ip_tos": _safe_int(ip_layer.tos),
            "ip_id": _safe_int(ip_layer.id),
            "ip_flags": str(ip_layer.flags) if ip_layer.flags is not None else None,
            "ip_fragment_offset": _safe_int(ip_layer.frag),
            "ip_ttl": _safe_int(ip_layer.ttl),
            "ip_total_length": _safe_int(ip_layer.len),
            "ip_checksum": hex(int(ip_layer.chksum)) if ip_layer.chksum is not None else None,
        })
    if TCP in packet:
        tcp_layer = packet[TCP]
        details.update({
            "tcp_sequence": _safe_int(tcp_layer.seq),
            "tcp_acknowledgment": _safe_int(tcp_layer.ack),
            "tcp_flags": str(tcp_layer.flags),
            "tcp_header_length": (_safe_int(tcp_layer.dataofs) or 0) * 4,
            "tcp_window": _safe_int(tcp_layer.window),
            "tcp_checksum": hex(int(tcp_layer.chksum)) if tcp_layer.chksum is not None else None,
            "tcp_urgent_pointer": _safe_int(tcp_layer.urgptr),
        })
    elif UDP in packet:
        udp_layer = packet[UDP]
        details.update({
            "udp_length": _safe_int(udp_layer.len),
            "udp_checksum": hex(int(udp_layer.chksum)) if udp_layer.chksum is not None else None,
        })
    elif ICMP in packet:
        icmp_layer = packet[ICMP]
        details.update({
            "icmp_type": _safe_int(icmp_layer.type),
            "icmp_code": _safe_int(icmp_layer.code),
            "icmp_id": _safe_int(icmp_layer.id),
            "icmp_sequence": _safe_int(icmp_layer.seq),
            "icmp_checksum": hex(int(icmp_layer.chksum)) if icmp_layer.chksum is not None else None,
        })
    payload = info.get("payload") or b""
    if payload:
        details["payload_preview"] = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:64])
        details["payload_hex"] = payload[:32].hex(" ")
    return {k: v for k, v in details.items() if v is not None}


def packet_to_info(packet) -> Optional[dict]:
    """Normalise IPv4 packets into the shared Delta-NIDS packet contract.

    IPv6 is intentionally ignored so capture, detection, storage, and the
    dashboard remain IPv4-only.
    """
    if IPv6 in packet:
        return None
    if ARP in packet and IP not in packet:
        arp = packet[ARP]
        return {
            "src_ip": getattr(arp, "psrc", None),
            "dst_ip": getattr(arp, "pdst", None),
            "protocol": "ARP",
            "src_port": None,
            "dst_port": None,
            "length": len(packet),
            "payload": b"",
            "icmp_type": None,
            "icmp_code": None,
            "tcp_flags": None,
            "details": {"arp_op": _safe_int(getattr(arp, "op", None))},
            "source": getattr(arp, "psrc", None),
            "destination": getattr(arp, "pdst", None),
        }
    if IP not in packet:
        return None

    # Scapy's IPv6 extension layers can leave the transport protocol hidden
    # from direct layer lookup. Walk the payload chain so TCP/UDP/ICMPv6 remain
    # visible after Hop-by-Hop, Destination, Routing, or Fragment headers.
    transport_layer = None
    if IPv6 in packet and not any(layer_type in packet for layer_type in (TCP, UDP, ICMPv6EchoRequest)):
        transport_layer = packet[IPv6].payload
        for _ in range(16):
            if isinstance(transport_layer, (TCP, UDP, ICMPv6EchoRequest)):
                break
            next_layer = getattr(transport_layer, "payload", None)
            if next_layer is None or next_layer is transport_layer:
                transport_layer = None
                break
            transport_layer = next_layer

    ip_layer = packet[IP]
    info = {
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": "IP",
        "src_port": None,
        "dst_port": None,
        "length": len(packet),
        "payload": b"",
        "icmp_type": None,
        "icmp_code": None,
        "icmp_inner_src_ip": None,
        "icmp_inner_dst_ip": None,
        "icmp_inner_src_port": None,
        "icmp_inner_dst_port": None,
        "icmp_inner_protocol": None,
        "tcp_flags": None,
        "tcp_sequence": None,
        "tcp_acknowledgment": None,
        "icmp_id": None,
        "icmp_sequence": None,
    }
    icmpv6_error_layer = packet[ICMPv6DestUnreach] if ICMPv6DestUnreach in packet else (transport_layer if isinstance(transport_layer, ICMPv6DestUnreach) else None)
    tcp_layer = packet[TCP] if TCP in packet and icmpv6_error_layer is None else (transport_layer if isinstance(transport_layer, TCP) else None)
    udp_layer = packet[UDP] if UDP in packet and icmpv6_error_layer is None else (transport_layer if isinstance(transport_layer, UDP) else None)
    icmpv6_layer = packet[ICMPv6EchoRequest] if ICMPv6EchoRequest in packet and icmpv6_error_layer is None else (transport_layer if isinstance(transport_layer, ICMPv6EchoRequest) else None)
    if tcp_layer is not None:
        info.update(protocol="TCP", src_port=int(tcp_layer.sport), dst_port=int(tcp_layer.dport),
                    tcp_flags=str(tcp_layer.flags), tcp_sequence=_safe_int(tcp_layer.seq),
                    tcp_acknowledgment=_safe_int(tcp_layer.ack), payload=bytes(tcp_layer.payload))
    elif udp_layer is not None:
        info.update(protocol="UDP", src_port=int(udp_layer.sport), dst_port=int(udp_layer.dport),
                    payload=bytes(udp_layer.payload))
    elif ICMP in packet:
        icmp = packet[ICMP]
        info.update(protocol="ICMP", icmp_type=int(icmp.type), icmp_code=int(icmp.code),
                    icmp_id=_safe_int(getattr(icmp, "id", None)),
                    icmp_sequence=_safe_int(getattr(icmp, "seq", None)),
                    payload=bytes(icmp.payload))
        inner = getattr(icmp, "payload", None)
        if inner is not None and IP in inner:
            info["icmp_inner_src_ip"] = inner[IP].src
            info["icmp_inner_dst_ip"] = inner[IP].dst
            info["icmp_inner_protocol"] = str(getattr(inner[IP], "proto", ""))
            if UDP in inner:
                info["icmp_inner_src_port"] = _safe_int(inner[UDP].sport)
                info["icmp_inner_dst_port"] = _safe_int(inner[UDP].dport)
            elif TCP in inner:
                info["icmp_inner_src_port"] = _safe_int(inner[TCP].sport)
                info["icmp_inner_dst_port"] = _safe_int(inner[TCP].dport)
    # Ethernet metadata remains available to the decoder for low-level
    # diagnostics, but it is not part of the normal user-facing normalized
    # packet contract. Traffic persistence/API consumers therefore cannot
    # mistake a MAC address for an IP endpoint.
    decoded = _decoded_details(packet, info)
    info["details"] = {key: value for key, value in decoded.items()
                       if key not in {"src_mac", "dst_mac"}}
    info["source"] = _format_endpoint(info["src_ip"], info["src_port"])
    info["destination"] = _format_endpoint(info["dst_ip"], info["dst_port"])
    return info


# ---------------------------------------------------------------------------
# Windows raw-socket ICMP parser
# ---------------------------------------------------------------------------

def _raw_ip_to_info(raw_data: bytes) -> Optional[dict]:
    """Parse a raw IP packet delivered by a Windows SIO_RCVALL socket.

    Windows raw sockets deliver complete IPv4 packets including the IP header.
    The output dict is identical to what packet_to_info() produces so both
    capture paths feed the same downstream pipeline.
    """
    if len(raw_data) < 20:
        return None
    ip_version = raw_data[0] >> 4
    if ip_version != 4:
        return None
    ihl = (raw_data[0] & 0xF) * 4
    protocol_num = raw_data[9]
    src_ip = socket.inet_ntoa(raw_data[12:16])
    dst_ip = socket.inet_ntoa(raw_data[16:20])
    total_length = struct.unpack("!H", raw_data[2:4])[0]
    ttl = raw_data[8]
    ip_id = struct.unpack("!H", raw_data[4:6])[0]

    info: dict = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": "IP",
        "src_port": None,
        "dst_port": None,
        "length": total_length,
        "payload": b"",
        "icmp_type": None,
        "icmp_code": None,
        "tcp_flags": None,
        "details": {
            "ip_version": 4,
            "ip_header_length": ihl,
            "ip_ttl": ttl,
            "ip_id": ip_id,
            "ip_total_length": total_length,
        },
    }

    transport = raw_data[ihl:]
    if protocol_num == 1 and len(transport) >= 4:   # ICMP
        info.update(protocol="ICMP", icmp_type=transport[0], icmp_code=transport[1],
                    payload=transport[8:])
        if len(transport) >= 8:
            info["details"]["icmp_id"] = struct.unpack("!H", transport[4:6])[0]
            info["details"]["icmp_sequence"] = struct.unpack("!H", transport[6:8])[0]
        inner = _raw_ip_to_info(transport[8:]) if len(transport) > 8 else None
        if inner:
            info["icmp_inner_src_ip"] = inner.get("src_ip")
            info["icmp_inner_dst_ip"] = inner.get("dst_ip")
            info["icmp_inner_protocol"] = inner.get("protocol")
            info["icmp_inner_src_port"] = inner.get("src_port")
            info["icmp_inner_dst_port"] = inner.get("dst_port")
    elif protocol_num == 6 and len(transport) >= 20:  # TCP
        src_port, dst_port = struct.unpack("!HH", transport[0:4])
        data_offset = (transport[12] >> 4) * 4
        flags = transport[13]
        flag_str = "".join(f for f, b in [("F", 0x01), ("S", 0x02), ("R", 0x04),
                                           ("P", 0x08), ("A", 0x10), ("U", 0x20)] if flags & b)
        info.update(protocol="TCP", src_port=src_port, dst_port=dst_port,
                    tcp_flags=flag_str, tcp_sequence=struct.unpack("!I", transport[4:8])[0],
                    tcp_acknowledgment=struct.unpack("!I", transport[8:12])[0],
                    payload=transport[data_offset:])
    elif protocol_num == 17 and len(transport) >= 8:  # UDP
        src_port, dst_port = struct.unpack("!HH", transport[0:4])
        info.update(protocol="UDP", src_port=src_port, dst_port=dst_port,
                    payload=transport[8:])
    info["source"] = _format_endpoint(info["src_ip"], info["src_port"])
    info["destination"] = _format_endpoint(info["dst_ip"], info["dst_port"])
    return info


# ---------------------------------------------------------------------------
# Windows supplementary ICMP capture via raw socket
# ---------------------------------------------------------------------------

class _WindowsRawCapture:
    """Windows-only supplementary ICMP capture using SIO_RCVALL promiscuous raw socket.

    Npcap cannot capture ICMP packets destined to the local machine because
    Windows processes them entirely within the kernel before the Npcap driver
    sees them. This thread runs in parallel with the Npcap sniffer and closes
    that gap for ICMP traffic.

    Requires Administrator privileges. Starts silently and logs a message if
    unavailable; the main Npcap capture continues regardless.

    This class is only ever instantiated on Windows (os.name == "nt").
    Linux/macOS are completely unaffected.
    """

    SIO_RCVALL = 0x98000001

    def __init__(self, local_ip: str, on_packet: Callable[[dict], None]):
        self._local_ip = local_ip
        self._on_packet = on_packet
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stopped = False

    def start(self) -> bool:
        """Open the promiscuous raw socket. Returns True on success."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((self._local_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(self.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(1.0)
            self._sock = s
        except PermissionError:
            logger.info(
                "Windows ICMP raw-socket capture requires Administrator privileges; "
                "ICMP may not be detected if run without elevation. "
                "Continuing with Npcap-only capture."
            )
            return False
        except OSError as exc:
            logger.debug("Windows raw socket unavailable: %s", exc)
            return False

        self._thread = threading.Thread(target=self._loop, name="delta-nids-rawcap", daemon=True)
        self._thread.start()
        logger.info("Windows raw socket ICMP capture started on %s", self._local_ip)
        return True

    def _loop(self) -> None:
        assert self._sock is not None
        while not self._stopped:
            try:
                raw_data, _ = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            info = _raw_ip_to_info(raw_data)
            if info is None:
                continue
            try:
                self._on_packet(info)
            except Exception:
                logger.exception("raw capture packet handler failed")

    def stop(self) -> None:
        self._stopped = True
        if self._sock:
            try:
                self._sock.ioctl(self.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3)


# ---------------------------------------------------------------------------
# Main PacketCapture class
# ---------------------------------------------------------------------------

class PacketCapture:
    """Packet source supporting one-shot PCAP replay or continuous live capture.

    On Windows a supplementary raw-socket thread captures ICMP and TCP/UDP traffic that
    Npcap cannot see or filters out on Wi-Fi. Requires Administrator; falls back silently if unavailable.
    On Linux/macOS only the Scapy/pcap path is used (behaviour unchanged).
    """

    def __init__(self, on_packet: Callable[[dict], None], interface: Optional[str] = None,
                 pcap_path: Optional[str] = None, bpf_filter: Optional[str] = None,
                 count: int = 0):
        if not interface and not pcap_path:
            raise ValueError("one of interface or pcap_path is required")
        self.on_packet = on_packet
        self.interface = interface
        self.pcap_path = pcap_path
        self.bpf_filter = bpf_filter
        self.count = count
        self._stopped = False
        self.packets_seen = 0
        self.packets_failed = 0
        self.last_packet_time = None
        self.state = "STARTING"
        self._raw_cap: Optional[_WindowsRawCapture] = None
        self._seen_lock = threading.Lock()
        # Keys are retained only briefly so overlapping capture backends do not
        # double-dispatch a frame, while a later real scan with identical probe
        # fields is still observable.
        self._seen_packets: dict[tuple, float] = {}
        self._duplicate_window_seconds = 1.0

    def _is_duplicate(self, info: dict) -> bool:
        details = info.get("details") or {}
        key = (
            info.get("src_ip"),
            info.get("dst_ip"),
            info.get("protocol"),
            info.get("src_port"),
            info.get("dst_port"),
            details.get("ip_id"),
            info.get("tcp_flags"),
            info.get("tcp_sequence"),
            info.get("icmp_sequence"),
            hashlib.sha256(info.get("payload") or b"").digest(),
            len(info.get("payload") or b"")
        )
        now = time.monotonic()
        with self._seen_lock:
            cutoff = now - self._duplicate_window_seconds
            self._seen_packets = {
                packet_key: seen_at for packet_key, seen_at in self._seen_packets.items()
                if seen_at >= cutoff
            }
            if key in self._seen_packets:
                return True
            self._seen_packets[key] = now
            if len(self._seen_packets) > 10000:
                oldest = sorted(self._seen_packets, key=self._seen_packets.get)
                for packet_key in oldest[:len(self._seen_packets) - 10000]:
                    self._seen_packets.pop(packet_key, None)
            return False

    def _dispatch(self, packet, monotonic: Optional[float] = None) -> None:
        if self._stopped:
            return
        try:
            info = packet_to_info(packet)
            if info is not None and not self._stopped:
                if monotonic is not None:
                    # PCAP replay drives the detection clock from the capture
                    # timestamps so sliding windows, flow/session expiry, and
                    # deduplication behave exactly as they did during the live
                    # capture. Wall-clock time is never used for replay state.
                    info["_monotonic"] = float(monotonic)
                if self._is_duplicate(info):
                    return
                self.packets_seen += 1
                self.last_packet_time = time.time()
                self.on_packet(info)
        except Exception:
            self.packets_failed += 1
            self.state = "DEGRADED"
            logger.exception("packet processing failed; capture loop continues")

    def _dispatch_raw(self, info: dict) -> None:
        """Forward a pre-parsed packet dict from the Windows raw-socket thread."""
        if self._stopped:
            return
        try:
            if self._is_duplicate(info):
                return
            self.packets_seen += 1
            self.last_packet_time = time.time()
            self.on_packet(info)
        except Exception:
            self.packets_failed += 1
            self.state = "DEGRADED"
            logger.exception("raw packet dispatch failed; continuing")

    def _resolve_iface_windows(self, name: str):
        """Resolve a human-readable interface name to a Scapy interface object."""
        if not hasattr(conf, "ifaces"):
            return name

        def _norm(s: str) -> str:
            return s.lower().replace("-", "").replace(" ", "").replace("_", "")

        want = _norm(name)
        matched = None
        for dev in conf.ifaces.values():                # Pass 1: exact
            if name in (getattr(dev, "name", ""), getattr(dev, "description", ""),
                        getattr(dev, "network_name", "")):
                matched = dev
                break
        if matched is None:                             # Pass 2: normalised
            for dev in conf.ifaces.values():
                if want in (_norm(getattr(dev, "name", "")), _norm(getattr(dev, "description", ""))):
                    matched = dev
                    break
        if matched is None:                             # Pass 3: substring
            for dev in conf.ifaces.values():
                if want in _norm(getattr(dev, "name", "")) or want in _norm(getattr(dev, "description", "")):
                    matched = dev
                    break
        if matched is not None:
            logger.debug("Windows interface '%s' resolved to: %s", name, getattr(matched, "name", matched))
            return matched
        logger.warning("Windows interface '%s' not in conf.ifaces; passing name as-is", name)
        return name

    def run(self) -> None:
        self._stopped = False
        self.state = "RUNNING"
        # ---- PCAP replay path ------------------------------------------------
        if self.pcap_path:
            try:
                last_timestamp: Optional[float] = None
                for packet in rdpcap(self.pcap_path):
                    if self._stopped:
                        break
                    timestamp = getattr(packet, "time", None)
                    if timestamp is not None:
                        # PCAPs are normally monotonic; clamp any backward jump
                        # so the detection clock never runs backwards.
                        timestamp = float(timestamp)
                        if last_timestamp is not None and timestamp < last_timestamp:
                            timestamp = last_timestamp
                        last_timestamp = timestamp
                    self._dispatch(packet, monotonic=timestamp)
            finally:
                if self._stopped:
                    self.state = "STOPPED"
            return
        # ---- Live capture path -----------------------------------------------
        try:
            iface_arg = self.interface
            if os.name == "nt" and isinstance(self.interface, str):
                iface_arg = self._resolve_iface_windows(self.interface)
                # Start the supplementary Windows ICMP capture thread.
                # It binds to the interface's local IP to target the right adapter.
                local_ip = getattr(iface_arg, "ip", None) if iface_arg is not self.interface else None
                if local_ip and local_ip not in ("0.0.0.0", ""):
                    self._raw_cap = _WindowsRawCapture(local_ip, self._dispatch_raw)
                    self._raw_cap.start()

            # Use no BPF filter when bpf_filter is empty so ALL protocols are
            # captured (ICMP, TCP, UDP, ARP, etc.) and packet_to_info silently
            # discards non-IPv4 frames. A non-empty filter is honoured as-is.
            filter_arg = self.bpf_filter if self.bpf_filter else None
            previous_bufsize = conf.bufsize
            # Scanner-class bursts (masscan/nmap at 10k+ pps) can overflow the
            # default 64 KiB receive buffer and silently drop the packets the
            # detector needs. Enlarge the socket buffer for the capture.
            conf.bufsize = max(conf.bufsize, 16 * 1024 * 1024)
            try:
                sniff(iface=iface_arg, filter=filter_arg, prn=self._dispatch,
                      store=False, count=self.count, stop_filter=lambda _: self._stopped)
            finally:
                conf.bufsize = previous_bufsize
        except Exception:
            self.state = "ERROR"
            logger.exception("capture backend stopped unexpectedly")
            raise
        finally:
            if self._raw_cap:
                self._raw_cap.stop()
                self._raw_cap = None
            if self._stopped:
                self.state = "STOPPED"

    def stop(self) -> None:
        self._stopped = True
        if self._raw_cap:
            self._raw_cap.stop()
        if self.state != "ERROR":
            self.state = "STOPPED"
