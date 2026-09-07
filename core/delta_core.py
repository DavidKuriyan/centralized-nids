from __future__ import annotations

import heapq
import ipaddress
import re
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from typing import Any


# Service ports that are ordinary client destinations. Outbound callbacks to
# any other port are behaviourally unusual and contribute to reverse-shell
# scoring. SSH (22) is excluded from reverse-shell evaluation because a normal
# interactive SSH session is indistinguishable from an SSH-borne tunnel.
COMMON_CLIENT_PORTS = frozenset({
    21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 443, 465, 587, 636, 853, 993,
    995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
})

# Ports that are frequent exploitation targets; a strong shell-invocation
# payload toward one of these is reported as possible exploitation activity.
_EXPLOIT_TARGET_PORTS = frozenset({
    21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521,
    2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017,
})

# Interactive shell markers. These are corroborating evidence for reverse-shell
# evaluation, never the sole trigger (the requirement forbids single
# tool/payload-string rules).
_SHELL_INDICATORS = (
    b"/bin/sh", b"/bin/bash", b"/bin/zsh", b"/bin/ash", b"sh -i", b"bash -i",
    b"sh -c", b"bash -c", b"cmd.exe", b"powershell", b"whoami", b"uname -a",
    b"id &&", b"id;", b"nc -e", b"ncat -e", b"/dev/tcp/", b"socat",
    b"python -c", b"python3 -c", b"perl -e", b"chmod +x", b"busybox",
    b"exec 5<>", b"mkfifo", b"mknod", b"cat /etc/passwd", b"ls -la", b"ls -al",
    b"pty", b"setsid",
)
_SHELL_RE = re.compile(b"|".join(re.escape(indicator) for indicator in _SHELL_INDICATORS))

# Stronger shell-invocation markers: executable launch of a shell interpreter
# or a reverse-shell plumbing primitive. These are the basis for the possible
# exploitation event (SID 90011).
_STRONG_SHELL_INDICATORS = (
    b"/bin/sh", b"/bin/bash", b"/bin/zsh", b"/bin/ash", b"sh -i", b"bash -i",
    b"sh -c", b"bash -c", b"cmd.exe", b"powershell", b"nc -e", b"ncat -e",
    b"/dev/tcp/", b"socat", b"python -c", b"python3 -c", b"perl -e",
    b"exec 5<>", b"mkfifo", b"mknod",
)
_STRONG_SHELL_RE = re.compile(b"|".join(re.escape(indicator) for indicator in _STRONG_SHELL_INDICATORS))

_HTTP_REQUEST_RE = re.compile(rb"^([A-Z]+)\s+(\S+)\s+HTTP/1\.[01]")

# TLS record types: change-cipher-spec(20), alert(21), handshake(22),
# application-data(23). A stream whose payloads all carry TLS records or HTTP
# framing is a web protocol conversation (browsing/API), which must never be
# scored as a raw reverse-shell session.
_TLS_RECORD_TYPES = frozenset((20, 21, 22, 23))
_HTTP2_PREFACE = b"PRI * HTTP/2.0"


def _is_web_framed_payload(payload: bytes) -> bool:
    """True when the payload is a TLS record, an HTTP message, or an h2 preface.

    A genuine reverse shell over a common port speaks a raw interactive
    protocol (plain shell commands/output), not TLS/HTTP framing, so web-framed
    streams can be excluded from reverse-shell scoring without hiding real
    shells.
    """
    if not payload:
        return False
    if len(payload) >= 3 and payload[0] in _TLS_RECORD_TYPES and payload[1] == 0x03:
        return True
    if payload.startswith((b"HTTP/1.", b"HTTP/2 ")) or payload.startswith(_HTTP2_PREFACE):
        return True
    return _HTTP_REQUEST_RE.match(payload) is not None


# FTP product/version extraction from a 220 greeting line.
_FTP_PRODUCT_RE = re.compile(
    r"(?i)(vsftpd|proftpd|pure-?ftpd|wu-?ftpd|filezilla|microsoft ftp|serv-u|iis|glftpd|bftpd|pyftpdlib)[^0-9]{0,8}([0-9][0-9a-zA-Z._-]*)"
)
_FTP_VERSION_RE = re.compile(r"(?i)\b([a-z][a-z0-9._-]{1,24})\s+v?(\d[0-9a-zA-Z._-]{0,12})")


def _bounded_list(values, limit: int = 96) -> str:
    """Render a sorted list compactly, truncating huge scanner-scale evidence.

    Masscan/RustScan-class probes can cover the full 65,535-port space and
    Zmap-class host sweeps can cover large subnets. Alert evidence must stay
    bounded regardless of how many distinct ports or targets the scanner
    emits, while the complete distinct count is always preserved.
    """
    values = list(values)
    try:
        ordered = sorted(values)  # ports sort numerically, addresses as strings
    except TypeError:
        ordered = sorted(str(value) for value in values)
    if len(ordered) <= limit:
        return ", ".join(str(value) for value in ordered)
    return ", ".join(str(value) for value in ordered[:limit]) + f", ... (+{len(ordered) - limit} more)"


class DeltaCore:
    """Coordinates packet normalization, signature detection, and behavioral detection.

    Behavioral state is deliberately keyed by the complete observation scope. A
    scanner cannot contaminate another source, target, protocol, or scan class.
    The implementation reports observable behavior (not the originating tool).

    Evidence contract: every alert generated here is derived from observed
    packet fields (source, destination, protocol, ports, flags, ICMP metadata,
    timestamps). No synthetic or simulated events are ever generated.
    """

    TCP_FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}

    def __init__(self, alert_manager, detection_engine, scan_window: float = 30.0,
                 port_threshold: int = 8, ping_threshold: int = 5,
                 remote_sweep_threshold: int = 200,
                 remote_sweep_enabled: bool = False,
                 dns_threshold: int = 50, brute_force_threshold: int = 10,
                 syn_flood_threshold: int = 100,
                 ssh_brute_force_threshold: int = 10,
                 ssh_brute_force_window: float = 60.0,
                 ftp_grab_threshold: int = 1, ftp_enum_window: float = 60.0,
                 ftp_brute_force_threshold: int = 10,
                 ftp_brute_force_window: float = 60.0,
                 http_enum_threshold: int = 40, http_enum_window: float = 60.0,
                 reverse_shell_min_duration: float = 30.0,
                 connection_idle_timeout: float = 120.0,
                 correlation_window: float = 600.0):
        self.alert_manager = alert_manager
        self.detection_engine = detection_engine
        self.scan_window = float(scan_window)
        self.port_threshold = max(2, int(port_threshold))
        self.ping_threshold = max(2, int(ping_threshold))
        self.remote_sweep_threshold = max(2, int(remote_sweep_threshold))
        self.remote_sweep_enabled = bool(remote_sweep_enabled)
        self.dns_threshold = max(2, int(dns_threshold))
        self.brute_force_threshold = max(2, int(brute_force_threshold))
        # SYN flood fires once bare half-open SYN attempts toward one service
        # endpoint reach the threshold inside the window.
        self.syn_flood_threshold = max(2, int(syn_flood_threshold))
        # Brute force fires once the number of failed authentication attempts
        # reaches the configured threshold (default 10) inside the window.
        self.ssh_brute_force_threshold = max(2, int(ssh_brute_force_threshold))
        self.ssh_brute_force_window = max(5.0, float(ssh_brute_force_window))
        self.ftp_brute_force_threshold = max(2, int(ftp_brute_force_threshold))
        self.ftp_brute_force_window = max(5.0, float(ftp_brute_force_window))
        self.ftp_grab_threshold = max(1, int(ftp_grab_threshold))
        self.ftp_enum_window = max(5.0, float(ftp_enum_window))
        self.http_enum_threshold = max(5, int(http_enum_threshold))
        self.http_enum_window = max(5.0, float(http_enum_window))
        self.reverse_shell_min_duration = max(1.0, float(reverse_shell_min_duration))
        self.connection_idle_timeout = max(10.0, float(connection_idle_timeout))
        self.correlation_window = max(30.0, float(correlation_window))
        self.total_data = 0
        self.unique_ips = set()
        self.flows = set()
        self.packets_sniffed = 0

        # (source, destination, protocol, probe class) -> observations.
        self._ports: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        # TCP response evidence is only valid for an observed probe with the
        # same destination port and a compatible reverse direction. Keeping it
        # in the probe state prevents unrelated packets from completing a scan.
        self._tcp_response_ttl = max(1.0, self.scan_window)
        # Host-discovery observations keyed by
        # (source, protocol, probe signature, target scope).
        self._hosts: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        # Source -> DNS query-rate observations (outbound queries, not replies).
        self._dns: dict[str, dict[str, Any]] = {}
        # (source, destination, destination port) -> connection failure observations.
        self._brute: dict[tuple[str, str, int], dict[str, Any]] = {}
        # (source, destination, destination port) -> half-open SYN observations.
        self._synflood: dict[tuple[str, str, int], dict[str, Any]] = {}
        # SSH sessions toward one service:
        # (client_ip, server_ip, service_port) -> {sessions, emitted}.
        self._ssh: dict[tuple[str, str, int], dict[str, Any]] = {}
        # FTP banner-grabbing evidence per target service:
        # (client_ip, server_ip, service_port) -> {grabs, emitted}.
        self._ftp_grabs: dict[tuple[str, str, int], dict[str, Any]] = {}
        # Per-TCP-connection tracking state keyed by the SYN orientation
        # (client_ip, client_port, server_ip, server_port). Drives SSH/FTP
        # session identification, reverse-shell evaluation, and multi-stage
        # correlation. Directional (reverse) lookups are resolved on read.
        self._conns: dict[tuple[str, int, str, int], dict[str, Any]] = {}
        # HTTP resource enumeration per target web service:
        # (source, destination, dst_port) -> {paths, emitted}.
        self._http_enum: dict[tuple[str, str, int], dict[str, Any]] = {}
        # Attack-sequence correlation: (attacker, victim) -> {first_seen, last_seen}.
        self._recon: dict[tuple[str, str], dict[str, Any]] = {}
        self._last_conn_prune = 0.0
        self._last_http_prune = 0.0
        # (source, destination, protocol) -> last window epoch that emitted an
        # ICMP echo visibility event. Ordinary echo requests are a bounded,
        # low-severity visibility event, not an attack by themselves.
        self._icmp_events: dict[tuple[str, str, str], tuple[float, int]] = {}
        # FTP failed-login brute force per (client, server, service port):
        # sliding window of failed authentication timestamps.
        self._ftp_auth: dict[tuple[str, str, int], dict[str, Any]] = {}
        # Compatibility name retained for callers that inspect bounded ping
        # state; it references the same host-discovery map.
        self._pings = self._hosts
        self._last_ping: dict[tuple[str, str], float] = {}
        self._event_sequence = 0
        self._lock = threading.RLock()
        self._max_scan_states = 4096
        self._max_host_states = 4096
        self._max_dns_states = 1024
        self._max_brute_states = 1024
        self._max_synflood_states = 1024
        self._max_icmp_event_states = 4096
        self._max_ssh_states = 2048
        self._max_ftp_grab_states = 2048
        self._max_ftp_auth_states = 2048
        self._max_conn_states = 8192
        self._max_http_states = 2048
        self._max_recon_states = 4096

    @staticmethod
    def _is_same_subnet(ip1: str, ip2: str) -> bool:
        try:
            a = ipaddress.ip_address(ip1)
            b = ipaddress.ip_address(ip2)
            return a.version == b.version and a.is_private and b.is_private and \
                str(a).rsplit(".", 1)[0] == str(b).rsplit(".", 1)[0]
        except ValueError:
            return False

    @staticmethod
    def _tcp_flags(value: Any) -> int:
        if isinstance(value, int):
            return value
        return sum(bit for name, bit in DeltaCore.TCP_FLAG_BITS.items()
                   if name in str(value or "").upper())

    @staticmethod
    def _flag_class(flags: int) -> str | None:
        """Return a behavioral class for an active TCP probe.

        ACK-only probes are inherently ambiguous from a passive vantage point,
        so they require the same multi-port threshold as other probes and are
        reported as "possible" behavior rather than a definitive scan.

        SYN+FIN returns None here because it is an invalid combination that is
        reported separately as a protocol anomaly.
        """
        if flags & 0x02 and flags & 0x01:
            # SYN+FIN is an invalid combination, not a normal SYN probe.
            return None
        if flags & 0x02 and not (flags & (0x10 | 0x04)):
            return "syn"
        if flags == 0x10:
            return "ack"
        if flags == (0x01 | 0x10):
            # Maimon-style probes use FIN+ACK.
            return "maimon"
        if flags == 0x01:
            return "fin"
        if flags == 0:
            return "null"
        if flags == (0x01 | 0x08 | 0x20):
            return "xmas"
        return None

    def _next_event_id(self, prefix: str) -> str:
        self._event_sequence += 1
        return f"{prefix}-{self._event_sequence}"

    def _alert(self, packet: dict, sid: int, severity: str, message: str,
               evidence: str | None = None, explanation: str | None = None,
               event_id: str | None = None, **extra: Any) -> None:
        alert = {**packet, "sid": sid, "severity": severity, "message": message,
                 "is_ml_anomaly": False}
        if evidence is not None:
            alert["evidence"] = evidence
        if explanation is not None:
            alert["explanation"] = explanation
        if event_id is not None:
            alert["event_id"] = event_id
        alert.update(extra)
        self.alert_manager.log_alert(alert)

    def _evict_oldest(self, coll: dict, cap: int, last_seen_of) -> None:
        """Amortized size-cap eviction for a detector state table.

        Evicts the least-recently-seen entries down to a low watermark in bulk
        (never a full sort on every packet of a burst), so re-crossing the cap
        is occasional and work stays bounded under high packet rates.
        """
        if len(coll) <= cap:
            return
        target = max(1, cap * 3 // 4)
        victims = heapq.nsmallest(len(coll) - target, coll.items(),
                                  key=lambda kv: last_seen_of(kv[1]))
        for key, _state in victims:
            coll.pop(key, None)

    def _prune_ports(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, state in list(self._ports.items()):
            observations = state["observations"]
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            if not observations:
                self._ports.pop(key, None)
                continue
            ports = {port for _, port in observations}
            if len(ports) < self.port_threshold:
                # Allow a later scan with the same source/target/class to emit a
                # new event after its previous window has genuinely ended.
                state["emitted"] = False
        self._evict_oldest(self._ports, self._max_scan_states,
                           lambda state: state["observations"][-1][0])

    def _threshold_for(self, protocol: str, scope: str) -> int:
        """Distinct-target threshold for a host-discovery correlation bucket.

        Locally-scoped probes (private hosts on the local segment / private
        ranges) use the standard host-sweep threshold. Globally-routable
        (Internet) destinations are ordinary client egress and are only
        correlated when remote sweep detection is explicitly enabled, with a
        far higher threshold.
        """
        if scope == "public":
            return self.remote_sweep_threshold if self.remote_sweep_enabled else 0
        return self.ping_threshold

    def _prune_hosts(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, state in list(self._hosts.items()):
            observations = state["observations"]
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            if not observations:
                self._hosts.pop(key, None)
                continue
            protocol, scope = key[1], key[3]
            threshold = self._threshold_for(protocol, scope)
            if threshold == 0 or len({target for _, target in observations}) < threshold:
                state["emitted"] = False
        self._evict_oldest(self._hosts, self._max_host_states,
                           lambda state: state["observations"][-1][0])

    def _prune_dns(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, state in list(self._dns.items()):
            observations = state["observations"]
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            names = state.get("names", {})
            if names:
                for name, seen_at in list(names.items()):
                    if seen_at < cutoff:
                        names.pop(name, None)
            if not observations and not names:
                self._dns.pop(key, None)
                continue
            count = len(names) if names else len(observations)
            if count < self.dns_threshold:
                state["emitted"] = False
        self._evict_oldest(self._dns, self._max_dns_states,
                           lambda state: state["observations"][-1][0]
                           if state["observations"] else max(state.get("names", {}).values()))

    def _prune_brute(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, state in list(self._brute.items()):
            observations = state["observations"]
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            if not observations:
                self._brute.pop(key, None)
                continue
            if len(observations) < self.brute_force_threshold:
                state["emitted"] = False
        self._evict_oldest(self._brute, self._max_brute_states,
                           lambda state: state["observations"][-1][0])

    def _prune_synflood(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, state in list(self._synflood.items()):
            observations = state["observations"]
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            if not observations:
                self._synflood.pop(key, None)
                continue
            pending = state.get("pending")
            if pending:
                for seq, seen_at in list(pending.items()):
                    if seen_at < cutoff:
                        pending.pop(seq, None)
            if len(observations) < self.syn_flood_threshold:
                # Allow a later flood from the same source/target to emit a new
                # event after its previous window has genuinely ended.
                state["emitted"] = False
        self._evict_oldest(self._synflood, self._max_synflood_states,
                           lambda state: state["observations"][-1][0])

    def _prune_icmp_events(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, (seen_at, _window) in list(self._icmp_events.items()):
            if seen_at < cutoff:
                self._icmp_events.pop(key, None)
        self._evict_oldest(self._icmp_events, self._max_icmp_event_states,
                           lambda state: state[0])

    # ------------------------------------------------------------------
    # SSH brute-force detection
    #
    # SSH authentication happens after the encrypted key exchange, so password
    # success/failure is not observable passively. What IS observable is the
    # cleartext banner exchange: every authentication attempt from a
    # connection-per-attempt tool (hydra, medusa, ...) opens a new TCP
    # connection, exchanges "SSH-2.0-..." banners in both directions, and
    # closes. We count completed banner exchanges (sessions) toward one SSH
    # service within a sliding window; more than `ssh_brute_force_threshold`
    # sessions is reported as a brute-force campaign. Banner-based service
    # identification makes non-standard SSH ports detectable.
    # ------------------------------------------------------------------

    def _prune_ssh(self, now: float) -> None:
        cutoff = now - self.ssh_brute_force_window
        for key, state in list(self._ssh.items()):
            sessions = state["sessions"]
            while sessions and sessions[0][0] < cutoff:
                sessions.popleft()
            if not sessions:
                self._ssh.pop(key, None)
                continue
            if len({port for _, port in sessions}) < self.ssh_brute_force_threshold:
                state["emitted"] = False
        self._evict_oldest(self._ssh, self._max_ssh_states,
                           lambda state: state["sessions"][-1][0])

    def _register_ssh_session(self, state: dict[str, Any], packet: dict, now: float) -> None:
        client = state["client_ip"]
        server = state["server_ip"]
        client_port = state["client_port"]
        service_port = int(state.get("syn_port") if state.get("syn_port") is not None else state["server_port"])
        key = (client, server, service_port)
        ssh_state = self._ssh.setdefault(key, {"sessions": deque(), "emitted": False})
        sessions = ssh_state["sessions"]
        if not any(existing_port == client_port for _, existing_port in sessions):
            sessions.append((now, client_port))
        self._prune_ssh(now)
        distinct = {session_port for _, session_port in sessions}
        if len(distinct) >= self.ssh_brute_force_threshold and not ssh_state["emitted"]:
            ssh_state["emitted"] = True
            event_id = self._next_event_id("ssh-brute-force")
            evidence = (f"attack_type=ssh_brute_force; service=ssh; source={client}; "
                        f"destination={server}; destination_port={service_port}; "
                        f"failed_authentication_attempts={len(distinct)}; "
                        f"window_seconds={self.ssh_brute_force_window:g}; "
                        f"threshold={self.ssh_brute_force_threshold}; "
                        f"client_source_ports=[{_bounded_list(sorted(distinct))}]")
            self._alert(packet, 90007, "High",
                        f"SSH brute force / repeated authentication attempts from {client} "
                        f"to {server}:{service_port} ({len(distinct)} sessions in "
                        f"{self.ssh_brute_force_window:g}s)",
                        evidence=evidence,
                        explanation=("{0} or more completed SSH banner exchanges toward one SSH service "
                                     "within {1:g}s; each session is the observable proxy for one "
                                     "authentication attempt (auth result is encrypted)".format(
                                         self.ssh_brute_force_threshold, self.ssh_brute_force_window)),
                        event_id=event_id,
                        detection_type="ssh_brute_force", service="ssh", confidence=85)
            self._record_recon(client, server, now)

    # ------------------------------------------------------------------
    # FTP banner/version enumeration detection
    #
    # An FTP server greets every connection with a "220" line. Legitimate
    # sessions continue with a USER command; a banner grab connects, receives
    # the greeting, and closes without issuing any command. The greeting
    # product/version (when the server discloses it) is reported as evidence.
    # Sessions are identified from the observed connection (SYN -> greeting
    # -> close), so a normal FTP session (USER observed) never alerts, and
    # non-standard FTP ports are recognized from the 220 greeting itself.
    # ------------------------------------------------------------------

    def _prune_ftp_grabs(self, now: float) -> None:
        cutoff = now - self.ftp_enum_window
        for key, state in list(self._ftp_grabs.items()):
            grabs = state["grabs"]
            while grabs and grabs[0] < cutoff:
                grabs.popleft()
            if not grabs:
                self._ftp_grabs.pop(key, None)
                continue
            if len(grabs) < self.ftp_grab_threshold:
                state["emitted"] = False
        self._evict_oldest(self._ftp_grabs, self._max_ftp_grab_states,
                           lambda state: state["grabs"][-1])

    @staticmethod
    def _ftp_version(banner_text: str) -> str | None:
        match = _FTP_PRODUCT_RE.search(banner_text)
        if match:
            return match.group(0)[:64]
        match = _FTP_VERSION_RE.search(banner_text)
        if match:
            return match.group(0)[:64]
        return None

    def _evaluate_ftp_session(self, state: dict[str, Any], packet: dict, now: float) -> None:
        if state.get("ftp_evaluated"):
            return
        state["ftp_evaluated"] = True
        banner = state.get("ftp_banner")
        if not banner or not state.get("syn"):
            return
        if state.get("ftp_client_data"):
            # Legitimate session: the client issued a command (USER/PASS/...).
            return
        client = state["client_ip"]
        server = state["server_ip"]
        service_port = int(state.get("syn_port") if state.get("syn_port") is not None else state["server_port"])
        banner_text = banner.decode("utf-8", errors="replace").strip()
        version = self._ftp_version(banner_text)
        key = (client, server, service_port)
        grab_state = self._ftp_grabs.setdefault(key, {"grabs": deque(), "emitted": False})
        grab_state["grabs"].append(now)
        self._prune_ftp_grabs(now)
        grabs = grab_state["grabs"]
        if len(grabs) >= self.ftp_grab_threshold and not grab_state["emitted"]:
            grab_state["emitted"] = True
            event_id = self._next_event_id("ftp-banner-grab")
            evidence = (f"attack_type=ftp_banner_enumeration; service=ftp; source={client}; "
                        f"destination={server}; destination_port={service_port}; "
                        f"banner=[{banner_text[:128]}]; version={version or 'not-disclosed'}; "
                        f"banner_grabs={len(grabs)}; window_seconds={self.ftp_enum_window:g}")
            self._alert(packet, 90008, "Medium",
                        f"FTP banner/version enumeration (banner grabbing) from {client} "
                        f"to {server}:{service_port}",
                        evidence=evidence,
                        explanation=("FTP connection received the server 220 greeting and closed without "
                                     "issuing any command (no USER/PASS), the observable banner-grab pattern"),
                        event_id=event_id,
                        detection_type="ftp_banner_enumeration", service="ftp", confidence=75)
            self._record_recon(client, server, now)

    def _ftp_banner_enumeration(self, packet: dict, now: float) -> None:
        state, _oriented = self._lookup_connection(packet)
        if state is None or not state.get("closed"):
            return
        self._evaluate_ftp_session(state, packet, now)

    # ------------------------------------------------------------------
    # FTP brute force (repeated failed logins)
    #
    # FTP authentication is cleartext: a failed login is observable as a 5xx
    # reply (typically 530) after the client sent PASS. Each failed login is
    # counted per (source, server, service port) inside a sliding window;
    # reaching the threshold (default 10) emits one brute-force alert.
    # ------------------------------------------------------------------

    def _prune_ftp_auth(self, now: float) -> None:
        cutoff = now - self.ftp_brute_force_window
        for key, state in list(self._ftp_auth.items()):
            times = state["times"]
            while times and times[0] < cutoff:
                times.popleft()
            if not times:
                self._ftp_auth.pop(key, None)
                continue
            if len(times) < self.ftp_brute_force_threshold:
                state["emitted"] = False
        self._evict_oldest(self._ftp_auth, self._max_ftp_auth_states,
                           lambda state: state["times"][-1])

    def _maybe_ftp_auth_failure(self, state: dict[str, Any], packet: dict, now: float) -> None:
        """Register one failed FTP login when the connection closed after one."""
        if not state.get("syn") or not state.get("ftp_auth_failed"):
            return
        client = state["client_ip"]
        server = state["server_ip"]
        service_port = int(state.get("syn_port") if state.get("syn_port") is not None else state["server_port"])
        key = (client, server, service_port)
        auth_state = self._ftp_auth.setdefault(key, {"times": deque(), "emitted": False})
        auth_state["times"].append(now)
        self._prune_ftp_auth(now)
        times = auth_state["times"]
        if len(times) >= self.ftp_brute_force_threshold and not auth_state["emitted"]:
            auth_state["emitted"] = True
            event_id = self._next_event_id("ftp-brute-force")
            evidence = (f"attack_type=ftp_brute_force; service=ftp; source={client}; "
                        f"destination={server}; destination_port={service_port}; "
                        f"failed_authentication_attempts={len(times)}; "
                        f"window_seconds={self.ftp_brute_force_window:g}; "
                        f"threshold={self.ftp_brute_force_threshold}")
            self._alert(packet, 90013, "Medium",
                        f"FTP brute force / repeated failed logins from {client} "
                        f"to {server}:{service_port} ({len(times)} failures in "
                        f"{self.ftp_brute_force_window:g}s)",
                        evidence=evidence,
                        explanation=("{0} or more failed FTP logins (5xx reply after PASS) toward one "
                                     "FTP service within {1:g}s".format(
                                         self.ftp_brute_force_threshold, self.ftp_brute_force_window)),
                        event_id=event_id,
                        detection_type="ftp_brute_force", service="ftp", confidence=80)
            self._record_recon(client, server, now)

    # ------------------------------------------------------------------
    # Per-connection tracking (TCP)
    #
    # One bounded state per observed TCP connection, keyed by the SYN
    # orientation. Tracks bidirectional payload volume, shell-like content,
    # SSH/FTP service evidence, and lifetime; drives SSH brute force, FTP
    # banner grabbing, reverse-shell evaluation, and multi-stage correlation.
    # ------------------------------------------------------------------

    @staticmethod
    def _is_private_ip(value: str) -> bool:
        """True for private, loopback, link-local, and reserved ranges.

        Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
        are treated as non-public so offline test traffic behaves like an
        internal network.
        """
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast:
            return True
        return not address.is_global

    def _new_connection_state(self, client_ip: str, client_port: int,
                              server_ip: str, server_port: int, now: float) -> dict[str, Any]:
        return {
            "client_ip": str(client_ip), "client_port": int(client_port),
            "server_ip": str(server_ip), "server_port": int(server_port),
            "created": now, "last": now, "syn": False, "syn_port": None,
            "client_pkts": 0, "client_bytes": 0,
            "server_pkts": 0, "server_bytes": 0,
            "shell_hits": [], "strong_shell": False,
            "ssh_client": False, "ssh_server": False,
            "ftp_banner": None, "ftp_client_data": False,
            "ftp_pass_seen": False, "ftp_auth_failed": False,
            "web_payloads": 0, "raw_payloads": 0,
            "closed": False, "closed_at": None, "evaluated": False,
            "ftp_evaluated": False, "exploit_checked": False,
        }

    def _lookup_connection(self, packet: dict) -> tuple[dict[str, Any] | None, bool]:
        """Return (connection state, packet_src_is_client)."""
        src = packet.get("src_ip")
        dst = packet.get("dst_ip")
        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")
        if not src or not dst or src_port is None or dst_port is None:
            return None, False
        forward = (str(src), int(src_port), str(dst), int(dst_port))
        reverse = (str(dst), int(dst_port), str(src), int(src_port))
        state = self._conns.get(forward)
        if state is not None:
            return state, True
        state = self._conns.get(reverse)
        if state is not None:
            return state, False
        return None, False

    def _inspect_payload(self, state: dict[str, Any], payload: bytes, from_client: bool, now: float) -> None:
        if b"SSH-" in payload:
            if from_client:
                state["ssh_client"] = True
            else:
                state["ssh_server"] = True
        if from_client and payload.startswith((b"USER ", b"PASS ", b"AUTH ", b"SYST ", b"FEAT ", b"PWD ",
                                               b"CWD ", b"LIST", b"TYPE ", b"PORT ", b"PASV", b"QUIT", b"NOOP")):
            # A client command after the greeting means a legitimate FTP
            # session rather than a bare banner grab.
            state["ftp_client_data"] = True
        if from_client and payload.startswith(b"PASS "):
            state["ftp_pass_seen"] = True
        if not from_client and state.get("ftp_pass_seen") and payload[:1] == b"5" and len(payload) >= 4 and payload[1:3].isdigit():
            # A 5xx FTP reply after PASS means the login attempt failed
            # (530 Login incorrect, 500/501/532 ...). Successful logins reply
            # 230 and never set this flag.
            state["ftp_auth_failed"] = True
        if not from_client and (payload.startswith(b"220 ") or payload.startswith(b"220-")):
            # Server 220 greeting identifies the FTP service. Keep the first
            # line (the greeting) for banner/version evidence.
            if state.get("ftp_banner") is None:
                state["ftp_banner"] = payload.split(b"\r\n", 1)[0][:256]
                state["ftp_banner_at"] = now
        if _is_web_framed_payload(payload):
            # TLS records, HTTP messages, and h2 prefaces mark the stream as a
            # protocol conversation (browsing/API traffic). A stream made up
            # entirely of such payloads is never a raw interactive shell.
            state["web_payloads"] += 1
        elif payload:
            state["raw_payloads"] += 1
        lowered = payload.lower()
        # URL-decoded form so shell markers hidden behind percent/plus
        # encoding (e.g. `;bash+-i` in a query string) are still seen.
        try:
            decoded = lowered.replace(b"+", b" ")
            decoded = urllib.parse.unquote_to_bytes(decoded)
        except Exception:
            decoded = lowered
        if not state.get("ssh_client") and not state.get("ssh_server"):
            # Shell markers inside SSH service payloads are ordinary admin
            # commands and must not contribute to reverse-shell scoring.
            match = _SHELL_RE.search(decoded)
            if match:
                if len(state["shell_hits"]) < 3:
                    state["shell_hits"].append(match.group(0).decode("ascii", errors="replace"))
            if _STRONG_SHELL_RE.search(decoded):
                state["strong_shell"] = True

    def _track_connection(self, packet: dict, now: float) -> None:
        src = packet.get("src_ip")
        dst = packet.get("dst_ip")
        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")
        if not src or not dst or src_port is None or dst_port is None:
            return
        flags = self._tcp_flags(packet.get("tcp_flags"))
        payload = bytes(packet.get("payload") or b"")
        forward = (str(src), int(src_port), str(dst), int(dst_port))
        reverse = (str(dst), int(dst_port), str(src), int(src_port))
        state = self._conns.get(forward)
        oriented = True
        if state is None:
            state = self._conns.get(reverse)
            oriented = False
        is_syn = bool(flags & 0x02) and not (flags & 0x10) and not (flags & 0x04)
        is_syn_ack = bool(flags & 0x02) and bool(flags & 0x10) and not (flags & 0x04)
        if state is None:
            if is_syn:
                state = self._new_connection_state(src, src_port, dst, dst_port, now)
                self._conns[forward] = state
                oriented = True
            elif is_syn_ack:
                # SYN-ACK observed without the SYN: the client is the destination.
                state = self._new_connection_state(dst, dst_port, src, src_port, now)
                self._conns[reverse] = state
                oriented = False
            elif payload or (flags & 0x04) or (flags & 0x01):
                # Mid-stream observation: orient from the first data/close packet.
                state = self._new_connection_state(src, src_port, dst, dst_port, now)
                self._conns[forward] = state
                oriented = True
            else:
                return  # Pure ACK with no connection context is ignored.
        state["last"] = now
        if is_syn:
            state["syn"] = True
            if oriented:
                state["syn_port"] = int(dst_port)
            else:
                state["syn_port"] = int(src_port)
        if payload:
            if oriented:
                state["client_pkts"] += 1
                state["client_bytes"] += len(payload)
            else:
                state["server_pkts"] += 1
                state["server_bytes"] += len(payload)
            self._inspect_payload(state, payload, oriented, now)
            if oriented and state["strong_shell"] and not state["exploit_checked"]:
                self._exploit_payload_check(state, packet, now)
        if (flags & 0x04) or (flags & 0x01):
            if not state["closed"]:
                state["closed"] = True
                state["closed_at"] = now
                self._evaluate_connection(state, now)
                if state.get("ftp_banner"):
                    self._evaluate_ftp_session(state, packet, now)
                self._maybe_ftp_auth_failure(state, packet, now)
        self._prune_conns(now)

    def _exploit_payload_check(self, state: dict[str, Any], packet: dict, now: float) -> None:
        """Report strong shell-invocation payloads toward service ports.

        Exploit payloads (shellcode stagers, command injections) are only
        reported when the observed stream carries a strong shell-launching
        marker toward a common service port; the originating tool is never
        named. This catches Metasploit-style exploit stages whose payload is
        visible on the wire (cleartext protocols) without a tool-name rule.
        """
        state["exploit_checked"] = True
        service_port = int(state.get("syn_port") if state.get("syn_port") is not None else state["server_port"])
        if service_port not in _EXPLOIT_TARGET_PORTS:
            return
        client = state["client_ip"]
        server = state["server_ip"]
        if self._is_private_ip(client) and not self._is_private_ip(server):
            # A private host pushing shell markers out to a public server is
            # the callback phase (handled by the reverse-shell detector), not
            # an exploitation payload delivered to a victim service; reporting
            # it as exploitation would double-flag one stream.
            return
        event_id = self._next_event_id("exploit-payload")
        evidence = (f"attack_type=possible_exploitation; source={client}; destination={server}; "
                    f"destination_port={service_port}; service=unknown; "
                    f"shell_markers={state['shell_hits']}; "
                    f"direction=client_to_server")
        self._alert(packet, 90011, "High",
                    f"possible exploitation / shellcode delivery payload from {client} to {server}:{service_port}",
                    evidence=evidence,
                    explanation=("strong shell-launching marker observed in a client-to-server stream "
                                 "toward a common service port; corroborates a later outbound callback"),
                    event_id=event_id,
                    detection_type="exploitation", confidence=75)
        self._record_recon(client, server, now)

    def _prune_conns(self, now: float) -> None:
        # Lazy idle expiration at most once per packet-time second so a
        # high-rate burst cannot turn per-packet cleanup into O(n) work. The
        # size cap is always enforced so memory stays bounded under bursts.
        if len(self._conns) <= self._max_conn_states and now - self._last_conn_prune < 1.0:
            return
        self._last_conn_prune = now
        idle_cutoff = now - self.connection_idle_timeout
        for key, state in list(self._conns.items()):
            if state.get("closed"):
                reference = state.get("closed_at") or state["last"]
                if now - reference >= 60.0:
                    self._conns.pop(key, None)
            elif state["last"] < idle_cutoff:
                self._evaluate_connection(state, now)
                if state.get("ftp_banner"):
                    self._evaluate_ftp_session(state, self._last_packet_context(state, state.get("syn_port") or state["server_port"]), now)
                self._maybe_ftp_auth_failure(state, self._last_packet_context(state, state.get("syn_port") or state["server_port"]), now)
                self._conns.pop(key, None)
        if len(self._conns) > self._max_conn_states:
            # Under a new-connection burst the table can exceed its cap between
            # idle sweeps. Evict the least-recently-updated entries down to a
            # low watermark in bulk (never a full sort per packet), evaluating
            # still-open suspicious connections first so detection is not lost
            # to memory pressure.
            excess = len(self._conns) - self._max_conn_states
            victims = heapq.nsmallest(excess + self._max_conn_states // 4,
                                      self._conns.items(),
                                      key=lambda kv: kv[1]["last"])
            for key, state in victims:
                if not state.get("evaluated") and state.get("syn") and \
                        state["client_pkts"] + state["server_pkts"] >= 2:
                    self._evaluate_connection(state, now)
                self._conns.pop(key, None)

    def _evaluate_connection(self, state: dict[str, Any], now: float) -> None:
        """Evaluate a TCP connection for reverse-shell / callback behaviour.

        Indicators (never tool names): outbound direction from an internal
        host, unusual destination port, long-lived session, interactive
        bidirectional payload traffic, and shell-like content. SSH service
        connections are excluded (a normal SSH session is not a raw reverse
        shell and is covered by the SSH detector).
        """
        if state.get("evaluated"):
            return
        state["evaluated"] = True
        if state.get("ssh_client") or state.get("ssh_server") or state.get("ftp_banner"):
            return
        if not state.get("syn"):
            return
        if state["client_pkts"] + state["server_pkts"] < 2:
            return
        client_ip = state["client_ip"]
        server_ip = state["server_ip"]
        server_port = int(state.get("syn_port") if state.get("syn_port") is not None else state["server_port"])
        internal_client = self._is_private_ip(client_ip)
        outbound_public = internal_client and not self._is_private_ip(server_ip)
        unusual_port = server_port not in COMMON_CLIENT_PORTS
        pure_protocol_session = state.get("web_payloads", 0) > 0 and state.get("raw_payloads", 0) == 0
        if pure_protocol_session:
            # Every payload on the stream is TLS/HTTP framing (web browsing,
            # API traffic, dev servers). A genuine reverse shell speaks a raw
            # interactive protocol, never HTTP/TLS framing, so a pure protocol
            # conversation is not a shell even when it is long-lived,
            # bidirectional, and happens to carry shell-like text.
            return
        interactive = (state["client_pkts"] >= 3 and state["server_pkts"] >= 3 and
                       state["client_bytes"] > 0 and state["server_bytes"] > 0)
        duration = (state.get("closed_at") or state["last"]) - state["created"]
        long_lived = duration >= self.reverse_shell_min_duration
        shell = bool(state["shell_hits"])
        strong = state["strong_shell"]
        score = sum((unusual_port, outbound_public, interactive, long_lived, 2 if shell else 0))
        triggered = (
            (unusual_port and (interactive or long_lived or shell))
            or (shell and interactive and long_lived)
            or (strong and unusual_port)
            or (outbound_public and interactive and shell)
        )
        if not triggered:
            return
        confidence = min(95, 55 + score * 8)
        event_id = self._next_event_id("reverse-shell")
        evidence = (f"attack_type=reverse_shell_behavior; source={client_ip}; destination={server_ip}; "
                    f"destination_port={server_port}; protocol=TCP; "
                    f"client_bytes={state['client_bytes']}; server_bytes={state['server_bytes']}; "
                    f"client_packets={state['client_pkts']}; server_packets={state['server_pkts']}; "
                    f"duration_seconds={duration:g}; interactive={interactive}; "
                    f"long_lived={long_lived}; unusual_port={unusual_port}; "
                    f"outbound_to_public={outbound_public}; "
                    f"shell_markers={state['shell_hits'] or 'none'}; score={score}")
        self._alert(packet := {**self._last_packet_context(state, server_port), "src_ip": client_ip,
                               "dst_ip": server_ip, "dst_port": server_port},
                    90009, "High",
                    f"suspicious outbound callback / possible reverse shell from {client_ip} to {server_ip}:{server_port}",
                    evidence=evidence,
                    explanation=("outbound TCP connection exhibiting interactive bidirectional traffic, "
                                 "unusual destination port, long lifetime, and/or shell-like content; "
                                 "behavioral indicators only, no tool-name matching"),
                    event_id=event_id,
                    detection_type="reverse_shell", confidence=confidence)
        # The callback flows victim -> attacker; correlate with earlier
        # attacker -> victim reconnaissance/exploitation activity.
        prior = self._recon.get((server_ip, client_ip))
        if prior and now - (prior.get("last_seen") or 0) <= self.correlation_window:
            self._alert(packet, 90012, "Critical",
                        f"multi-stage attack sequence: reconnaissance/exploitation from {server_ip} followed by outbound callback to {server_ip}:{server_port}",
                        evidence=(f"attack_type=multi_stage_attack; attacker={server_ip}; victim={client_ip}; "
                                  f"callback_port={server_port}; correlation_window_seconds={self.correlation_window:g}; "
                                  f"prior_activity_first_seen={prior.get('first_seen', 0):g}; "
                                  f"prior_activity_last_seen={prior.get('last_seen', 0):g}"),
                        explanation="earlier reconnaissance/exploitation from the callback destination preceded the outbound interactive callback",
                        event_id=self._next_event_id("multi-stage"),
                        detection_type="multi_stage_attack", confidence=95)
        self._record_recon(server_ip, client_ip, now)

    def _last_packet_context(self, state: dict[str, Any], service_port: int) -> dict:
        """Best-effort packet context for alerts emitted outside a packet callback."""
        return {
            "protocol": "TCP",
            "src_ip": state["client_ip"], "src_port": state["client_port"],
            "dst_ip": state["server_ip"], "dst_port": service_port,
            "length": 0, "payload": b"",
        }

    def _ssh_brute_force(self, packet: dict, now: float) -> None:
        state, _oriented = self._lookup_connection(packet)
        if state is None:
            return
        if state.get("ssh_client") and state.get("ssh_server") and state.get("syn"):
            self._register_ssh_session(state, packet, now)

    # ------------------------------------------------------------------
    # HTTP resource enumeration (Nikto-class behaviour)
    # ------------------------------------------------------------------

    def _prune_http_enum(self, now: float) -> None:
        # Window sweep throttled to once per packet-time second; the size cap
        # below is always enforced so memory stays bounded under bursts.
        if len(self._http_enum) <= self._max_http_states and now - self._last_http_prune < 1.0:
            return
        self._last_http_prune = now
        cutoff = now - self.http_enum_window
        for key, state in list(self._http_enum.items()):
            paths = state["paths"]
            for path, seen_at in list(paths.items()):
                if seen_at < cutoff:
                    paths.pop(path, None)
            if not paths:
                self._http_enum.pop(key, None)
                continue
            if len(paths) < self.http_enum_threshold:
                state["emitted"] = False
        if len(self._http_enum) > self._max_http_states:
            # Bulk-evict least-recently-seen entries down to a low watermark
            # (never a full sort on every packet of a burst), so the cap is
            # only re-crossed occasionally and work stays amortized.
            target = max(1, self._max_http_states * 3 // 4)
            victims = heapq.nsmallest(len(self._http_enum) - target, self._http_enum.items(),
                                      key=lambda kv: max(kv[1]["paths"].values()))
            for key, _state in victims:
                self._http_enum.pop(key, None)

    def _http_enumeration(self, packet: dict, now: float) -> None:
        payload = bytes(packet.get("payload") or b"")
        match = _HTTP_REQUEST_RE.match(payload)
        if match is None:
            return
        method = match.group(1).decode("ascii", errors="replace")
        path = match.group(2).decode("ascii", errors="replace")
        src = packet.get("src_ip")
        dst = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        if not src or not dst or dst_port is None:
            return
        key = (str(src), str(dst), int(dst_port))
        state = self._http_enum.setdefault(key, {"paths": {}, "emitted": False})
        if path not in state["paths"]:
            state["paths"][path] = now
            if len(state["paths"]) > 20000:
                oldest = min(state["paths"], key=state["paths"].get)
                state["paths"].pop(oldest, None)
        self._prune_http_enum(now)
        paths = state["paths"]
        if len(paths) >= self.http_enum_threshold and not state["emitted"]:
            state["emitted"] = True
            event_id = self._next_event_id("http-enumeration")
            evidence = (f"attack_type=http_resource_enumeration; service=http; source={src}; "
                        f"destination={dst}; destination_port={int(dst_port)}; "
                        f"distinct_paths={len(paths)}; window_seconds={self.http_enum_window:g}; "
                        f"paths=[{_bounded_list(sorted(paths))}]")
            self._alert(packet, 90010, "Medium",
                        f"HTTP resource enumeration from {src} to {dst}:{dst_port} ({len(paths)} distinct paths in {self.http_enum_window:g}s)",
                        evidence=evidence,
                        explanation="behavioral distinct HTTP request-path threshold reached",
                        event_id=event_id,
                        detection_type="http_enumeration", service="http", confidence=70)
            self._record_recon(str(src), str(dst), now)

    # ------------------------------------------------------------------
    # Attack-sequence correlation
    # ------------------------------------------------------------------

    def _prune_recon(self, now: float) -> None:
        cutoff = now - self.correlation_window
        for key, state in list(self._recon.items()):
            if (state.get("last_seen") or 0) < cutoff:
                self._recon.pop(key, None)

    def _record_recon(self, source: str, destination: str, now: float) -> None:
        """Record attacker -> victim activity for multi-stage correlation."""
        key = (str(source), str(destination))
        state = self._recon.get(key)
        if state is None:
            if len(self._recon) >= self._max_recon_states:
                oldest = min(self._recon, key=lambda item: self._recon[item].get("last_seen") or 0)
                self._recon.pop(oldest, None)
            self._recon[key] = {"first_seen": now, "last_seen": now}
        else:
            state["last_seen"] = now
        self._prune_recon(now)

    @staticmethod
    def _target_scope(source: str, destination: str) -> str:
        """Classify a probed target: local, private, or public (Internet).

        Host discovery is a local-network reconnaissance behaviour. Targets on
        the same segment as the source, or inside private/documentation space,
        are the evidence of host discovery. Globally-routable destinations are
        ordinary client egress (web browsing, API calls, CDN traffic) and are
        not counted as local host discovery unless remote sweep detection is
        explicitly enabled with a high volume threshold.
        """
        try:
            import ipaddress
            address = ipaddress.ip_address(destination)
            if DeltaCore._is_same_subnet(source, destination) and not address.is_global:
                return "local"
            if address.is_global:
                return "public"
            return "private"
        except ValueError:
            return "public"

    def _host_discovery(self, packet: dict, now: float) -> None:
        protocol = str(packet.get("protocol") or "").upper()
        source = packet.get("src_ip")
        destination = packet.get("dst_ip")
        if not source or not destination:
            return

        if protocol in ("ICMP", "ICMPV6") and packet.get("icmp_type") in (8, 128):
            # Ordinary ICMP echo requests are not attacks by themselves. Report
            # each (source, destination, protocol) pair at most once per scan
            # window as a bounded INFO-level visibility event. Capture-level
            # duplicates are already removed upstream; repeated real pings
            # aggregate into one event whose occurrence count grows, so normal
            # ping traffic cannot flood the alert stream.
            window_epoch = int(now // self.scan_window)
            key = (str(source), str(destination), str(protocol))
            previous = self._icmp_events.get(key)
            if previous is None or previous[1] != window_epoch:
                self._icmp_events[key] = (now, window_epoch)
                self._prune_icmp_events(now)
                self._alert(packet, 90001, "INFO",
                            f"{protocol} echo request from {source} to {destination}",
                            evidence=(f"protocol={protocol}; icmp_type={packet.get('icmp_type')}; "
                                      f"source={source}; destination={destination}; "
                                      f"window_seconds={self.scan_window:g}; window_epoch={window_epoch}"),
                            explanation="captured ICMP echo request visibility event; not by itself an attack",
                            event_id=f"icmp-request-{source}-{destination}-{window_epoch}",
                            detection_type="icmp_visibility", confidence=20)
            signature = "echo"
            active = True
        elif protocol == "TCP":
            flags = self._tcp_flags(packet.get("tcp_flags"))
            # Only unacknowledged SYN probes are multi-host discovery evidence;
            # established conversation traffic is ordinary client communication.
            active = bool(flags & 0x02 and not (flags & (0x10 | 0x04)))
            # A horizontal host sweep probes the same service port across many
            # hosts. Grouping by destination port prevents unrelated
            # conversations (e.g. a client reaching several different services)
            # from aggregating into a fake sweep.
            signature = str(packet.get("dst_port") or "0")
        elif protocol == "UDP" and packet.get("dst_port") in (137, 138):
            # NetBIOS name-service queries (UDP 137/138) are host-discovery
            # probes: one source querying many hosts on the NBNS port is the
            # observable nbtscan-style sweep. Grouped by the probe port so
            # ordinary UDP conversations cannot aggregate into a fake sweep.
            active = True
            signature = str(packet.get("dst_port"))
        else:
            # ARP requests no longer participate in host-discovery sweeps:
            # normal gateway neighbor resolution is L2 housekeeping, not a
            # scan, so ARP is intentionally never correlated here. Other UDP
            # traffic (including DNS) is handled by the dedicated detectors.
            return
        if not active:
            return

        scope = self._target_scope(source, destination)
        if scope == "public" and not self.remote_sweep_enabled:
            # Normal Internet egress (browsing, CDNs, API traffic) must never
            # be mistaken for local-network host discovery.
            return
        threshold = self._threshold_for(protocol, scope)
        if threshold == 0:
            return

        key = (str(source), str(protocol), signature, scope)
        state = self._hosts.setdefault(key, {"observations": deque(), "emitted": False})
        # Distinct targets only: retransmissions and capture-level duplicates
        # of a probe to the same host must not inflate the threshold.
        targets = {target for _, target in state["observations"]}
        if str(destination) not in targets:
            state["observations"].append((now, str(destination)))
            targets.add(str(destination))
        self._prune_hosts(now)
        targets = {target for _, target in state["observations"]}
        if len(targets) >= threshold and not state["emitted"]:
            state["emitted"] = True
            event_id = self._next_event_id("host-sweep")
            window_span = 0.0
            if state["observations"]:
                window_span = state["observations"][-1][0] - state["observations"][0][0]
            evidence = (f"detection_type=host_discovery; source={source}; protocol={protocol}; "
                        f"scope={scope}; probe_signature={signature}; "
                        f"window_seconds={self.scan_window:g}; window_span_seconds={window_span:g}; "
                        f"distinct_targets={len(targets)}; probes={len(state['observations'])}; "
                        f"targets=[{_bounded_list(targets, limit=64)}]")
            self._alert(packet, 90002, "High",
                        f"{protocol} host discovery sweep from {source} ({len(targets)} targets)",
                        evidence=evidence,
                        explanation="behavioral distinct-target host-discovery threshold reached on "
                                    f"{protocol} scope {scope} within {self.scan_window:g}s",
                        event_id=event_id,
                        detection_type="host_discovery",
                        confidence=90)
            self._record_recon(str(source), str(destination), now)

    @staticmethod
    def _dns_qname(payload: bytes) -> str | None:
        """Extract the first question name from a DNS query payload."""
        if len(payload) < 12:
            return None
        offset = 12
        labels: list[str] = []
        limit = min(len(payload), 12 + 255)
        while offset < limit:
            length = payload[offset]
            if length == 0:
                return ".".join(labels) if labels else None
            if length & 0xC0:
                # Compression pointer terminates the name; the label before it
                # is sufficient for enumeration counting.
                return ".".join(labels) if labels else None
            offset += 1
            if offset + length > len(payload):
                return None
            labels.append(payload[offset:offset + length].decode("ascii", errors="replace").lower())
            offset += length
        return None

    def _dns_anomaly(self, packet: dict, now: float) -> None:
        """Report anomalous outbound DNS query volume from a single source.

        Responses (source port 53) and unresolved packets are not counted. The
        event is emitted as soon as the threshold is reached within the window,
        matching the streaming behavior used for port scans.
        """
        if packet.get("dst_port") != 53:
            return
        source = packet.get("src_ip")
        if not source or packet.get("src_port") == 53:
            return
        destination = packet.get("dst_ip")
        key = str(source)
        state = self._dns.setdefault(key, {"observations": deque(), "names": {}, "emitted": False})
        state["observations"].append((now, str(destination)))
        qname = self._dns_qname(bytes(packet.get("payload") or b""))
        if qname:
            state["names"][qname] = now
        self._prune_dns(now)
        # Distinct query names are the precise enumeration signal (Amass/
        # Subfinder brute-force subdomain discovery); when payloads cannot be
        # decoded (DNS over fragmented/odd traffic), raw query count is used.
        count = len(state["names"]) if state["names"] else len(state["observations"])
        if count < self.dns_threshold or state["emitted"]:
            return
        state["emitted"] = True
        event_id = self._next_event_id("dns-anomaly")
        destinations = {item[1] for item in state["observations"]}
        names = sorted(state["names"]) if state["names"] else []
        evidence = (f"source={source}; protocol=UDP; service=dns; window_seconds={self.scan_window:g}; "
                    f"query_count={count}; distinct_destinations={len(destinations)}; "
                    f"destinations=[{', '.join(sorted(destinations))}]; "
                    f"distinct_query_names={len(names)}; query_names=[{_bounded_list(names, limit=32)}]")
        self._alert(packet, 90004, "Medium",
                    f"high DNS query rate from {source} ({count} queries in {self.scan_window:g}s)",
                    evidence=evidence,
                    explanation="behavioral DNS query-rate threshold reached",
                    event_id=event_id,
                    detection_type="dns_anomaly", confidence=65)

    def _repeated_connection_failures(self, packet: dict, now: float) -> None:
        """Report repeated bare RST/FIN closures toward one service endpoint.

        From a passive vantage point, authentication success/failure is not
        visible for encrypted protocols. Repeated abandoned or failed
        connections to a single (destination, destination port) are the
        observable analogue of brute-force-like scanning and are reported here
        with bounded, windowed state.

        Only *bare* RST and FIN packets are counted (no ACK/SYN/PSH/URG). This
        excludes normal teardown (FIN+ACK), target rejection responses
        (RST+ACK), and probe classes such as Xmas (FIN+PSH+URG), so ordinary
        traffic and scan responses cannot accumulate as failures.
        """
        if str(packet.get("protocol") or "").upper() != "TCP":
            return
        flags = self._tcp_flags(packet.get("tcp_flags"))
        if flags not in (0x04, 0x01):
            return
        source = packet.get("src_ip")
        destination = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        if not source or not destination or dst_port is None:
            return
        key = (str(source), str(destination), int(dst_port))
        state = self._brute.setdefault(key, {"observations": deque(), "emitted": False})
        state["observations"].append((now,))
        self._prune_brute(now)
        count = len(state["observations"])
        if count < self.brute_force_threshold or state["emitted"]:
            return
        state["emitted"] = True
        event_id = self._next_event_id("connection-failures")
        evidence = (f"source={source}; destination={destination}; destination_port={int(dst_port)}; "
                    f"protocol=TCP; window_seconds={self.scan_window:g}; "
                    f"connection_failures={count}; failure_flags=bare-RST,FIN")
        self._alert(packet, 90005, "Medium",
                    f"repeated TCP connection failures from {source} to {destination}:{dst_port} ({count} in {self.scan_window:g}s)",
                    evidence=evidence,
                    explanation="behavioral repeated-connection-failure threshold reached",
                    event_id=event_id,
                    detection_type="connection_failures", confidence=75)

    def _syn_flood(self, packet: dict, now: float) -> None:
        """Report a high rate of bare half-open SYNs toward one service endpoint.

        A SYN flood is observable passively as an unusually dense stream of SYN
        packets from one source to one (destination, destination port) that
        never completes handshakes. Only *bare* SYN packets are counted
        (no ACK/RST/FIN/PSH/URG), which keeps the following out of the window:

        - completed handshakes (a SYN-ACK answer retracts the counted SYN;
          only attempts that never receive a SYN-ACK remain in the window);
        - the server's SYN-ACK responses themselves (not bare SYNs, and
          processed in the reverse direction only for retraction);
        - teardown traffic (FIN/RST) and established data flow.

        Keyed per (source, target, port), threshold-gated within the sliding
        window, and reported as observable behavior: many half-open connection
        attempts, regardless of the tool that emitted them. Note: retraction
        of answered SYNs requires the capture point to see both directions; on
        a one-way span port raise the threshold to accommodate normal
        connection rates.
        """
        if str(packet.get("protocol") or "").upper() != "TCP":
            return
        flags = self._tcp_flags(packet.get("tcp_flags"))
        source = packet.get("src_ip")
        destination = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        if not source or not destination or dst_port is None:
            return
        if flags == 0x12:
            # SYN-ACK: the initiator's bare SYN was answered, so that attempt
            # belongs to a real connection, not a flood. Retract it from the
            # initiating (client, server, service port) window. The exact
            # retracted attempt is matched by sequence number (the SYN-ACK ack
            # equals the client SYN seq + 1); when sequence tracking is
            # unavailable, fall back to retracting the oldest pending attempt.
            src_port = packet.get("src_port")
            try:
                ack = int(packet.get("tcp_acknowledgment") or 0)
            except (TypeError, ValueError):
                ack = 0
            if src_port is not None:
                state = self._synflood.get((str(destination), str(source), int(src_port)))
                if state is not None and state["observations"]:
                    timestamp = None
                    if ack:
                        timestamp = state["pending"].pop((ack - 1) & 0xFFFFFFFF, None)
                    if timestamp is None and state["pending"]:
                        oldest_seq = min(state["pending"], key=state["pending"].get)
                        timestamp = state["pending"].pop(oldest_seq, None)
                    if timestamp is not None:
                        try:
                            state["observations"].remove((timestamp,))
                        except ValueError:
                            pass
            return
        if flags != 0x02:
            return
        key = (str(source), str(destination), int(dst_port))
        state = self._synflood.setdefault(key, {"observations": deque(), "pending": {}, "emitted": False})
        try:
            seq = int(packet.get("tcp_sequence") or 0) & 0xFFFFFFFF
        except (TypeError, ValueError):
            seq = 0
        state["pending"][seq] = now
        state["observations"].append((now,))
        self._prune_synflood(now)
        count = len(state["observations"])
        if count < self.syn_flood_threshold or state["emitted"]:
            return
        state["emitted"] = True
        event_id = self._next_event_id("syn-flood")
        evidence = (f"source={source}; destination={destination}; destination_port={int(dst_port)}; "
                    f"protocol=TCP; window_seconds={self.scan_window:g}; "
                    f"half_open_syn_attempts={count}; flags=bare-SYN")
        self._alert(packet, 90014, "High",
                    f"TCP SYN flood from {source} to {destination}:{dst_port} ({count} half-open attempts in {self.scan_window:g}s)",
                    evidence=evidence,
                    explanation="high rate of bare SYN packets toward one service endpoint without handshake completion; "
                                "behavioral half-open connection attempt threshold reached",
                    event_id=event_id,
                    detection_type="syn_flood", confidence=85)

    def _tcp_anomaly(self, packet: dict) -> None:
        """Report invalid TCP flag combinations (SYN+FIN) as protocol anomalies.

        The classification does not depend on the originating tool; SYN+FIN is
        invalid for every TCP implementation (RFC 793).
        """
        source = packet.get("src_ip")
        destination = packet.get("dst_ip")
        if not source or not destination:
            return
        flags = self._tcp_flags(packet.get("tcp_flags"))
        if not (flags & 0x02) or not (flags & 0x01):
            return
        self._alert(packet, 90006, "Low",
                    f"invalid TCP flag combination from {source} to {destination}",
                    evidence=(f"protocol=TCP; tcp_flags={packet.get('tcp_flags')}; "
                              f"source={source}; destination={destination}; "
                              f"dst_port={packet.get('dst_port')}; tcp_sequence={packet.get('tcp_sequence')}"),
                    explanation="SYN+FIN is not a valid TCP flag combination (RFC 793)",
                    event_id=f"tcp-anomaly-{source}-{destination}-{packet.get('tcp_sequence', '')}",
                    detection_type="tcp_anomaly", confidence=90)

    def _emit_probe_if_ready(self, packet: dict, source: str, destination: str,
                             protocol: str, probe_class: str, state: dict[str, Any]) -> None:
        observations = state["observations"]
        ports_seen = {observed_port for _, observed_port in observations}
        response_counts = {name: sum(name in values for values in state["responses"].values())
                           for name in ("syn_ack", "rst", "icmp_unreachable")}
        # An ACK-only packet is common in established traffic. Only call a
        # multi-port ACK pattern a scan when the target also produced response
        # evidence (normally RSTs), making the result defensible passively.
        if probe_class in ("ack", "maimon") and response_counts["rst"] == 0 and response_counts["icmp_unreachable"] == 0:
            return
        if len(ports_seen) < self.port_threshold or state["emitted"]:
            return
        state["emitted"] = True
        event_id = self._next_event_id(f"{protocol.lower()}-{probe_class}-scan")
        ports = _bounded_list(ports_seen)
        evidence = (f"source={source}; destination={destination}; protocol={protocol}; "
                    f"probe_class={probe_class}; window_seconds={self.scan_window:g}; "
                    f"distinct_destination_ports={len(ports_seen)}; ports=[{ports}]; "
                    f"responses={response_counts}")
        qualifier = "possible " if probe_class == "ack" else ""
        self._alert({**packet, "src_ip": source, "dst_ip": destination,
                     "dst_port": observations[-1][1]},
                    90003, "High",
                    f"{qualifier}{protocol} {probe_class.upper()} port scan from {source} to {destination} ({len(ports_seen)} ports)",
                    evidence=evidence,
                    explanation="behavioral active-probe threshold reached",
                    event_id=event_id,
                    scan_class=probe_class,
                    response_counts=response_counts,
                    detection_type="port_scan", confidence=85)
        if observations:
            self._record_recon(source, destination, observations[-1][0])

    def _record_probe(self, packet: dict, source: str, destination: str,
                      protocol: str, probe_class: str, port: int, now: float,
                      response: str | None = None) -> None:
        source_port = packet.get("src_port") if probe_class in ("ack", "maimon") else None
        key = (source, destination, protocol, probe_class, source_port)
        state = self._ports.setdefault(key, {"observations": deque(), "responses": defaultdict(set),
                                              "source_ports": defaultdict(set), "emitted": False})
        observations = state["observations"]
        # One source/target/class/port observation represents one probe target;
        # retransmissions and duplicate capture paths must not inflate it.
        if not any(existing_port == port for _, existing_port in observations):
            observations.append((now, port))
        if packet.get("src_port") is not None:
            state["source_ports"][port].add(int(packet["src_port"]))
        if response:
            state["responses"][port].add(response)
        self._prune_ports(now)
        ports_seen = {observed_port for _, observed_port in observations}
        if len(ports_seen) < self.port_threshold:
            state["emitted"] = False
        response_counts = {name: sum(name in values for values in state["responses"].values())
                           for name in ("syn_ack", "rst", "icmp_unreachable")}
        # An ACK-only packet is common in established traffic. Only call a
        # multi-port ACK pattern a scan when the target also produced response
        # evidence (normally RSTs), making the result defensible passively.
        if probe_class in ("ack", "maimon") and response_counts["rst"] == 0 and response_counts["icmp_unreachable"] == 0:
            return
        if len(ports_seen) >= self.port_threshold and not state["emitted"]:
            state["emitted"] = True
            event_id = self._next_event_id(f"{protocol.lower()}-{probe_class}-scan")
            ports = _bounded_list(ports_seen)
            evidence = (f"source={source}; destination={destination}; protocol={protocol}; "
                        f"probe_class={probe_class}; window_seconds={self.scan_window:g}; "
                        f"distinct_destination_ports={len(ports_seen)}; ports=[{ports}]; "
                        f"responses={response_counts}")
            qualifier = "possible " if probe_class == "ack" else ""
            self._alert({**packet, "src_ip": source, "dst_ip": destination, "dst_port": port},
                        90003, "High",
                        f"{qualifier}{protocol} {probe_class.upper()} port scan from {source} to {destination} ({len(ports_seen)} ports)",
                        evidence=evidence,
                        explanation="behavioral active-probe threshold reached",
                        event_id=event_id,
                        scan_class=probe_class,
                        response_counts=response_counts,
                        detection_type="port_scan", confidence=85)
            self._record_recon(source, destination, now)

    def _scan_detection(self, packet: dict) -> None:
        now = float(packet.get("_monotonic", time.monotonic()))
        source = packet.get("src_ip")
        destination = packet.get("dst_ip")
        if not source or not destination:
            return
        protocol = str(packet.get("protocol") or "").upper()
        self._host_discovery(packet, now)

        if protocol == "TCP" and packet.get("dst_port") is not None:
            flags = self._tcp_flags(packet.get("tcp_flags"))
            self._track_connection(packet, now)
            self._tcp_anomaly(packet)
            # ACK-only scans are only meaningful when they are not interleaved
            # with FIN+ACK traffic from the same source/target flow.
            if flags == 0x10:
                has_maimon_flow = any(
                    key[:4] == (str(source), str(destination), "TCP", "maimon")
                    for key in self._ports
                )
                if has_maimon_flow:
                    return
            self._repeated_connection_failures(packet, now)
            self._syn_flood(packet, now)
            self._ssh_brute_force(packet, now)
            self._ftp_banner_enumeration(packet, now)
            self._http_enumeration(packet, now)
            # Correlate target responses with each active probe class. The
            # response source port is the probed destination port.
            if flags & 0x04 or (flags & 0x12) == 0x12:
                response_kind = "rst" if flags & 0x04 else "syn_ack"
                response_port = packet.get("src_port")
                if response_port is not None:
                            # A response can qualify only the exact reverse probe
                    # state whose destination port it answers. Do not attach a
                    # response to every scan class for the same tuple: that
                    # cross-class fan-out was capable of turning unrelated
                    # ACK/FIN-ACK traffic into a Maimon/ACK scan.
                    for probe_class in ("syn", "fin", "null", "xmas", "maimon", "ack"):
                        response_state = None
                        if probe_class == "ack":
                            # Normal ACK traffic commonly coexists with
                            # FIN+ACK traffic. Require the ACK class itself to
                            # have a consistent source-port pattern; mixed
                            # per-port streams are not probe evidence.
                            ack_state = self._ports.get(
                                (str(destination), str(source), "TCP", "ack", packet.get("dst_port")))
                            if ack_state is not None:
                                ack_sources = {port for ports in ack_state["source_ports"].values() for port in ports}
                                if len(ack_sources) != 1:
                                    continue
                        if probe_class in ("ack", "maimon"):
                            response_state = self._ports.get(
                                (str(destination), str(source), "TCP", probe_class, packet.get("dst_port")))
                        else:
                            response_state = self._ports.get((str(destination), str(source), "TCP", probe_class, None))
                        if response_state is None:
                            continue
                        observed_ports = {port for _, port in response_state["observations"]}
                        response_destination_port = packet.get("dst_port")
                        source_ports = response_state.get("source_ports", {})
                        if int(response_port) not in observed_ports:
                            continue
                        # ACK/MAIMON responses require the exact source port
                        # used by the corresponding probe. Other probe classes
                        # can correlate by the reverse destination port alone.
                        if probe_class in ("ack", "maimon"):
                            if (response_destination_port is None or
                                    int(response_destination_port) not in source_ports.get(int(response_port), set())):
                                continue
                            if probe_class == "ack":
                                has_maimon_flow = any(
                                    key[:4] == (str(destination), str(source), "TCP", "maimon")
                                    for key in self._ports
                                )
                                if has_maimon_flow:
                                    continue
                            # ACK and FIN+ACK traffic sharing the same target
                            # is normal connection traffic when both classes
                            # use the same source-port set. Do not let RSTs for
                            # that mixed stream qualify the ACK class.
                            ack_state = self._ports.get(
                                (str(destination), str(source), "TCP", "ack", packet.get("dst_port")))
                            maimon_state = self._ports.get(
                                (str(destination), str(source), "TCP", "maimon", packet.get("dst_port")))
                            if ack_state is not None and maimon_state is not None:
                                ack_sources = {port for ports in ack_state["source_ports"].values() for port in ports}
                                maimon_sources = {port for ports in maimon_state["source_ports"].values() for port in ports}
                                if ack_sources and maimon_sources and ack_sources != maimon_sources:
                                    continue
                            # A RST is useful evidence for ACK scans only when
                            # the probe flow is unambiguous across the window.
                            if (probe_class == "maimon" and response_kind == "rst"):
                                continue
                        response_state["responses"][int(response_port)].add(response_kind)
                        self._emit_probe_if_ready(packet, str(destination), str(source), "TCP",
                                                   probe_class, response_state)
            probe_class = self._flag_class(flags)
            if probe_class is not None:
                self._record_probe(packet, str(source), str(destination), "TCP", probe_class,
                                   int(packet["dst_port"]), now)
            return

        if protocol == "UDP" and packet.get("dst_port") is not None:
            self._dns_anomaly(packet, now)
            # A UDP packet with no payload is still an observable UDP probe. Do
            # not classify common server-source replies as outbound probes.
            if packet.get("src_port") not in (53, 67, 68, 123, 161):
                self._record_probe(packet, str(source), str(destination), "UDP", "udp",
                                   int(packet["dst_port"]), now)
            return

        # ICMP port-unreachable messages carry the original UDP probe. The
        # scanner/target/port are recovered from the quoted inner IP packet.
        if protocol in ("ICMP", "ICMPV6") and packet.get("icmp_type") in (1, 3):
            inner_protocol = str(packet.get("icmp_inner_protocol") or "").upper()
            inner_source = packet.get("icmp_inner_src_ip")
            inner_destination = packet.get("icmp_inner_dst_ip")
            inner_port = packet.get("icmp_inner_dst_port")
            if inner_protocol in ("UDP", "17", "58") and inner_source and inner_destination and inner_port is not None:
                self._record_probe({**packet, "src_ip": inner_source, "dst_ip": inner_destination},
                                   str(inner_source), str(inner_destination), "UDP", "udp",
                                   int(inner_port), now, response="icmp_unreachable")

    def _suppress_rule_alert(self, alert: dict, packet: dict) -> bool:
        """Filter informational rule alerts so normal SSH never alerts.

        SID 1000003 ("SSH protocol banner observed") matches the cleartext
        "SSH-..." banner that opens EVERY SSH session. A banner exchange on a
        standard SSH port (22/2222) is normal operation and must not alert:
        the client banner carries dst_port 22 while the server reply carries
        src_port 22, so both directions are covered by the port check.
        Banner observations on a non-standard port are a genuine
        hidden-service signal: keep the client-side observation but strip the
        per-packet event_id so repeated sessions against one service collapse
        into a single unique alert row (occurrence_count tracks how often)
        instead of one alert per connection. The redundant server-reply
        observation is dropped.
        """
        if int(alert.get("sid") or 0) != 1000003:
            return False
        try:
            src_port = int(packet.get("src_port") or 0)
            dst_port = int(packet.get("dst_port") or 0)
        except (TypeError, ValueError):
            return False
        if src_port in (22, 2222) or dst_port in (22, 2222):
            return True
        state, src_is_client = self._lookup_connection(packet)
        if state is not None and not src_is_client:
            return True
        alert.pop("event_id", None)
        return False

    def process_packet(self, packet):
        # Rule refresh is synchronized inside DetectionEngine; capture remains
        # the owner of packet ordering and is never stopped for an update.
        refresh = getattr(self.detection_engine, "refresh_if_changed", None)
        if refresh is not None:
            refresh()
        with self._lock:
            self.packets_sniffed += 1
            self.total_data += int(packet.get("length", 0) or 0)
            self.unique_ips.update(filter(None, (packet.get("src_ip"), packet.get("dst_ip"))))
            if packet.get("src_ip") and packet.get("dst_ip"):
                self.flows.add((packet.get("src_ip"), packet.get("src_port"), packet.get("dst_ip"),
                                packet.get("dst_port"), packet.get("protocol")))
        traffic_id = self.alert_manager.log_traffic(packet)
        if traffic_id:
            packet["traffic_id"] = traffic_id
        if self.alert_manager.session:
            # At most one write per second: packets_processed/bytes_processed
            # are single-row upserts, so persisting them on every packet only
            # hammers the shared SQLite write lock the dashboard also needs.
            now_epoch = int(time.time())
            if now_epoch != getattr(self, "_last_stat_epoch", None):
                self._last_stat_epoch = now_epoch
                self.alert_manager._upsert_statistic("packets_processed", self.packets_sniffed)
                self.alert_manager._upsert_statistic("bytes_processed", self.total_data)
        self._scan_detection(packet)
        for alert in self.detection_engine.analyze_packet(packet):
            alert.setdefault("traffic_id", packet.get("traffic_id"))
            if self._suppress_rule_alert(alert, packet):
                continue
            self.alert_manager.log_alert(alert)