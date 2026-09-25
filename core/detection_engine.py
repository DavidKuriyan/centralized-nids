from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from typing import Iterable

from core.rule_management import decode_content, load_port_variables, parse_port_expression

DEDUP_WINDOW_SECONDS = 30.0
MAX_ALERTS_PER_PACKET = 2
LEGACY_HEURISTIC_FIELD = "heuristic_payload"
SUPPORTED_FIELDS = {
    "sid", "rev", "revision", "action", "protocol", "src_ip", "dst_ip", "src_port", "dst_port",
    "message", "severity", "priority", "gid", "content", "pcre", "regex", "evidence", "explanation",
    "direction", "service", "buffer", "nocase", "classification", "category", "offset", "depth",
    "distance", "within", "threshold", "suppression_key", "rule_text", "enabled",
}


class DetectionEngine:
    def __init__(self, rules_path: str, runtime_db_path: str | None = None):
        load_port_variables(os.path.join(os.path.dirname(rules_path), "port_variables.json"))
        self.rules_path = rules_path
        self.runtime_db_path = runtime_db_path
        self.rules = self.load_rules(rules_path)
        self._compiled_rules = self._compile_rules(self.rules)
        self.unsupported_rules = sum(1 for item in self._compiled_rules if item["unsupported"])
        self._alert_cache: dict[tuple, float] = {}
        self._lock = threading.RLock()
        self._runtime_file_marker: tuple[int, int] | None = None
        self._runtime_signature: tuple = ()

    @staticmethod
    def load_rules(path: str) -> list[dict]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"rules file not found: {path}")
        with open(path, encoding="utf-8") as stream:
            rules = json.load(stream)
        if not isinstance(rules, list):
            raise ValueError("rules file must contain a JSON array")
        return rules

    @staticmethod
    def _compile_rules(rules: Iterable[dict]) -> list[dict]:
        compiled = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            content = rule.get("content")
            if isinstance(content, str):
                content_values = [decode_content(content)]
            elif isinstance(content, (list, tuple)):
                content_values = [decode_content(str(value)) for value in content]
            else:
                try:
                    content_values = [bytes(content or b"")]
                except (TypeError, ValueError):
                    content_values = [b""]
            nocase = bool(rule.get("nocase", False))
            regex_value = rule.get("pcre") or rule.get("regex")
            regex = None
            regex_error = None
            if regex_value:
                try:
                    pattern = regex_value.encode("utf-8") if isinstance(regex_value, str) else regex_value
                    regex = re.compile(pattern, re.I if nocase else 0)
                except (re.error, TypeError, ValueError) as error:
                    regex_error = str(error)
            # Canonical port normalization: every rule (file, UI, API, DB) is
            # compiled through the same single parser so `$HTTP_PORTS`,
            # `[80,443]`, and `1:1024` behave identically on every path.
            src_port = parse_port_expression(rule.get("src_port"), "Source Port")
            dst_port = parse_port_expression(rule.get("dst_port"), "Destination Port")
            unsupported = set(rule).difference(SUPPORTED_FIELDS)
            unsupported.difference_update({"src_ip", "dst_ip"})
            if LEGACY_HEURISTIC_FIELD in rule:
                unsupported.add(LEGACY_HEURISTIC_FIELD)
            if regex_error:
                unsupported.add("regex")
            compiled.append({
                "rule": rule,
                "unsupported": unsupported,
                "protocol": str(rule.get("protocol", "IP")).strip().upper(),
                "content": content_values[0] if len(content_values) == 1 else b"",
                "contents": content_values,
                "nocase": nocase,
                "regex": regex,
                "src_port": src_port,
                "dst_port": dst_port,
            })
        return compiled

    @staticmethod
    def _port_matches(condition, value) -> bool:
        """Match a canonical port condition (int, range, comma list) against a port.

        Accepts the canonical forms produced by the rule parser: an int, "any",
        "80", "80,443", "1:1024", and mixed "20:21,53,1000:1024".
        """
        if condition in (None, "", "any"):
            return True
        if value is None:
            return False
        try:
            value = int(value)
        except (TypeError, ValueError):
            return False
        if isinstance(condition, int):
            return value == condition
        text = str(condition).strip()
        for token in text.split(","):
            token = token.strip()
            if not token:
                continue
            if token.isdigit():
                if value == int(token):
                    return True
                continue
            if ":" in token:
                low, high = token.split(":", 1)
                if (not low or value >= int(low)) and (not high or value <= int(high)):
                    return True
        return False

    @staticmethod
    def _rule_identity(rule: dict) -> tuple[int, int, int]:
        return (int(rule.get("gid", 1) or 1), int(rule.get("sid", 0) or 0),
                int(rule.get("rev", rule.get("revision", 1)) or 1))

    def refresh_if_changed(self, force: bool = False) -> bool:
        """Atomically replace the active rule snapshot after a backend update."""
        runtime_db_path = getattr(self, "runtime_db_path", None)
        if not runtime_db_path or not os.path.exists(runtime_db_path):
            return False
        if not hasattr(self, "_lock"):
            self._lock = threading.RLock()
        if not hasattr(self, "_runtime_file_marker"):
            self._runtime_file_marker = None
        if not hasattr(self, "_runtime_signature"):
            self._runtime_signature = ()
        with self._lock:
            try:
                marker = os.stat(runtime_db_path).st_mtime_ns
            except OSError:
                return False
            if not force and marker == self._runtime_file_marker:
                return False
            try:
                with sqlite3.connect(runtime_db_path, timeout=2.0) as connection:
                    rows = connection.execute(
                        "SELECT gid, sid, revision, enabled, rule_json FROM rules "
                        "WHERE rule_json IS NOT NULL ORDER BY gid, sid, revision"
                    ).fetchall()
            except (OSError, sqlite3.Error):
                return False
            signature = tuple((int(gid or 1), int(sid), int(revision), bool(enabled), str(rule_json))
                              for gid, sid, revision, enabled, rule_json in rows)
            self._runtime_file_marker = marker
            if signature == self._runtime_signature:
                return False
            active = []
            for _gid, _sid, _revision, enabled, rule_json in rows:
                if not enabled:
                    continue
                try:
                    rule = json.loads(rule_json)
                except (TypeError, json.JSONDecodeError):
                    continue
                if isinstance(rule, dict):
                    active.append(rule)
            self.rules = active
            self._compiled_rules = self._compile_rules(active)
            self.unsupported_rules = sum(1 for item in self._compiled_rules if item["unsupported"])
            # A changed rule set must not inherit suppression from an old rule.
            self._alert_cache.clear()
            self._runtime_signature = signature
            return True

    def analyze_packet(self, packet: dict) -> list[dict]:
        self.refresh_if_changed()
        if not hasattr(self, "_lock"):
            self._lock = threading.RLock()
        if not hasattr(self, "_alert_cache"):
            self._alert_cache = {}
        protocol = str(packet.get("protocol", "")).upper()
        raw_payload = bytes(packet.get("payload", b""))
        alerts = []
        with self._lock:
            compiled_rules = tuple(self._compiled_rules)
            now = time.monotonic()
            for item in compiled_rules:
                if len(alerts) >= MAX_ALERTS_PER_PACKET:
                    break
                if item["unsupported"]:
                    continue
                rule = item["rule"]
                if rule.get("enabled", True) is False:
                    continue
                rule_protocol = item["protocol"]
                if rule_protocol == "ICMPV6":
                    protocol_matches = protocol == "ICMPV6"
                elif rule_protocol == "IP":
                    protocol_matches = protocol in {"IP", "IPV6", "TCP", "UDP", "ICMP", "ICMPV6"}
                else:
                    protocol_matches = rule_protocol == protocol
                if not protocol_matches:
                    continue
                if rule.get("direction") == "client_to_server" and packet.get("direction") not in (None, "client_to_server"):
                    continue
                if rule.get("direction") == "server_to_client" and packet.get("direction") != "server_to_client":
                    continue
                if not self._port_matches(item["src_port"], packet.get("src_port")):
                    continue
                if not self._port_matches(item["dst_port"], packet.get("dst_port")):
                    continue
                address_match = True
                for field, packet_field in (("src_ip", "src_ip"), ("dst_ip", "dst_ip")):
                    selector = rule.get(field)
                    if not selector or selector == "any":
                        continue
                    try:
                        import ipaddress
                        address = ipaddress.ip_address(packet.get(packet_field, ""))
                        network = ipaddress.ip_network(selector, strict=False) if "/" in str(selector) else ipaddress.ip_network(f"{selector}/{address.max_prefixlen}", strict=False)
                        if address not in network:
                            address_match = False
                            break
                    except ValueError:
                        address_match = False
                        break
                if not address_match:
                    continue
                content = item["content"]
                content_values = item.get("contents", [content])
                haystack = raw_payload.lower() if item["nocase"] else raw_payload
                # Signature content anchoring: `offset` starts the search at
                # a fixed byte index and `depth` bounds how many bytes of the
                # payload are searched from there. Rules without either keep
                # the historical whole-payload substring semantics.
                try:
                    offset = int(rule.get("offset", 0) or 0)
                    depth_value = rule.get("depth")
                    depth = int(depth_value) if depth_value is not None else None
                except (TypeError, ValueError):
                    offset, depth = 0, None
                if offset > len(haystack):
                    continue
                window = haystack[offset:] if depth is None else haystack[offset:offset + depth]
                if any(value and (value.lower() if item["nocase"] else value) not in window
                       for value in content_values):
                    continue
                if item["regex"] and not item["regex"].search(raw_payload):
                    continue
                # A protocol-only ICMP/ICMPV6/ARP rule is a bounded explicit
                # rule primitive. Other empty rules are rejected to avoid
                # accidental "alert everything" false positives.
                if not content and not item["regex"] and rule_protocol not in ("ICMP", "ICMPV6", "ARP"):
                    continue
                gid, sid, revision = self._rule_identity(rule)
                evidence_value = ", ".join(value.decode("utf-8", errors="replace") for value in content_values if value) if content_values else "protocol match"
                evidence = f"protocol={protocol}; payload_match={evidence_value}"
                fingerprint_material = "|".join(str(value) for value in (
                    gid, sid, revision, packet.get("src_ip"), packet.get("dst_ip"), protocol,
                    packet.get("src_port"), packet.get("dst_port"), packet.get("tcp_sequence"),
                    packet.get("icmp_type"), packet.get("icmp_code"), packet.get("length"),
                    hashlib.sha256(raw_payload).hexdigest(), evidence,
                ))
                key = hashlib.sha256(fingerprint_material.encode()).hexdigest()
                if now - self._alert_cache.get(key, 0.0) < DEDUP_WINDOW_SECONDS:
                    continue
                self._alert_cache[key] = now
                alerts.append({
                    "src_ip": packet.get("src_ip"), "dst_ip": packet.get("dst_ip"),
                    "src_port": packet.get("src_port"), "dst_port": packet.get("dst_port"),
                    "protocol": protocol, "gid": gid, "sid": sid, "revision": revision,
                    "priority": int(rule.get("priority", 3) or 3),
                    "severity": rule.get("severity", "Low"),
                    "message": rule.get("message", f"Rule {sid} matched"),
                    "action": rule.get("action", "ALERT"), "is_ml_anomaly": False,
                    "evidence": evidence,
                    "explanation": f"rule {sid} matched packet evidence on protocol {protocol}",
                })
            if len(self._alert_cache) > 10000:
                cutoff = now - DEDUP_WINDOW_SECONDS * 2
                self._alert_cache = {key: value for key, value in self._alert_cache.items() if value > cutoff}
        return alerts
