from __future__ import annotations

import datetime
import hashlib
import json
import logging
import sqlite3
import threading
import time
from collections import deque
from typing import Optional

from database.models import Alert, Incident, IncidentAlert, Rule, Statistic, TrafficLog, init_db
from sqlalchemy import or_
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger("delta-ids")


def format_endpoint(ip: object, port: object = None) -> str:
    """Render an IP endpoint for terminal and alert display.

    IPv4 endpoints are formatted as ``addr:port`` (or just ``addr``).
    IPv6 endpoints are formatted as ``[addr]:port`` (RFC 5952 bracket
    notation) so the colon separator is unambiguous.
    """
    if ip is None or ip == "":
        return "-"
    value = str(ip)
    if not value:
        return "-"
    is_ipv6 = ":" in value
    if port is None or port == "":
        return f"[{value}]" if is_ipv6 else value
    if is_ipv6:
        return f"[{value}]:{int(port)}"
    return f"{value}:{int(port)}"


def now_epoch() -> int:
    return int(time.time())


def format_human_alert(timestamp: int, alert: dict, severity: str) -> str:
    instant = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).astimezone()
    stamp = instant.strftime('%m/%d-%H:%M:%S') + f'.{instant.microsecond:06d}'
    gid = int(alert.get('gid', 1) or 1)
    sid = alert.get('sid', 0)
    rev = int(alert.get('revision', 1) or 1)
    protocol = str(alert.get('protocol') or 'IP').upper()
    source = format_endpoint(alert.get('src_ip'), alert.get('src_port') if protocol not in {'ICMP', 'ICMPV6', 'IP'} else None)
    destination = format_endpoint(alert.get('dst_ip'), alert.get('dst_port') if protocol not in {'ICMP', 'ICMPV6', 'IP'} else None)
    priority = int(alert.get('priority') or 3)
    return (f'{stamp}  [*] [{gid}:{sid}:{rev}] {alert.get("message", "Detection event")} [*]\\n'
            f'[Priority: {priority}] {{{protocol}}} {source} -> {destination}')


def alert_fingerprint(alert: dict, timestamp: int) -> str:
    """Build an event identity without turning source identity into suppression.

    Events that carry an explicit ``event_id`` (behavioral campaigns, correlated
    detections) keep a unique identity per campaign. Events without one
    (per-packet signature matches such as SSH banner observation) collapse into
    a single unique alert per event class: the ephemeral source port and any
    fixed time bucket are excluded so one recurring condition does not create a
    new alert row for every packet or connection -- occurrence_count and
    last_seen track how often and how recently it fired.
    """
    event_id = alert.get("event_id")
    if event_id is None:
        fingerprint_material = "|".join(str(value) for value in (
            alert.get('gid', 1), alert.get('sid', 0), alert.get('revision', 1),
            alert.get('src_ip') or "",
            alert.get('dst_ip') or "", alert.get('dst_port'),
            alert.get('protocol', ''), alert.get('service', ''),
            alert.get('detection_type', 'behavioral' if alert.get('is_ml_anomaly') else 'signature'),
            alert.get('evidence', ''), alert.get('message', ''),
        ))
        return hashlib.sha256(fingerprint_material.encode()).hexdigest()
    fingerprint_material = "|".join(str(value) for value in (
        alert.get('gid', 1), alert.get('sid', 0), alert.get('revision', 1),
        alert.get('src_ip') or "", alert.get('src_port'), alert.get('dst_ip') or "",
        alert.get('dst_port'), alert.get('protocol', ''), alert.get('service', ''),
        alert.get('detection_type', 'behavioral' if alert.get('is_ml_anomaly') else 'signature'),
        event_id,
        alert.get('evidence', ''), alert.get('message', ''),
    ))
    return hashlib.sha256(fingerprint_material.encode()).hexdigest()


class AlertManager:
    def __init__(self, db_path: str | None = None, terminal: bool = True, persist: bool = False):
        self.session = init_db(db_path) if db_path and persist else None
        self.terminal = terminal
        self.persist = persist
        self.session_start = datetime.datetime.now(datetime.timezone.utc)
        self._live_traffic = deque(maxlen=500)
        self._live_alerts = deque(maxlen=1000)
        self._live_alert_index: dict[str, dict] = {}
        self._alert_counter = 0
        self._lock = threading.RLock()
        # Thread that owns the SQLAlchemy session. SQLite connections created
        # by this module must not be shared across threads (check_same_thread
        # is left at its safe default), so cross-thread callers skip DB writes.
        self._db_owner_thread = threading.current_thread()
        if self.session:
            self._persist_statistic("capture_sessions_started", 1)

    def persist_rules(self, rules, source_file: str) -> None:
        if not self.session:
            return
        with self._lock:
            try:
                for rule in rules:
                    sid = int(rule.get('sid', 0) or 0)
                    revision = int(rule.get('rev', rule.get('revision', 1)) or 1)
                    existing = self.session.query(Rule).filter_by(sid=sid, revision=revision).one_or_none()
                    enabled = existing.enabled if existing is not None else bool(rule.get('enabled', True))
                    rule_copy = dict(rule)
                    rule_copy['enabled'] = enabled
                    rule_copy.setdefault('rule_text', rule.get('rule_text', ''))
                    row = existing or Rule(sid=sid, revision=revision)
                    row.message = rule.get('message', '')
                    row.enabled = enabled
                    row.source_file = source_file
                    row.gid = int(rule.get('gid', 1) or 1)
                    row.priority = int(rule.get('priority', 3) or 3)
                    row.protocol = str(rule.get('protocol', ''))
                    row.category = rule.get('category', rule.get('classification', ''))
                    row.rule_text = rule_copy.get('rule_text', '')
                    row.rule_json = json.dumps(rule_copy, separators=(',', ':'))
                    row.updated_at = time.time_ns()
                    self.session.add(row)
                self.session.commit()
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist rules: %s", error)

    def log_traffic(self, packet) -> Optional[int]:
        timestamp = now_epoch()
        event = {"timestamp": timestamp, "src_ip": packet.get("src_ip"), "dst_ip": packet.get("dst_ip"), "src_port": packet.get("src_port"), "dst_port": packet.get("dst_port"), "protocol": packet.get("protocol"), "length": packet.get("length", 0)}
        self._live_traffic.appendleft(event)
        if not self.session:
            return None
        with self._lock:
            try:
                details = packet.get("details") or {}
                # Defense in depth: callers may provide decoder metadata
                # directly, but MAC fields must never enter normal traffic
                # storage/API responses.
                if isinstance(details, dict):
                    details = {key: value for key, value in details.items()
                               if "mac" not in str(key).lower()}
                row = TrafficLog(**event, payload_summary="", details=json.dumps(details) if details else None)
                self.session.add(row)
                self.session.commit()
                return int(row.id)
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist traffic: %s", error)
                return None

    def log_alert(self, alert):
        # Alerts use canonical IP endpoint fields. Strip any accidental legacy
        # MAC aliases before exposing or persisting the event.
        alert = {key: value for key, value in alert.items()
                 if "mac" not in str(key).lower()}
        timestamp = now_epoch()
        fingerprint = alert_fingerprint(alert, timestamp)
        with self._lock:
            existing = self._live_alert_index.get(fingerprint)
            if existing is None:
                self._alert_counter += 1
                event = {"id": self._alert_counter, "timestamp": timestamp,
                         "occurrence_count": 1, **alert}
                self._live_alerts.appendleft(event)
                self._live_alert_index[fingerprint] = event
                if len(self._live_alert_index) > self._live_alerts.maxlen * 2:
                    live_ids = {id(item) for item in self._live_alerts}
                    self._live_alert_index = {
                        key: item for key, item in self._live_alert_index.items()
                        if id(item) in live_ids
                    }
            else:
                # Keep one realtime row for the same event, while persistence
                # below still increments occurrence_count for auditability.
                existing["timestamp"] = timestamp
                existing["occurrence_count"] = int(existing.get("occurrence_count", 1)) + 1
        severity = str(alert.get("severity", "Low")).upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "LOW"
        if self.terminal:
            print(format_human_alert(timestamp, alert, severity), flush=True)
        if not self.session:
            return
        with self._lock:
            try:
                source = alert.get("src_ip") or ""
                destination = alert.get("dst_ip") or ""
                sid = alert.get("sid") or 0
                fingerprint = alert_fingerprint(alert, timestamp)
                provided_type = alert.get("detection_type")
                detection_type = "behavioral" if provided_type not in (None, "signature") or alert.get("is_ml_anomaly") else "signature"
                values = {"first_seen": timestamp, "last_seen": timestamp, "occurrence_count": 1, "suppressed_count": 0, "severity": severity, "confidence": int(alert.get("confidence", 0) or 0), "risk": int(alert.get("risk", 0) or 0), "detection_type": detection_type, "sid": sid, "revision": int(alert.get("revision", 1) or 1), "source_ip": source, "source_port": alert.get("src_port"), "destination_ip": destination, "destination_port": alert.get("dst_port"), "protocol": alert.get("protocol") or "", "service": alert.get("service") or "", "flow_id": int(alert.get("flow_id", 0) or 0), "traffic_id": int(alert.get("traffic_id", 0) or 0), "message": alert.get("message") or "", "evidence": alert.get("evidence") or "", "explanation": alert.get("explanation") or "", "fingerprint": fingerprint}
                statement = sqlite_insert(Alert).values(**values).on_conflict_do_update(index_elements=[Alert.__table__.c.fingerprint], set_={"last_seen": values["last_seen"], "occurrence_count": Alert.__table__.c.occurrence_count + 1, "traffic_id": values["traffic_id"]})
                self.session.execute(statement)
                self.session.commit()
                persisted = self.session.query(Alert).filter_by(fingerprint=fingerprint).one_or_none()
                if persisted is not None:
                    values["id"] = int(persisted.id)
                self._persist_incident(values)
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist alert: %s", error)

    def _persist_incident(self, values: dict) -> None:
        with self._lock:
            try:
                # Correlate only with an open incident that has an actual
                # source/destination/protocol/category relationship. The old
                # implementation grouped every open signature alert together.
                window = 30
                candidates = (self.session.query(Incident)
                              .filter(Incident.status == 'OPEN',
                                      Incident.category == ('behavioral' if values.get('detection_type') == 'behavioral' else 'signature'),
                                      Incident.last_seen >= values['first_seen'] - window)
                              .order_by(Incident.last_seen.desc()).all())
                incident = None
                for candidate in candidates:
                    linked_ids = [row.alert_id for row in self.session.query(IncidentAlert).filter_by(incident_id=candidate.id).all()]
                    linked = self.session.query(Alert).filter(Alert.id.in_(linked_ids)).all() if linked_ids else []
                    if any(alert.source_ip == values['source_ip'] and
                           alert.destination_ip == values['destination_ip'] and
                           alert.protocol == values['protocol'] for alert in linked):
                        incident = candidate
                        break
                if incident is None:
                    incident = Incident(first_seen=values['first_seen'], last_seen=values['last_seen'], status='OPEN', severity=values['severity'], confidence=values['confidence'], risk=values['risk'], category='behavioral' if values.get('detection_type') == 'behavioral' else 'signature', event_count=1, explanation=values['message'])
                    self.session.add(incident)
                    self.session.flush()
                else:
                    incident.last_seen = max(incident.last_seen or 0, values['last_seen'])
                    incident.event_count = (incident.event_count or 0) + 1
                    incident.confidence = max(incident.confidence or 0, values['confidence'])
                    incident.risk = max(incident.risk or 0, values['risk'])
                alert_id = int(values.get('id', 0) or 0)
                if alert_id:
                    self.session.merge(IncidentAlert(incident_id=incident.id, alert_id=alert_id))
                self.session.commit()
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist incident: %s", error)

    def persist_runtime_status(
            self, state: str, source: str,
            packets_captured: int = 0, packets_processed: int = 0,
            last_packet_time=None, packets_failed: int = 0,
            # Extended SPAN / capture statistics
            capture_mode: str = "normal",
            capture_interface: str = "",
            bytes_captured: int = 0,
            duplicate_packets: int = 0,
            malformed_packets: int = 0,
            ipv4_packets: int = 0, ipv6_packets: int = 0,
            vlan_packets: int = 0,
            tcp_packets: int = 0, udp_packets: int = 0,
            icmp_packets: int = 0, icmpv6_packets: int = 0,
            zero_traffic_warning: bool = False, error: str | None = None) -> None:
        if not self.session:
            return
        payload = json.dumps({
            "status": state, "source": source,
            "packets_captured": packets_captured, "packets_processed": packets_processed,
            "last_packet_time": last_packet_time, "packets_failed": packets_failed,
            "capture_mode": capture_mode, "capture_interface": capture_interface,
            "bytes_captured": bytes_captured, "duplicate_packets": duplicate_packets,
            "malformed_packets": malformed_packets, "ipv4_packets": ipv4_packets,
            "ipv6_packets": ipv6_packets, "vlan_packets": vlan_packets,
            "tcp_packets": tcp_packets, "udp_packets": udp_packets,
            "icmp_packets": icmp_packets, "icmpv6_packets": icmpv6_packets,
            "zero_traffic_warning": zero_traffic_warning, "error": error
        })
        with self._lock:
            try:
                self.session.query(Statistic).filter(Statistic.name == "capture_runtime").delete(synchronize_session=False)
                self.session.add(Statistic(timestamp=now_epoch(), name="capture_runtime", value=0, text_value=payload))
                self.session.commit()
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist capture runtime status: %s", error)

    def _persist_statistic(self, name: str, value: int) -> None:
        if not self.session:
            return
        with self._lock:
            try:
                self.session.add(Statistic(timestamp=now_epoch(), name=name, value=value))
                self.session.commit()
            except (SQLAlchemyError, sqlite3.OperationalError) as error:
                self.session.rollback()
                logger.error("failed to persist statistic: %s", error)

    def _upsert_statistic(self, name: str, value: int) -> None:
        """Maintain a single current row per counter name (no unbounded history).

        Called from the capture thread's hot loop: one idempotent write per
        second instead of two committed transactions per packet keeps the
        shared database's write lock available for the dashboard and the C++
        API, which previously collided into "database is locked".
        """
        if not self.session:
            return
        if threading.current_thread() is not getattr(self, "_db_owner_thread", None):
            return
        with self._lock:
            try:
                timestamp = now_epoch()
                statement = sqlite_insert(Statistic).values(
                    timestamp=timestamp, name=name, value=int(value)
                ).on_conflict_do_update(
                    index_elements=[Statistic.__table__.c.name],
                    set_={"timestamp": timestamp, "value": int(value)},
                )
                self.session.execute(statement)
                self.session.commit()
            except (SQLAlchemyError, sqlite3.OperationalError) as error:
                self.session.rollback()
                logger.error("failed to upsert statistic: %s", error)

    def get_recent_traffic(self, limit=100):
        return list(self._live_traffic)[:limit]

    def get_recent_alerts(self, limit=500):
        return list(self._live_alerts)[:limit]

    def __del__(self):
        # Best-effort cleanup for short-lived replay/test processes. Long-lived
        # applications should call close() explicitly during shutdown.
        try:
            self.close()
        except Exception:
            pass

    def clear_runtime_state(self) -> None:
        """Clear in-memory event views without affecting capture or rules."""
        with self._lock:
            self._live_traffic.clear()
            self._live_alerts.clear()
            self._live_alert_index.clear()

    def get_alert_counts(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
        for alert in self._live_alerts:
            severity = str(alert.get("severity", "LOW")).upper()
            counts[severity] = counts.get(severity, 0) + 1
            counts["total"] += 1
        return counts

    def purge_false_sweep_alerts(self, host_threshold: int | None = None,
                                 arp_threshold: int | None = None) -> int:
        """Remove persisted SID 90002 alerts that cannot be justified.

        Alerts produced by the pre-fix host-discovery detector claimed a
        "host discovery sweep" on the basis of a weak target count and no
        scope awareness. This revalidates each stored 90002 row against the
        current evidence contract and deletes rows whose stored evidence
        records fewer distinct targets than the configured threshold (which is
        also the case for the alerts generated by the old default threshold).

        Returns the number of alerts removed.
        """
        if not self.session:
            return 0
        from database.models import Alert, IncidentAlert
        import re as _re
        removed = 0
        with self._lock:
            try:
                rows = self.session.query(Alert).filter(Alert.sid == 90002).all()
                for row in rows:
                    evidence = row.evidence or ""
                    protocol = (row.protocol or "").upper()
                    threshold = arp_threshold if protocol == "ARP" else host_threshold
                    if threshold is None:
                        continue
                    match = _re.search(r"distinct_targets=(\d+)", evidence)
                    if not match:
                        continue
                    if int(match.group(1)) < threshold:
                        self.session.query(IncidentAlert).filter_by(alert_id=row.id).delete(synchronize_session=False)
                        self.session.delete(row)
                        removed += 1
                self.session.commit()
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to purge sweep alerts: %s", error)
                raise
        return removed

    def reset_session_data(self) -> None:
        """Remove current-session evidence while preserving configured rules."""
        if not self.session:
            self.clear_runtime_state()
            return
        with self._lock:
            try:
                for model in (IncidentAlert, Incident, Alert, TrafficLog, Statistic):
                    self.session.query(model).delete(synchronize_session=False)
                self.session.commit()
                self.clear_runtime_state()
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to reset session data: %s", error)
                raise

    def close(self) -> None:
        if self.session:
            bind = self.session.get_bind()
            self.session.close()
            if bind:
                bind.dispose()


