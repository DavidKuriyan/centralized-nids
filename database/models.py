from __future__ import annotations

import datetime
import os
import pathlib
import sqlite3

from sqlalchemy import Boolean, Column, Integer, String, Text, UniqueConstraint, create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_seen = Column(Integer, nullable=False, default=lambda: int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
    last_seen = Column(Integer, nullable=False, default=lambda: int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
    occurrence_count = Column(Integer, nullable=False, default=1)
    suppressed_count = Column(Integer, nullable=False, default=0)
    severity = Column(String(20), nullable=False, default="MEDIUM")
    confidence = Column(Integer, nullable=False, default=0)
    risk = Column(Integer, nullable=False, default=0)
    detection_type = Column(String(40), nullable=False, default="signature")
    sid = Column(Integer, nullable=False, default=0)
    revision = Column(Integer, nullable=False, default=0)
    source_ip = Column(String(50))
    source_port = Column(Integer)
    destination_ip = Column(String(50))
    destination_port = Column(Integer)
    protocol = Column(String(20))
    service = Column(String(80))
    flow_id = Column(Integer, nullable=False, default=0)
    traffic_id = Column(Integer, nullable=False, default=0)
    message = Column(Text)
    evidence = Column(Text)
    explanation = Column(Text)
    fingerprint = Column(String(255), unique=True)


class Flow(Base):
    __tablename__ = "flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    start_time = Column(Integer)
    last_seen = Column(Integer)
    service = Column(String(80))
    protocol = Column(String(20))
    packets = Column(Integer, default=0)
    bytes = Column(Integer, default=0)


class DetectionEvent(Base):
    __tablename__ = "detection_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Integer)
    flow_id = Column(Integer, default=0)
    sid = Column(Integer, default=0)
    event_type = Column(String(40))
    explanation = Column(Text)
    evidence = Column(Text)


class Rule(Base):
    __tablename__ = "rules"

    sid = Column(Integer, primary_key=True)
    revision = Column(Integer, primary_key=True)
    message = Column(Text)
    enabled = Column(Boolean, default=True)
    source_file = Column(Text)
    gid = Column(Integer, nullable=False, default=1)
    priority = Column(Integer, nullable=False, default=3)
    protocol = Column(String(20))
    category = Column(String(100))
    rule_text = Column(Text)
    rule_json = Column(Text)
    updated_at = Column(Integer)


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, primary_key=True)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_seen = Column(Integer, nullable=False, default=0)
    last_seen = Column(Integer, nullable=False, default=0)
    status = Column(String(20), nullable=False, default="OPEN")
    severity = Column(String(20), nullable=False, default="MEDIUM")
    confidence = Column(Integer, nullable=False, default=0)
    risk = Column(Integer, nullable=False, default=0)
    category = Column(String(100), nullable=False, default="signature")
    event_count = Column(Integer, nullable=False, default=0)
    explanation = Column(Text)


class Statistic(Base):
    __tablename__ = "statistics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Integer)
    # The capture hot loop upserts one current row per counter name (see
    # idx_statistics_name in _migrate_existing_tables) instead of appending
    # history rows, keeping write volume -- and lock contention with the
    # dashboard/API -- bounded.
    name = Column(String(100))
    value = Column(Integer)
    text_value = Column(Text)


class TrafficLog(Base):
    """Compatibility model for the Python capture path's packet stream."""

    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Integer)
    src_ip = Column(String(50))
    dst_ip = Column(String(50))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(20))
    length = Column(Integer)
    payload_summary = Column(Text)
    details = Column(Text)


_MIGRATIONS = (
    # (table, column, ALTER definition) applied to databases created before the column existed.
    ("alerts", "traffic_id",             "INTEGER NOT NULL DEFAULT 0"),
    ("alerts", "ip_version",             "INTEGER NOT NULL DEFAULT 0"),
    ("alerts", "capture_mode",           "TEXT"),
    ("alerts", "capture_interface",      "TEXT"),
    ("alerts", "vlan_id",               "INTEGER NOT NULL DEFAULT -1"),
    ("alerts", "source_mac",             "TEXT"),
    ("alerts", "destination_mac",        "TEXT"),
    ("traffic_logs", "details",          "TEXT"),
    ("traffic_logs", "ip_version",       "INTEGER NOT NULL DEFAULT 0"),
    ("traffic_logs", "capture_mode",     "TEXT"),
    ("traffic_logs", "vlan_id",          "INTEGER NOT NULL DEFAULT -1"),
    ("rules", "gid",                     "INTEGER NOT NULL DEFAULT 1"),
    ("rules", "priority",               "INTEGER NOT NULL DEFAULT 3"),
    ("rules", "protocol",               "VARCHAR(20)"),
    ("rules", "category",               "VARCHAR(100)"),
    ("rules", "rule_text",              "TEXT"),
    ("rules", "rule_json",              "TEXT"),
    ("rules", "updated_at",             "INTEGER"),
    ("statistics", "text_value",        "TEXT"),
)


def _migrate_existing_tables(engine) -> None:
    """Add columns introduced after the first release without touching existing data."""
    with engine.connect() as connection:
        for table, column, definition in _MIGRATIONS:
            rows = connection.execute(text(f"PRAGMA table_info({table})")).fetchall()
            if rows and all(row[1] != column for row in rows):
                connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {definition}"))
                connection.commit()
        # Counters moved from append-only history to one row per name. Older
        # databases hold many rows per name, so deduplicate (keeping the most
        # recent) before the unique index required by the upsert can be built.
        indexes = connection.execute(text("PRAGMA index_list(statistics)")).fetchall()
        if all(row[1] != "idx_statistics_name" for row in indexes):
            connection.execute(text(
                "DELETE FROM statistics WHERE id NOT IN "
                "(SELECT MAX(id) FROM statistics GROUP BY name)"
            ))
            connection.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_statistics_name ON statistics(name)"
            ))
            connection.commit()


_ENGINES: dict[str, tuple] = {}
_INITIALIZED: set[str] = set()


def _configure_sqlite_engine(engine) -> None:
    """Make concurrent multi-process, multi-thread access safe.

    The NIDS capture process, the C++ REST API, and the dashboard all open the
    same database file. With the default rollback journal and no busy
    timeout, the capture thread's per-packet writes and the dashboard's
    schema introspection collide into "database is locked". WAL mode lets
    readers proceed during writes and a busy timeout makes writers queue
    instead of failing.

    NullPool plus ``check_same_thread=False`` gives every session its own
    connection that may be used from whatever thread holds it (the heartbeat
    thread, Flask request workers, the Windows raw-socket capture thread);
    callers serialize shared sessions through their own locks.
    """

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA busy_timeout=10000")
            try:
                # WAL is persistent per database file; once enabled for the
                # file, every other process (C++ API included) benefits. A
                # transient failure only delays the upgrade.
                cursor.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


def init_db(db_path="nids.db"):
    """Create/open the schema shared with the C++ REST API.

    Engines are cached per database path and schema creation/migration runs
    once per process, so request handlers no longer re-reflect the schema on
    every call.
    """
    database = pathlib.Path(db_path).expanduser().resolve()
    parent = database.parent
    parent.mkdir(parents=True, exist_ok=True)
    if database.exists() and not os.access(database, os.W_OK):
        raise PermissionError(f"database is not writable: {database}; repair ownership or permissions")
    if not os.access(parent, os.W_OK):
        raise PermissionError(f"database directory is not writable: {parent}; repair ownership or permissions")
    key = str(database)
    cached = _ENGINES.get(key)
    if cached is None:
        engine = create_engine(
            f"sqlite:///{database}", future=True,
            connect_args={"timeout": 10.0, "check_same_thread": False},
            poolclass=NullPool,
        )
        _configure_sqlite_engine(engine)
        cached = (engine, sessionmaker(bind=engine, future=True))
        _ENGINES[key] = cached
    engine, factory = cached
    if key not in _INITIALIZED:
        Base.metadata.create_all(engine)
        _migrate_existing_tables(engine)
        _INITIALIZED.add(key)
    return factory()
