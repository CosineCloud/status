#!/usr/bin/env python3
"""
Single-file Flask status dashboard (no Telegram).

Changes made:
- CSS switched to a clean, Apple-inspired white theme.
- Issue reports are posted from the public dashboard only; reports remain visible on the /update admin page.
- /api/report returns a friendly confirmation message on success.
- Incidents and Developer Messages on the dashboard open a popup modal with full details when clicked.
- Added Title fields for Developer Messages and Incidents (admin can set).
- Removed report form from /update page.
- Reordered dashboard sections: Status Monitors, Incident Log, Developer Messages, Issue Reports.

Run:
    pip install flask sqlalchemy requests email-validator
    python main.py

Notes:
- DB defaults to sqlite:///status_dash.sqlite (change via DATABASE_URL env var)
- This is intentionally single-file for ease of deployment.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).with_name(".env"))
import sys
import time
import shlex
import subprocess
import asyncio
import json
import re
import math
import hashlib
from datetime import datetime, date, timedelta
from typing import Optional, Tuple, Iterable

from flask import (
    Flask, render_template, render_template_string, request, jsonify, redirect, url_for, session, abort
)
from sqlalchemy import (
    event, inspect, text, create_engine, Column, Integer, String, DateTime, Boolean, Float, Text, ForeignKey, Date, and_, or_, exists
)
from sqlalchemy.sql import func as sa_func
import secrets
import string
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
import requests

# ---------------- CONFIG ----------------
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///status_dash.sqlite")
SAMPLE_SECS = int(os.environ.get("STATUS_SAMPLE_SECS", "10"))
# Runtime-adjustable sampling interval used by background sampler
SAMPLE_SECS_RUNTIME = SAMPLE_SECS
# Last-run timestamps per tag for per-tag intervals
SAMPLE_LAST_RUN_BY_TAG = {}
DEV_RESET_DB = False  # set True to wipe DB each run (dev only)
COMMENTS_ENABLED = True

# Admin update key (user-provided)
UPDATE_KEY = os.environ["UPDATE_KEY"]

# Dashboard PIN protection
DASHBOARD_PIN = os.environ["DASHBOARD_PIN"]

# License required to post issue reports
ALLOWED_LICENSE = "VCT5187"
ALLOWED_ERROR_CONTACT = "issue@nascm.cloud"

# Flask secret key for session cookies
FLASK_SECRET = os.environ["FLASK_SECRET"]

# ---------------- DB ----------------
Base = declarative_base()
engine = create_engine(DB_URL, future=True, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, future=True)


class Status(Base):
    __tablename__ = "status"
    id = Column(Integer, primary_key=True, autoincrement=True)
    public_id = Column(String(6), nullable=True, unique=True)
    kind = Column(String(16), nullable=False)  # 'ping' | 'html' | 'tcp'
    target = Column(String(512), nullable=False)
    server_name = Column(String(256), nullable=True)  # Display name to hide IP
    graph_type = Column(String(16), default='line', nullable=False)  # 'line' | 'bar'
    graph_color = Column(String(7), default='#0a84ff', nullable=False)  # hex color
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    dashboard_tag = Column(String(120), nullable=True)
    datapoints = relationship("StatusData", back_populates="status", cascade="all, delete-orphan")


class DisplayCodeReservation(Base):
    __tablename__ = "display_code_reservations"
    namespace = Column(String(30), primary_key=True)
    code = Column(String(6), primary_key=True)


class MetricTextReading(Base):
    __tablename__ = "metric_text_readings"
    status_id = Column(Integer, ForeignKey("status.id", ondelete="CASCADE"), primary_key=True)
    output = Column(Text, nullable=False)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class MetricConfig(Base):
    __tablename__ = "metric_configs"
    status_id = Column(Integer, ForeignKey("status.id", ondelete="CASCADE"), primary_key=True)
    ssh_server_id = Column(Integer, ForeignKey("ssh_servers.id"), nullable=True)
    command = Column(Text, nullable=True)
    min_value = Column(Float, nullable=False, default=0)
    max_value = Column(Float, nullable=False, default=100)
    unit = Column(String(30), nullable=False, default="%")
    interval_secs = Column(Integer, nullable=False, default=10)
    needle_color = Column(String(7), nullable=False, default="#18243a")
    show_value = Column(Boolean, nullable=False, default=True)
    decimals = Column(Integer, nullable=False, default=1)


def metric_config_dict(db, status_id, admin=False):
    config = db.get(MetricConfig, status_id)
    if config is None:
        return None
    result = {name: getattr(config, name) for name in ("min_value", "max_value", "unit", "interval_secs", "needle_color", "show_value", "decimals")}
    if admin:
        result.update(command=config.command, ssh_server_id=config.ssh_server_id)
    return result


class StatusData(Base):
    __tablename__ = "status_data"
    id = Column(Integer, primary_key=True)
    status_id = Column(Integer, ForeignKey("status.id", ondelete="CASCADE"), index=True, nullable=False)
    ts = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    latency_ms = Column(Float, nullable=True)  # None if unreachable
    success = Column(Boolean, default=False, nullable=False)
    status = relationship("Status", back_populates="datapoints")


class DevMessage(Base):
    __tablename__ = "dev_messages"
    id = Column(Integer, primary_key=True)
    public_id = Column(String(6), nullable=True, unique=True)
    title = Column(String(200), nullable=False, default="")
    message = Column(Text, nullable=False)
    dashboard_tag = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    public_id = Column(String(6), nullable=True, unique=True)
    title = Column(String(200), nullable=False, default="")
    tag = Column(String(32), nullable=False)  # event/warning/minor/major
    message = Column(Text, nullable=False)
    dashboard_tag = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class IssueReport(Base):
    __tablename__ = "issue_reports"
    id = Column(Integer, primary_key=True)
    username = Column(String(120), nullable=False)
    license_number = Column(String(120), nullable=False, index=True)
    issue = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_day = Column(Date, default=date.today, nullable=False, index=True)


class SSHAlarm(Base):
    __tablename__ = "ssh_alarms"
    id = Column(Integer, primary_key=True)
    public_id = Column(String(6), nullable=True, unique=True)
    server_name = Column(String(200), nullable=False)
    alarm_type = Column(String(50), nullable=False)  # 'active' or 'history'
    severity = Column(String(20), nullable=False)  # 'critical', 'warning', 'info'
    message = Column(Text, nullable=False)
    details = Column(Text, nullable=True)
    dashboard_tag = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)


class AutoAlarmState(Base):
    __tablename__ = "auto_alarm_state"
    alarm_id = Column(Integer, ForeignKey("ssh_alarms.id", ondelete="CASCADE"), primary_key=True)
    fingerprint = Column(String(300), nullable=False)
    present = Column(Boolean, nullable=False, default=True)


class ImportedAlarmEvent(Base):
    __tablename__ = "imported_alarm_events"
    event_key = Column(String(64), primary_key=True)
    # Keep a receipt even when a user deletes the alarm, so it stays deleted.
    imported_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class SSHServer(Base):
    __tablename__ = "ssh_servers"
    id = Column(Integer, primary_key=True)
    server_name = Column(String(200), nullable=False, unique=True)
    ip_address = Column(String(45), nullable=False)  # IPv4 or IPv6
    username = Column(String(100), nullable=False)
    password = Column(String(500), nullable=False)  # Should be encrypted in production
    port = Column(Integer, default=22, nullable=False)
    fetch_interval = Column(Integer, default=300, nullable=False)  # seconds
    last_fetch = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    auto_fetch_enabled = Column(Boolean, default=False, nullable=False)  # Only fetch if enabled
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class DashboardKey(Base):
    __tablename__ = "dashboard_keys"
    id = Column(Integer, primary_key=True)
    tag = Column(String(120), nullable=False)
    key_value = Column(String(64), nullable=False, unique=True)
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

FEATURE_NAMES = ("monitors", "messages", "incidents", "alarms")

class KeyFeatures(Base):
    __tablename__ = "key_features"
    key_id = Column(Integer, ForeignKey("dashboard_keys.id", ondelete="CASCADE"), primary_key=True)
    features_json = Column(Text, nullable=False, default="{}")

class AppSetting(Base):
    __tablename__ = "app_settings"
    name = Column(String(120), primary_key=True)
    value = Column(Integer, nullable=False)


def key_features(db, key_id):
    row = db.get(KeyFeatures, key_id)
    stored = json.loads(row.features_json) if row else {}
    return {name: stored.get(name, True) for name in FEATURE_NAMES}


def global_sample_seconds(db):
    setting = db.get(AppSetting, "sample_seconds")
    return setting.value if setting else SAMPLE_SECS


class TagInterval(Base):
    __tablename__ = "tag_intervals"
    id = Column(Integer, primary_key=True)
    tag = Column(String(120), nullable=False, unique=True)
    seconds = Column(Integer, nullable=False, default=SAMPLE_SECS)


if DEV_RESET_DB:
    Base.metadata.drop_all(engine)
class StatusTag(Base):
    __tablename__ = "status_tags"
    id = Column(Integer, primary_key=True)
    status_id = Column(Integer, ForeignKey("status.id", ondelete="CASCADE"), index=True, nullable=False)
    tag = Column(String(120), nullable=False, index=True)


class DevMessageTag(Base):
    __tablename__ = "dev_message_tags"
    id = Column(Integer, primary_key=True)
    dev_message_id = Column(Integer, ForeignKey("dev_messages.id", ondelete="CASCADE"), index=True, nullable=False)
    tag = Column(String(120), nullable=False, index=True)


class IncidentTag(Base):
    __tablename__ = "incident_tags"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    tag = Column(String(120), nullable=False, index=True)


class SSHAlarmTag(Base):
    __tablename__ = "ssh_alarm_tags"
    id = Column(Integer, primary_key=True)
    alarm_id = Column(Integer, ForeignKey("ssh_alarms.id", ondelete="CASCADE"), index=True, nullable=False)
    tag = Column(String(120), nullable=False, index=True)


# Helper functions for key-based filtering

def get_active_tag_for_key_value(key_value: Optional[str]) -> Optional[str]:
    if not key_value:
        return None
    try:
        with SessionLocal() as s:
            now = datetime.utcnow()
            k = s.query(DashboardKey).filter(DashboardKey.key_value == key_value).first()
            if not k:
                return None
            if not k.is_active:
                return None
            if k.expires_at and k.expires_at <= now:
                return None
            return k.tag
    except Exception:
        return None


def get_request_tag() -> Optional[str]:
    # Read dashboard key from header and resolve to tag
    key_value = request.headers.get('X-Dashboard-Key')
    return get_active_tag_for_key_value(key_value)


def allocate_display_code(connection, namespace, width):
    table = DisplayCodeReservation.__table__
    used = set(connection.execute(table.select().with_only_columns(table.c.code).where(table.c.namespace == namespace)).scalars())
    capacity = 10 ** width
    if len(used) >= capacity:
        raise ValueError(f"All {width}-digit display IDs have been allocated for {namespace}")
    for _ in range(100):
        code = str(secrets.randbelow(capacity)).zfill(width)
        if code not in used:
            break
    else:
        code = next(str(i).zfill(width) for i in range(capacity) if str(i).zfill(width) not in used)
    connection.execute(table.insert().values(namespace=namespace, code=code))
    return code


def assign_display_code(mapper, connection, target):
    if not target.public_id:
        target.public_id = allocate_display_code(connection, target.__tablename__, 6 if isinstance(target, SSHAlarm) else 3)


for display_model in (Status, DevMessage, Incident, SSHAlarm):
    event.listen(display_model, "before_insert", assign_display_code)


Base.metadata.create_all(engine)
# Add optional presentation settings to existing metric databases.
metric_columns = {column["name"] for column in inspect(engine).get_columns("metric_configs")}
with engine.begin() as connection:
    if "show_value" not in metric_columns:
        connection.execute(text("ALTER TABLE metric_configs ADD COLUMN show_value BOOLEAN NOT NULL DEFAULT TRUE"))
    if "decimals" not in metric_columns:
        connection.execute(text("ALTER TABLE metric_configs ADD COLUMN decimals INTEGER NOT NULL DEFAULT 1"))


# Stable public labels are separate from internal relational IDs.
for display_model in (Status, DevMessage, Incident, SSHAlarm):
    table_name = display_model.__tablename__
    columns = {column["name"] for column in inspect(engine).get_columns(table_name)}
    with engine.begin() as connection:
        if "public_id" not in columns:
            connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN public_id VARCHAR(6)"))
        rows = connection.execute(text(f"SELECT id FROM {table_name} WHERE public_id IS NULL")).all()
        for row in rows:
            code = allocate_display_code(connection, table_name, 6 if display_model is SSHAlarm else 3)
            connection.execute(text(f"UPDATE {table_name} SET public_id=:code WHERE id=:id"), {"code": code, "id": row.id})
        connection.execute(text(f"CREATE UNIQUE INDEX IF NOT EXISTS ix_{table_name}_public_id ON {table_name}(public_id)"))


with SessionLocal() as settings_db:
    SAMPLE_SECS_RUNTIME = global_sample_seconds(settings_db)


def request_feature_enabled(name):
    with SessionLocal() as db:
        key = db.query(DashboardKey).filter_by(key_value=request.headers.get("X-Dashboard-Key")).first()
        return bool(key and get_request_tag() and key_features(db, key.id)[name])


# Previous versions used history for explicit resolutions. Migrate once.
with SessionLocal() as db:
    if db.get(AppSetting, "alarm_states_v2") is None:
        db.query(SSHAlarm).filter(SSHAlarm.is_active == False, SSHAlarm.resolved_at.isnot(None), SSHAlarm.alarm_type == "history").update({SSHAlarm.alarm_type: "resolved"}, synchronize_session=False)
        db.add(AppSetting(name="alarm_states_v2", value=1))
        db.commit()


def alarm_fingerprint(message):
    # Measurements change each poll; identify the condition independently of values.
    return re.sub(r"\d+(?:\.\d+)?", "#", message).strip().lower()


def sync_detected_alarms(db, server_name, detected):
    """Reconcile only known automatic alarms after a successful SSH check."""
    if detected is None:
        return 0  # Connection failures never mean an alarm cleared.
    history_added = 0
    for event in (a for a in detected if a.get("_history")):
        event_key = hashlib.sha256((server_name + "\n" + event["event_id"]).encode()).hexdigest()
        if db.get(ImportedAlarmEvent, event_key):
            continue
        timestamp = event.get("occurred_at") or datetime.utcnow()
        alarm = SSHAlarm(server_name=server_name, alarm_type="history", severity=event["severity"], message=event["message"], details=event.get("details"), dashboard_tag=DEFAULT_DASHBOARD_TAG, is_active=False, created_at=timestamp, resolved_at=timestamp)
        db.add(alarm); db.flush()
        db.add(ImportedAlarmEvent(event_key=event_key))
        db.add(AutoAlarmState(alarm_id=alarm.id, fingerprint=event_key, present=False))
        ensure_alarm_tags(db, alarm.id, [DEFAULT_DASHBOARD_TAG])
        history_added += 1
    current = {alarm_fingerprint(a["message"]): a for a in detected if not a.get("_history")}
    tracked = db.query(AutoAlarmState, SSHAlarm).join(SSHAlarm, SSHAlarm.id == AutoAlarmState.alarm_id).filter(SSHAlarm.server_name == server_name, AutoAlarmState.present == True).all()
    present = {}
    for state, alarm in tracked:
        if state.fingerprint not in current:
            if alarm.is_active:
                alarm.is_active = False
                alarm.alarm_type = "history"
                alarm.resolved_at = datetime.utcnow()
            state.present = False
        else:
            present[state.fingerprint] = alarm
    added = 0
    for fingerprint, data in current.items():
        existing = present.get(fingerprint)
        if existing:
            if existing.is_active:
                existing.message = data["message"]
                existing.details = data.get("details")
                existing.severity = data["severity"]
            continue  # Forced resolution masks the condition until it clears.
        alarm = SSHAlarm(server_name=server_name, alarm_type="active", severity=data["severity"], message=data["message"], details=data.get("details"), is_active=True, dashboard_tag=DEFAULT_DASHBOARD_TAG)
        db.add(alarm); db.flush()
        db.add(AutoAlarmState(alarm_id=alarm.id, fingerprint=fingerprint))
        ensure_alarm_tags(db, alarm.id, [DEFAULT_DASHBOARD_TAG])
        added += 1
    return added + history_added


# Tag helpers
DEFAULT_DASHBOARD_TAG = 'NASCM-Default'

def ensure_status_tags(session, status_id: int, selected_tags: Optional[Iterable[str]]):
    existing = {r.tag for r in session.query(StatusTag).filter(StatusTag.status_id == status_id).all()}
    to_add = set()
    # Normalize selected_tags robustly
    candidates: Iterable[str]
    if not selected_tags:
        candidates = []
    elif isinstance(selected_tags, str):
        candidates = [selected_tags]
    elif isinstance(selected_tags, (list, tuple, set)):
        candidates = list(selected_tags)
    else:
        # Fallback: treat whole object as a single tag (avoid iterating characters)
        candidates = [str(selected_tags)]
    # If user provided none, fall back to default
    if not candidates:
        to_add.add(DEFAULT_DASHBOARD_TAG)
    for raw in candidates:
        t = (raw or '').strip()
        if t:
            to_add.add(t)
    for t in (to_add - existing):
        session.add(StatusTag(status_id=status_id, tag=t))


def ensure_dev_tags(session, dev_id: int, selected_tags: Optional[Iterable[str]]):
    existing = {r.tag for r in session.query(DevMessageTag).filter(DevMessageTag.dev_message_id == dev_id).all()}
    to_add = set()
    # Normalize
    if not selected_tags:
        candidates = []
    elif isinstance(selected_tags, str):
        candidates = [selected_tags]
    elif isinstance(selected_tags, (list, tuple, set)):
        candidates = list(selected_tags)
    else:
        candidates = [str(selected_tags)]
    if not candidates:
        to_add.add(DEFAULT_DASHBOARD_TAG)
    for raw in candidates:
        t = (raw or '').strip()
        if t:
            to_add.add(t)
    for t in (to_add - existing):
        session.add(DevMessageTag(dev_message_id=dev_id, tag=t))


def ensure_incident_tags(session, incident_id: int, selected_tags: Optional[Iterable[str]]):
    existing = {r.tag for r in session.query(IncidentTag).filter(IncidentTag.incident_id == incident_id).all()}
    to_add = set()
    # Normalize
    if not selected_tags:
        candidates = []
    elif isinstance(selected_tags, str):
        candidates = [selected_tags]
    elif isinstance(selected_tags, (list, tuple, set)):
        candidates = list(selected_tags)
    else:
        candidates = [str(selected_tags)]
    if not candidates:
        to_add.add(DEFAULT_DASHBOARD_TAG)
    for raw in candidates:
        t = (raw or '').strip()
        if t:
            to_add.add(t)
    for t in (to_add - existing):
        session.add(IncidentTag(incident_id=incident_id, tag=t))


def ensure_alarm_tags(session, alarm_id: int, selected_tags: Optional[Iterable[str]]):
    existing = {r.tag for r in session.query(SSHAlarmTag).filter(SSHAlarmTag.alarm_id == alarm_id).all()}
    to_add = set()
    # Normalize
    if not selected_tags:
        candidates = []
    elif isinstance(selected_tags, str):
        candidates = [selected_tags]
    elif isinstance(selected_tags, (list, tuple, set)):
        candidates = list(selected_tags)
    else:
        candidates = [str(selected_tags)]
    if not candidates:
        to_add.add(DEFAULT_DASHBOARD_TAG)
    for raw in candidates:
        t = (raw or '').strip()
        if t:
            to_add.add(t)
    for t in (to_add - existing):
        session.add(SSHAlarmTag(alarm_id=alarm_id, tag=t))

# Ensure NASCM-Default dashboard key exists
try:
    with SessionLocal() as s:
        default_tag = DEFAULT_DASHBOARD_TAG
        default_key_value = DASHBOARD_PIN
        # If a key with this exact value exists, ensure attributes
        key = s.query(DashboardKey).filter(DashboardKey.key_value == default_key_value).first()
        if key:
            key.tag = default_tag
            key.is_active = True
            key.expires_at = None
        else:
            # If any key exists for the default tag, leave it as-is (do not create another fixed key)
            existing_for_tag = s.query(DashboardKey).filter(DashboardKey.tag == default_tag).first()
            if not existing_for_tag:
                k = DashboardKey(tag=default_tag, key_value=default_key_value, is_active=True, expires_at=None)
                s.add(k)
        s.commit()
except Exception as e:
    print(f"Default key seed error: {e}")

# Backfill tags for existing records (idempotent)
try:
    with SessionLocal() as s:
        # Status
        for st in s.query(Status).all():
            ensure_status_tags(s, st.id, st.dashboard_tag)
        # Dev messages
        for dm in s.query(DevMessage).all():
            ensure_dev_tags(s, dm.id, dm.dashboard_tag)
        # Incidents
        for it in s.query(Incident).all():
            ensure_incident_tags(s, it.id, it.dashboard_tag)
        # SSH Alarms
        for al in s.query(SSHAlarm).all():
            ensure_alarm_tags(s, al.id, al.dashboard_tag)
        s.commit()
except Exception as e:
    print(f"Backfill tags error: {e}")

# Legacy SSH fetches left dashboard_tag unset; manual creation always assigned it.
with SessionLocal() as db:
    if db.get(AppSetting, "alarm_origins_v1") is None:
        server_names = {server.server_name for server in db.query(SSHServer).all()}
        prefixes = ("System load:", "Disk usage ", "Memory usage:", "Failed login attempts:", "Process count:", "SSH monitoring active for ")
        for alarm in db.query(SSHAlarm).filter(SSHAlarm.dashboard_tag.is_(None)).all():
            if alarm.server_name in server_names and alarm.message.startswith(prefixes):
                db.add(AutoAlarmState(alarm_id=alarm.id, fingerprint=alarm_fingerprint(alarm.message), present=alarm.is_active or alarm.alarm_type == "resolved"))
        db.add(AppSetting(name="alarm_origins_v1", value=1))
        db.commit()


# Add auto_fetch_enabled column if it doesn't exist (for existing databases)
try:
    with engine.connect() as conn:
        # Check if column exists
        from sqlalchemy import text
        result = conn.execute(text("PRAGMA table_info(ssh_servers)"))
        columns = [row[1] for row in result.fetchall()]
        if 'auto_fetch_enabled' not in columns:
            conn.execute(text("ALTER TABLE ssh_servers ADD COLUMN auto_fetch_enabled BOOLEAN DEFAULT 0"))
            conn.commit()
            print("Added auto_fetch_enabled column to ssh_servers table")
except Exception as e:
    print(f"Schema update error (can be ignored if column exists): {e}")

# ---------------- Utilities ----------------
VALID_TAGS = {"event": "#10b981", "warning": "#f59e0b", "minor": "#fb923c", "major": "#ef4444"}


def short_ts() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def ping_once(host: str, timeout_sec: int = 3) -> Tuple[bool, Optional[float]]:
    """
    Uses system ping. Returns (ok, latency_ms) where latency_ms is measured time until process finishes or None.
    Works on Linux/macOS/Windows (best-effort).
    If host contains a port (host:port), it will extract just the host part for ping.
    """
    try:
        # Extract host part if port is specified
        if ':' in host:
            host = host.rsplit(':', 1)[0]

        if sys.platform.startswith("win"):
            cmd = ["ping", "-n", "1", "-w", str(timeout_sec * 1000), host]
        else:
            # Linux/macOS best-effort
            cmd = ["ping", "-c", "1", "-W", str(timeout_sec), host]
        t0 = time.perf_counter()
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_sec + 2)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        ok = proc.returncode == 0
        return ok, (elapsed_ms if ok else None)
    except Exception:
        return False, None


def html_check(url: str, timeout_sec: int = 6) -> Tuple[bool, Optional[float]]:
    try:
        t0 = time.perf_counter()
        r = requests.get(url, timeout=timeout_sec)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        ok = r.status_code < 400
        return ok, (elapsed_ms if ok else None)
    except Exception:
        return False, None


def tcp_check(host_port: str, timeout_sec: int = 3) -> Tuple[bool, Optional[float]]:
    """
    Check TCP port connectivity. Format: host:port or ip:port
    """
    import socket
    try:
        if ':' not in host_port:
            return False, None
        host, port_str = host_port.rsplit(':', 1)
        port = int(port_str)

        t0 = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        result = sock.connect_ex((host, port))
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        sock.close()

        ok = result == 0
        return ok, (elapsed_ms if ok else None)
    except Exception:
        return False, None


def read_ssh_journal_history(ssh):
    """Read bounded, recent warning/error journal events; unavailable journals are optional."""
    try:
        _, stdout, _ = ssh.exec_command("journalctl --since '24 hours ago' -p warning -n 100 --no-pager -o json 2>/dev/null", timeout=10)
        output = stdout.read(1048576).decode(errors="replace")
        events = []
        for line in output.splitlines():
            try:
                entry = json.loads(line)
                message = entry.get("MESSAGE")
                if not isinstance(message, str) or not message.strip():
                    continue
                timestamp = datetime.utcfromtimestamp(int(entry["__REALTIME_TIMESTAMP"]) / 1000000)
                identity = entry.get("__CURSOR") or entry["__REALTIME_TIMESTAMP"] + message
                priority = int(entry.get("PRIORITY", 4))
                events.append({"_history": True, "event_id": identity, "occurred_at": timestamp,
                    "severity": "critical" if priority <= 3 else "warning", "message": message,
                    "details": "System journal event" + (" · " + entry["_SYSTEMD_UNIT"] if isinstance(entry.get("_SYSTEMD_UNIT"), str) else "")})
            except (ValueError, KeyError, TypeError):
                continue
        return events
    except Exception:
        return []


def fetch_ssh_alarms(server_config):
    """
    Fetch alarms from SSH server using paramiko.
    Returns list of alarm dictionaries.
    """
    try:
        import paramiko
    except ImportError:
        print("paramiko not installed. Install with: pip install paramiko")
        return None

    server_name = server_config.get('server_name', 'Unknown')
    print(f"[DEBUG] Starting SSH alarm fetch for {server_name} ({server_config['ip_address']}:{server_config['port']})")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to server
        print(f"[DEBUG] Connecting to {server_name}...")
        ssh.connect(
            hostname=server_config['ip_address'],
            port=server_config['port'],
            username=server_config['username'],
            password=server_config['password'],
            timeout=15
        )
        print(f"[DEBUG] Successfully connected to {server_name}")

        alarms = []

        # Check system load
        print(f"[DEBUG] Checking system load for {server_name}...")
        stdin, stdout, stderr = ssh.exec_command("uptime")
        uptime_output = stdout.read().decode().strip()
        stderr_output = stderr.read().decode().strip()
        print(f"[DEBUG] Uptime output: {uptime_output}")
        if stderr_output:
            print(f"[DEBUG] Uptime stderr: {stderr_output}")

        if uptime_output:
            # Parse load average - try different formats
            load_match = re.search(r'load average[s]?:?\s*([\d.]+)', uptime_output)
            if load_match:
                load_avg = float(load_match.group(1))
                print(f"[DEBUG] Load average: {load_avg}")
                if load_avg > 1.0:  # Lowered threshold for testing
                    alarms.append({
                        'severity': 'critical' if load_avg > 4.0 else 'warning',
                        'message': f'System load: {load_avg}',
                        'details': uptime_output
                    })
                    print(f"[DEBUG] Added load alarm: {load_avg}")

        # Check disk usage with more comprehensive command
        print(f"[DEBUG] Checking disk usage for {server_name}...")
        stdin, stdout, stderr = ssh.exec_command("df -h")
        disk_output = stdout.read().decode().strip()
        stderr_output = stderr.read().decode().strip()
        print(f"[DEBUG] Disk output: {disk_output}")
        if stderr_output:
            print(f"[DEBUG] Disk stderr: {stderr_output}")

        if disk_output:
            for line in disk_output.split('\n')[1:]:  # Skip header
                if line.strip() and not line.startswith('tmpfs') and not line.startswith('udev'):
                    parts = line.split()
                    if len(parts) >= 5:
                        usage_str = parts[4].replace('%', '')
                        filesystem = parts[0]
                        mount_point = parts[5] if len(parts) > 5 else parts[0]
                        try:
                            usage = int(usage_str)
                            print(f"[DEBUG] Disk usage {mount_point}: {usage}%")
                            if usage > 50:  # Lowered threshold for testing
                                alarms.append({
                                    'severity': 'critical' if usage > 95 else 'warning',
                                    'message': f'Disk usage {mount_point}: {usage}%',
                                    'details': f'Filesystem {filesystem} on {mount_point} is {usage}% full'
                                })
                                print(f"[DEBUG] Added disk alarm: {mount_point} {usage}%")
                        except (ValueError, IndexError):
                            continue

        # Check memory usage
        print(f"[DEBUG] Checking memory usage for {server_name}...")
        stdin, stdout, stderr = ssh.exec_command("free")
        mem_output = stdout.read().decode().strip()
        stderr_output = stderr.read().decode().strip()
        print(f"[DEBUG] Memory output: {mem_output}")
        if stderr_output:
            print(f"[DEBUG] Memory stderr: {stderr_output}")

        if mem_output:
            lines = mem_output.split('\n')
            for line in lines:
                if 'Mem:' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            total = int(parts[1])
                            used = int(parts[2])
                            mem_usage = (used / total) * 100
                            print(f"[DEBUG] Memory usage: {mem_usage:.1f}%")
                            if mem_usage > 50:  # Lowered threshold for testing
                                alarms.append({
                                    'severity': 'critical' if mem_usage > 95 else 'warning',
                                    'message': f'Memory usage: {mem_usage:.1f}%',
                                    'details': f'Memory usage is at {mem_usage:.1f}% ({used}/{total})'
                                })
                                print(f"[DEBUG] Added memory alarm: {mem_usage:.1f}%")
                        except (ValueError, IndexError):
                            pass
                    break

        # Check failed login attempts (try multiple log locations)
        print(f"[DEBUG] Checking failed login attempts for {server_name}...")
        for log_path in ['/var/log/auth.log', '/var/log/secure', '/var/log/messages']:
            stdin, stdout, stderr = ssh.exec_command(f"grep -i 'failed password\\|authentication failure' {log_path} 2>/dev/null | tail -5 | wc -l")
            failed_logins = stdout.read().decode().strip()
            if failed_logins and failed_logins.isdigit() and int(failed_logins) > 0:
                failed_count = int(failed_logins)
                print(f"[DEBUG] Found {failed_count} failed login attempts in {log_path}")
                if failed_count > 2:  # Lowered threshold for testing
                    alarms.append({
                        'severity': 'warning',
                        'message': f'Failed login attempts: {failed_count}',
                        'details': f'{failed_count} failed login attempts detected in {log_path}'
                    })
                    print(f"[DEBUG] Added failed login alarm: {failed_count}")
                break

        # Check running processes
        print(f"[DEBUG] Checking process count for {server_name}...")
        stdin, stdout, stderr = ssh.exec_command("ps aux | wc -l")
        process_count = stdout.read().decode().strip()
        stderr_output = stderr.read().decode().strip()
        print(f"[DEBUG] Process count: {process_count}")
        if stderr_output:
            print(f"[DEBUG] Process stderr: {stderr_output}")

        if process_count and process_count.isdigit():
            proc_count = int(process_count)
            print(f"[DEBUG] Running processes: {proc_count}")
            if proc_count > 50:  # Lowered threshold for testing
                alarms.append({
                    'severity': 'info' if proc_count < 500 else 'warning',
                    'message': f'Process count: {proc_count}',
                    'details': f'System is running {proc_count} processes'
                })
                print(f"[DEBUG] Added process count alarm: {proc_count}")

        # Add a test alarm to verify the system is working
        alarms.append({
            'severity': 'info',
            'message': f'SSH monitoring active for {server_name}',
            'details': f'Successfully connected and monitored {server_name} at {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC'
        })
        print(f"[DEBUG] Added test alarm for {server_name}")

        alarms.extend(read_ssh_journal_history(ssh))
        ssh.close()
        print(f"[DEBUG] Found {len(alarms)} total alarms for {server_name}")
        return alarms

    except Exception as e:
        print(f"[ERROR] SSH connection failed for {server_name}: {str(e)}")
        print(f"[ERROR] Connection details: {server_config['ip_address']}:{server_config['port']} user:{server_config['username']}")
        return None


# ---------------- Flask + UI ----------------
app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = FLASK_SECRET



# Dashboard template lives in templates/dashboard.html.

# ---------------- Flask API (viewer-facing) ----------------
@app.get("/api/status")
def api_status_list():
    if not request_feature_enabled("monitors"):
        return jsonify([])
    req_tag = get_request_tag()
    with SessionLocal() as s:
        q = s.query(Status)
        if req_tag:
            q = q.filter(
                exists().where((StatusTag.status_id == Status.id) & (StatusTag.tag == req_tag))
            )
        else:
            # No access key provided: return empty set (overlay requires a key anyway)
            q = q.filter(False)
        rows = q.order_by(Status.created_at.desc()).all()
        # Sort by graph_type: indicator first, then bar, then line
        graph_type_order = {'indicator': 0, 'bar': 1, 'line': 2}
        rows = sorted(rows, key=lambda r: graph_type_order.get(r.graph_type, 3))
        return jsonify([{
            "id": r.id,
            "display_id": r.public_id,
            "kind": r.kind,
            "target": r.target,
            "server_name": r.server_name,
            "graph_type": r.graph_type,
            "graph_color": r.graph_color,
            "metric": metric_config_dict(s, r.id),
            "dashboard_tag": r.dashboard_tag,
            "created_at": r.created_at.isoformat()
        } for r in rows])


@app.get("/api/status/<int:sid>/data")
def api_status_data(sid):
    if not request_feature_enabled("monitors"):
        return jsonify({"error": "Monitor access denied"}), 403
    N = int(request.args.get("n", 500))
    req_tag = get_request_tag()
    with SessionLocal() as s:
        # Enforce access: status must belong to the requested tag
        if not req_tag:
            return jsonify({"error": "Access key required"}), 403
        allowed = s.query(exists().where((StatusTag.status_id == sid) & (StatusTag.tag == req_tag))).scalar()
        if not allowed:
            return jsonify({"error": "Forbidden"}), 403
        query = s.query(StatusData).filter(StatusData.status_id == sid)
        if request.args.get("successful") == "1":
            query = query.filter(StatusData.success == True, StatusData.latency_ms.isnot(None))
        q = query.order_by(StatusData.ts.desc(), StatusData.id.desc()).limit(N).all()
        q = list(reversed(q))
        out = [{"ts": d.ts.isoformat(), "latency_ms": d.latency_ms, "value": d.latency_ms, "success": bool(d.success)} for d in q]
        return jsonify(out)


@app.get("/api/status/<int:sid>/output")
def api_metric_output(sid):
    if not request_feature_enabled("monitors"):
        return jsonify({"error": "Monitor access denied"}), 403
    tag = get_request_tag()
    with SessionLocal() as db:
        allowed = db.query(StatusTag).filter_by(status_id=sid, tag=tag).first() if tag else None
        if not allowed:
            return jsonify({"error": "Monitor access denied"}), 403
        reading = db.get(MetricTextReading, sid)
        return jsonify({"output": reading.output, "ts": reading.updated_at.isoformat()} if reading else None)


@app.get("/api/dev_messages")
def api_dev_messages():
    if not request_feature_enabled("messages"):
        return jsonify([])
    req_tag = get_request_tag()
    with SessionLocal() as s:
        q = s.query(DevMessage)
        if req_tag:
            q = q.filter(
                exists().where((DevMessageTag.dev_message_id == DevMessage.id) & (DevMessageTag.tag == req_tag))
            )
        else:
            q = q.filter(False)
        rows = q.order_by(DevMessage.created_at.desc()).all()
        return jsonify([
            {
                "id": r.id,
            "display_id": r.public_id,
                "title": r.title,
                "message": r.message,
                "dashboard_tag": r.dashboard_tag,
                "created_at": r.created_at.isoformat()
            } for r in rows
        ])


@app.get("/api/incidents")
def api_incidents():
    if not request_feature_enabled("incidents"):
        return jsonify([])
    req_tag = get_request_tag()
    with SessionLocal() as s:
        q = s.query(Incident)
        if req_tag:
            q = q.filter(
                exists().where((IncidentTag.incident_id == Incident.id) & (IncidentTag.tag == req_tag))
            )
        else:
            q = q.filter(False)
        rows = q.order_by(Incident.created_at.desc()).all()
        return jsonify([
            {
                "id": r.id,
            "display_id": r.public_id,
                "title": r.title,
                "tag": r.tag,
                "message": r.message,
                "dashboard_tag": r.dashboard_tag,
                "created_at": r.created_at.isoformat()
            } for r in rows
        ])


@app.get("/api/reports")
def api_reports():
    n = int(request.args.get("n", 50))
    tag = request.args.get("tag") or None
    with SessionLocal() as s:
        q = s.query(IssueReport)
        if tag:
            # Join through tag tables for any content type that supports tags and is tagged with this tag,
            # but for IssueReport we currently don't tag them; so filter is no-op.
            pass
        rows = q.order_by(IssueReport.created_at.desc()).limit(n).all()
        return jsonify([{"id": r.id, "username": r.username, "license_number": r.license_number, "issue": r.issue, "created_at": r.created_at.isoformat()} for r in rows])


@app.get("/api/ssh_alarms")
def api_ssh_alarms():
    if not request_feature_enabled("alarms"):
        return jsonify([])
    alarm_type = request.args.get("type", "active")  # 'active' or 'history'
    try:
        n = max(1, min(200, int(request.args.get("n", 50))))
        offset = max(0, int(request.args.get("offset", 0)))
    except ValueError:
        return jsonify({"error": "Invalid pagination"}), 400
    req_tag = get_request_tag()
    with SessionLocal() as s:
        q = s.query(SSHAlarm)
        if alarm_type == "active":
            q = q.filter(SSHAlarm.is_active == True)
        elif alarm_type in ("history", "resolved"):
            q = q.filter(SSHAlarm.is_active == False, SSHAlarm.alarm_type == alarm_type)
        else:
            return jsonify({"error": "Invalid alarm type"}), 400
        if req_tag:
            q = q.filter(
                exists().where((SSHAlarmTag.alarm_id == SSHAlarm.id) & (SSHAlarmTag.tag == req_tag))
            )
        else:
            q = q.filter(False)
        rows = q.order_by(SSHAlarm.created_at.desc(), SSHAlarm.id.desc()).offset(offset).limit(n).all()
        return jsonify([{
            "id": r.id,
            "display_id": r.public_id,
            "server_name": r.server_name,
            "alarm_type": r.alarm_type,
            "source": "automatic" if s.get(AutoAlarmState, r.id) else "manual",
            "severity": r.severity,
            "message": r.message,
            "details": r.details,
            "dashboard_tag": r.dashboard_tag,
            "created_at": r.created_at.isoformat(),
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
            "is_active": r.is_active
        } for r in rows])


@app.get("/api/ssh_servers")
def api_ssh_servers():
    with SessionLocal() as s:
        rows = s.query(SSHServer).filter(SSHServer.is_active == True).order_by(SSHServer.server_name).all()
        return jsonify([{
            "id": r.id,
            "server_name": r.server_name,
            "ip_address": r.ip_address,
            "username": r.username,
            "port": r.port,
            "fetch_interval": r.fetch_interval,
            "last_fetch": r.last_fetch.isoformat() if r.last_fetch else None,
            "is_active": r.is_active,
            "auto_fetch_enabled": r.auto_fetch_enabled,
            "created_at": r.created_at.isoformat()
        } for r in rows])


@app.post("/api/report")
def api_report():
    """
    Public report endpoint active on the dashboard only. Admins view reports at /update.
    """
    payload = request.get_json(force=True, silent=True) or {}
    username = (payload.get("username") or "").strip()
    license_number = (payload.get("license_number") or "").strip()
    issue = (payload.get("issue") or "").strip()
    if not username or len(username) < 2:
        return jsonify({"ok": False, "error": "invalid username"}), 400
    if not license_number:
        return jsonify({"ok": False, "error": "invalid license"}), 400
    if license_number != ALLOWED_LICENSE:
        return jsonify({"ok": False, "error": f"you are not allowed to report please contact {ALLOWED_ERROR_CONTACT}"}), 403
    if not issue or len(issue) < 4:
        return jsonify({"ok": False, "error": "issue too short"}), 400
    today = date.today()
    with SessionLocal() as s:
        r = IssueReport(username=username, license_number=license_number, issue=issue, created_day=today)
        s.add(r); s.commit(); s.refresh(r)
        rid = r.id
    return jsonify({"ok": True, "id": rid, "message": "Issue has been reported we will resolve it and will contact you if needed Thanks."})


# ---------------- Admin / Update Page (web-based management) ----------------
# Simple login flow using session. No user management — single key.

# Random key generator: 17 chars with upper/lower/numbers/specials
ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}"

def generate_dashboard_key(length: int = 17) -> str:
    return ''.join(secrets.choice(ALPHABET) for _ in range(length))

# Admin template lives in templates/update.html.

from functools import wraps


def require_auth(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("update"))
        return f(*args, **kwargs)
    return _wrap


@app.route("/update", methods=["GET"])
def update():
    return render_template("update.html", authenticated=bool(session.get("authenticated")))

@app.post("/update/api/del_report/<int:rid>")
@require_auth
def update_api_del_report(rid):
    with SessionLocal() as s:
        r = s.get(IssueReport, rid)
        if r:
            s.delete(r)
            s.commit()
    return jsonify({"ok": True})

@app.post("/update/api/sampler_interval")
@require_auth
def set_sampler_interval():
    """Set sampler interval globally or per tag if `tag` provided."""
    global SAMPLE_SECS_RUNTIME
    data = request.get_json(silent=True) or {}
    tag = (data.get("tag") or "").strip() or None
    try:
        sec = int(data.get("seconds", 0))
    except Exception:
        return jsonify({"error": "invalid"}), 400
    # clamp between 1 and 2,592,000 (30 days) for safety
    if sec < 1 or sec > 2592000:
        return jsonify({"error": "out_of_range"}), 400
    if tag:
        with SessionLocal() as s:
            ti = s.query(TagInterval).filter(TagInterval.tag == tag).first()
            if not ti:
                ti = TagInterval(tag=tag, seconds=sec)
                s.add(ti)
            else:
                ti.seconds = sec
            s.commit()
        return jsonify({"ok": True, "seconds": sec, "tag": tag})
    else:
        with SessionLocal() as db:
            setting = db.get(AppSetting, "sample_seconds")
            if setting is None:
                db.add(AppSetting(name="sample_seconds", value=sec))
            else:
                setting.value = sec
            db.commit()
        SAMPLE_SECS_RUNTIME = sec
        return jsonify({"ok": True, "seconds": SAMPLE_SECS_RUNTIME})

@app.route("/update/login", methods=["POST"])
def update_login():
    key = (request.form.get("key") or "").strip()
    if key == UPDATE_KEY:
        session["authenticated"] = True
        # Grant admin-wide access for this session
        session["dashboardAccess"] = True
        session.pop("dashboard_key", None)
        return redirect(url_for("update"))
    return render_template("update.html", authenticated=False), 403


@app.route("/update/logout")
def update_logout():
    session.pop("authenticated", None)
    session.pop("dashboardAccess", None)
    return redirect(url_for("update"))


# Admin JSON endpoints (protected)
@app.post("/update/api/add_status")
@require_auth
def add_status_api():
    payload = request.get_json(force=True, silent=True) or {}
    kind = (payload.get("kind") or "").strip()
    target = (payload.get("target") or "").strip()
    server_name = (payload.get("server_name") or "").strip() or None
    graph_type = (payload.get("graph_type") or "line").strip()
    graph_color = (payload.get("graph_color") or "#0a84ff").strip()

    if kind not in ("ping", "html", "tcp") or not target:
        return jsonify({"error": "invalid"}), 400
    if graph_type not in ("line", "bar", "indicator"):
        graph_type = "line"

    selected_tags = payload.get("dashboard_tags") or []
    if not isinstance(selected_tags, list):
        selected_tags = [selected_tags] if selected_tags else []
    # Set a primary dashboard_tag for backward compatibility: prefer first tag or default
    primary_tag = (selected_tags[0] if selected_tags else DEFAULT_DASHBOARD_TAG)

    with SessionLocal() as s:
        st = Status(
            kind=kind,
            target=target,
            server_name=server_name,
            graph_type=graph_type,
            graph_color=graph_color,
            dashboard_tag=primary_tag
        )
        s.add(st); s.commit(); s.refresh(st)
        # ensure many-to-many tags include default + selected
        ensure_status_tags(s, st.id, selected_tags)
        s.commit()
        return jsonify({"ok": True, "id": st.id})


@app.route("/update/api/metric_monitors", methods=["POST"])
@app.route("/update/api/metric_monitors/<int:sid>", methods=["PUT"])
@require_auth
def save_metric_monitor(sid=None):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid monitor settings"}), 400
    try:
        kind = data.get("kind", "ssh")
        display = data.get("display", "progress")
        name = str(data.get("name", "")).strip()
        low, high = float(data.get("min_value", 0)), float(data.get("max_value", 100))
        interval = int(data.get("interval_secs", 10))
        color, needle = data.get("color", "#0a84ff"), data.get("needle_color", "#18243a")
        unit = str(data.get("unit", "%"))
        show_value = data.get("show_value", True)
        decimals = data.get("decimals", 1)
        if type(show_value) is not bool or type(decimals) is not int or not 0 <= decimals <= 6:
            raise ValueError("Choose value visibility and decimals between 0 and 6")
        tags = data.get("dashboard_tags") or [DEFAULT_DASHBOARD_TAG]
        if kind not in ("ssh", "ping", "tcp", "html") or display not in ("dial", "progress", "none") or not name or len(name) > 256:
            raise ValueError("Choose a name, source, and display")
        if not math.isfinite(low) or not math.isfinite(high) or low >= high or not 1 <= interval <= 86400 or len(unit) > 30:
            raise ValueError("Use finite min < max and an interval between 1 and 86400 seconds")
        if not all(isinstance(c, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", c) for c in (color, needle)):
            raise ValueError("Use valid colors")
        if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
            raise ValueError("Select access tags")
        if display == "none" and kind != "ssh":
            raise ValueError("Output-only display requires an SSH command")
        command = str(data.get("command") or "").strip()
        target = str(data.get("target") or "").strip()
        server_id = int(data.get("ssh_server_id")) if kind == "ssh" else None
        if kind == "ssh" and (not command or len(command) > 8000):
            raise ValueError("Enter an SSH command returning one numeric value")
        if kind != "ssh" and (not target or len(target) > 512):
            raise ValueError("Enter a target")
    except (ValueError, TypeError) as error:
        return jsonify({"error": str(error)}), 400
    with SessionLocal() as db:
        server = db.get(SSHServer, server_id) if server_id else None
        if kind == "ssh" and (server is None or not server.is_active):
            return jsonify({"error": "Select an active SSH server"}), 400
        known = {key.tag for key in db.query(DashboardKey).filter(DashboardKey.tag.in_(tags)).all()}
        if set(tags) != known:
            return jsonify({"error": "Unknown access tag"}), 400
        status = db.get(Status, sid) if sid else Status()
        if sid and (status is None or db.get(MetricConfig, sid) is None):
            return jsonify({"error": "Metric monitor not found"}), 404
        status.kind, status.target, status.server_name = kind, server.server_name if server else target, name
        status.graph_type, status.graph_color, status.dashboard_tag = display, color, tags[0]
        db.add(status); db.flush()
        config = db.get(MetricConfig, status.id) or MetricConfig(status_id=status.id)
        config.ssh_server_id, config.command = server_id, command if kind == "ssh" else None
        config.min_value, config.max_value, config.unit = low, high, unit
        config.interval_secs, config.needle_color = interval, needle
        config.show_value, config.decimals = show_value, decimals
        db.add(config)
        db.query(StatusTag).filter_by(status_id=status.id).delete(synchronize_session=False)
        ensure_status_tags(db, status.id, tags)
        db.commit()
        METRIC_LAST_RUN.pop(status.id, None)
        return jsonify({"ok": True, "id": status.id})


@app.post("/update/api/del_status/<int:sid>")
@require_auth
def del_status_api(sid):
    with SessionLocal() as s:
        got = s.get(Status, sid)
        if not got: return jsonify({"ok": False}), 404
        s.query(MetricTextReading).filter_by(status_id=sid).delete(synchronize_session=False)
        s.query(MetricConfig).filter_by(status_id=sid).delete(synchronize_session=False)
        s.delete(got); s.commit(); return jsonify({"ok": True})


@app.post("/update/api/status/<int:sid>/set_tag")
@require_auth
def set_status_tag_api(sid):
    payload = request.get_json(force=True, silent=True) or {}
    tags = payload.get("tags")
    if tags is None:
        tags = [(payload.get("dashboard_tag") or DEFAULT_DASHBOARD_TAG).strip()]
    if not isinstance(tags, list) or not tags or any(not isinstance(t, str) or not t.strip() for t in tags):
        return jsonify({"error": "Select at least one access key"}), 400
    tags = list(dict.fromkeys(t.strip() for t in tags))
    with SessionLocal() as db:
        st = db.get(Status, sid)
        if st is None:
            return jsonify({"error": "Monitor not found"}), 404
        known = {k.tag for k in db.query(DashboardKey).filter(DashboardKey.tag.in_(tags)).all()}
        if set(tags) != known:
            return jsonify({"error": "Unknown access key tag"}), 400
        st.dashboard_tag = tags[0]
        db.query(StatusTag).filter_by(status_id=sid).delete(synchronize_session=False)
        ensure_status_tags(db, sid, tags)
        db.commit()
    return jsonify({"ok": True, "tags": tags})


@app.post("/update/api/add_dev")
@require_auth
def add_dev_api():
    payload = request.get_json(force=True, silent=True) or {}
    title = (payload.get("title") or "").strip()
    msg = (payload.get("message") or "").strip()
    if not msg or not title:
        return jsonify({"error": "invalid"}), 400
    selected_tags = payload.get("dashboard_tags") or []
    if not isinstance(selected_tags, list):
        selected_tags = [selected_tags] if selected_tags else []
    primary_tag = (selected_tags[0] if selected_tags else DEFAULT_DASHBOARD_TAG)
    with SessionLocal() as s:
        m = DevMessage(title=title, message=msg, dashboard_tag=primary_tag); s.add(m); s.commit(); s.refresh(m)
        ensure_dev_tags(s, m.id, selected_tags)
        s.commit()
        return jsonify({"ok": True, "id": m.id})


@app.post("/update/api/dev/<int:mid>/set_tag")
@require_auth
def set_dev_tag_api(mid):
    payload = request.get_json(force=True, silent=True) or {}
    new_tag = (payload.get("dashboard_tag") or "").strip() or None
    if not new_tag:
        new_tag = DEFAULT_DASHBOARD_TAG
    with SessionLocal() as s:
        m = s.get(DevMessage, mid)
        if not m:
            return jsonify({"ok": False, "error": "not found"}), 404
        # Update primary tag
        m.dashboard_tag = new_tag
        s.commit()
        # Replace existing tag links with only default + new tag
        s.query(DevMessageTag).filter(DevMessageTag.dev_message_id == m.id).delete(synchronize_session=False)
        ensure_dev_tags(s, m.id, new_tag)
        s.commit()
        return jsonify({"ok": True})

@app.post("/update/api/del_dev/<int:mid>")
@require_auth
def del_dev_api(mid):
    with SessionLocal() as s:
        m = s.get(DevMessage, mid)
        if not m: return jsonify({"ok": False}), 404
        s.delete(m); s.commit(); return jsonify({"ok": True})


@app.post("/update/api/add_incident")
@require_auth
def add_incident_api():
    payload = request.get_json(force=True, silent=True) or {}
    tag = (payload.get("tag") or "").strip().lower()
    title = (payload.get("title") or "").strip()
    msg = (payload.get("message") or "").strip()
    if tag not in VALID_TAGS or not msg or not title:
        return jsonify({"error": "invalid"}), 400
    selected_tags = payload.get("dashboard_tags") or []
    if not isinstance(selected_tags, list):
        selected_tags = [selected_tags] if selected_tags else []
    primary_tag = (selected_tags[0] if selected_tags else DEFAULT_DASHBOARD_TAG)
    with SessionLocal() as s:
        it = Incident(tag=tag, title=title, message=msg, dashboard_tag=primary_tag); s.add(it); s.commit(); s.refresh(it)
        ensure_incident_tags(s, it.id, selected_tags)
        s.commit()
        return jsonify({"ok": True, "id": it.id})


@app.post("/update/api/incidents/<int:iid>/set_tag")
@require_auth
def set_incident_tag_api(iid):
    payload = request.get_json(force=True, silent=True) or {}
    new_tag = (payload.get("dashboard_tag") or "").strip() or None
    if not new_tag:
        new_tag = DEFAULT_DASHBOARD_TAG
    with SessionLocal() as s:
        it = s.get(Incident, iid)
        if not it:
            return jsonify({"ok": False, "error": "not found"}), 404
        # Update primary tag
        it.dashboard_tag = new_tag
        s.commit()
        # Replace existing tag links with only default + new tag
        s.query(IncidentTag).filter(IncidentTag.incident_id == it.id).delete(synchronize_session=False)
        ensure_incident_tags(s, it.id, new_tag)
        s.commit()
        return jsonify({"ok": True})

@app.post("/update/api/del_inc/<int:iid>")
@require_auth
def del_inc_api(iid):
    with SessionLocal() as s:
        it = s.get(Incident, iid)
        if not it: return jsonify({"ok": False}), 404
        s.delete(it); s.commit(); return jsonify({"ok": True})


@app.post("/update/api/add_ssh_alarm")
@require_auth
def add_ssh_alarm_api():
    payload = request.get_json(force=True, silent=True) or {}
    server_name = (payload.get("server_name") or "").strip()
    severity = (payload.get("severity") or "").strip().lower()
    message = (payload.get("message") or "").strip()
    details = (payload.get("details") or "").strip() or None

    if not server_name or not message:
        return jsonify({"error": "server_name and message required"}), 400
    if severity not in ("critical", "warning", "info"):
        return jsonify({"error": "invalid severity"}), 400

    selected_tags = payload.get("dashboard_tags") or []
    if not isinstance(selected_tags, list):
        selected_tags = [selected_tags] if selected_tags else []
    primary_tag = (selected_tags[0] if selected_tags else DEFAULT_DASHBOARD_TAG)

    with SessionLocal() as s:
        alarm = SSHAlarm(
            server_name=server_name,
            alarm_type="active",
            severity=severity,
            message=message,
            details=details,
            dashboard_tag=primary_tag,
            is_active=True
        )
        s.add(alarm); s.commit(); s.refresh(alarm)
        ensure_alarm_tags(s, alarm.id, selected_tags)
        s.commit()
        return jsonify({"ok": True, "id": alarm.id})


@app.post("/update/api/del_ssh_alarm/<int:aid>")
@require_auth
def del_ssh_alarm_api(aid):
    with SessionLocal() as s:
        alarm = s.get(SSHAlarm, aid)
        if not alarm: return jsonify({"ok": False}), 404
        s.query(AutoAlarmState).filter_by(alarm_id=aid).delete(synchronize_session=False)
        s.query(SSHAlarmTag).filter_by(alarm_id=aid).delete(synchronize_session=False)
        s.delete(alarm); s.commit(); return jsonify({"ok": True})


@app.post("/update/api/resolve_ssh_alarm/<int:aid>")
@require_auth
def resolve_ssh_alarm_api(aid):
    with SessionLocal() as s:
        alarm = s.get(SSHAlarm, aid)
        if not alarm: return jsonify({"ok": False}), 404
        alarm.is_active = False
        alarm.alarm_type = "resolved"
        alarm.resolved_at = datetime.utcnow()
        s.commit()
        return jsonify({"ok": True})


@app.post("/update/api/ssh_alarms/bulk")
@require_auth
def bulk_ssh_alarms():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Expected an action and alarm IDs"}), 400
    action, ids = payload.get("action"), payload.get("ids")
    if action not in ("resolve", "delete", "history") or not isinstance(ids, list) or not ids or any(type(i) is not int or i < 1 for i in ids):
        return jsonify({"error": "Select alarms and a valid action"}), 400
    ids = list(dict.fromkeys(ids))
    with SessionLocal() as db:
        alarms = db.query(SSHAlarm).filter(SSHAlarm.id.in_(ids)).all()
        if len(alarms) != len(ids):
            return jsonify({"error": "Some selected alarms no longer exist. Refresh and try again."}), 409
        if action == "history" and any(not a.is_active or db.get(AutoAlarmState, a.id) is not None for a in alarms):
            return jsonify({"error": "Only active manual alarms can be moved to history"}), 400
        updated = 0
        resolved_at = datetime.utcnow()
        for alarm in alarms:
            if action == "delete":
                db.query(AutoAlarmState).filter_by(alarm_id=alarm.id).delete(synchronize_session=False)
                db.query(SSHAlarmTag).filter_by(alarm_id=alarm.id).delete(synchronize_session=False)
                db.delete(alarm)
                updated += 1
            elif alarm.is_active or (action == "resolve" and alarm.alarm_type == "history"):
                alarm.is_active = False
                alarm.alarm_type = "resolved" if action == "resolve" else "history"
                alarm.resolved_at = resolved_at
                updated += 1
        db.commit()
    return jsonify({"ok": True, "updated": updated})


@app.post("/update/api/add_ssh_server")
@require_auth
def add_ssh_server_api():
    payload = request.get_json(force=True, silent=True) or {}
    server_name = (payload.get("server_name") or "").strip()
    ip_address = (payload.get("ip_address") or "").strip()
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    port = payload.get("port", 22)
    fetch_interval = payload.get("fetch_interval", 300)
    auto_fetch_enabled = payload.get("auto_fetch_enabled", False)

    if not all([server_name, ip_address, username, password]):
        return jsonify({"error": "server_name, ip_address, username, and password required"}), 400

    with SessionLocal() as s:
        # Check if server name already exists
        existing = s.query(SSHServer).filter(SSHServer.server_name == server_name).first()
        if existing:
            return jsonify({"error": "Server name already exists"}), 400

        server = SSHServer(
            server_name=server_name,
            ip_address=ip_address,
            username=username,
            password=password,  # In production, this should be encrypted
            port=port,
            fetch_interval=fetch_interval,
            auto_fetch_enabled=auto_fetch_enabled,
            is_active=True
        )
        s.add(server); s.commit(); s.refresh(server)
        return jsonify({"ok": True, "id": server.id})


@app.post("/update/api/del_ssh_server/<int:sid>")
@require_auth
def del_ssh_server_api(sid):
    with SessionLocal() as s:
        server = s.get(SSHServer, sid)
        if not server: return jsonify({"ok": False}), 404
        s.delete(server); s.commit(); return jsonify({"ok": True})


@app.post("/update/api/toggle_auto_fetch/<int:sid>")
@require_auth
def toggle_auto_fetch_api(sid):
    payload = request.get_json(force=True, silent=True) or {}
    auto_fetch_enabled = payload.get("auto_fetch_enabled", False)

    with SessionLocal() as s:
        server = s.get(SSHServer, sid)
        if not server: return jsonify({"ok": False}), 404

        server.auto_fetch_enabled = auto_fetch_enabled
        s.commit()
        return jsonify({"ok": True, "auto_fetch_enabled": server.auto_fetch_enabled})

# ---------------- Dashboard Tag API ----------------
@app.get("/update/api/dashboard_keys")
@require_auth
def list_dashboard_keys():
    with SessionLocal() as s:
        now = datetime.utcnow()
        # Cleanup expired but active keys (mark inactive)
        keys = s.query(DashboardKey).all()
        for k in keys:
            if k.is_active and k.expires_at and k.expires_at <= now:
                k.is_active = False
        s.commit()
        keys = s.query(DashboardKey).order_by(DashboardKey.created_at.desc()).all()
        return jsonify([{
            "id": k.id,
            "tag": k.tag,
            "key_value": k.key_value,
            "is_active": k.is_active,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "created_at": k.created_at.isoformat(),
            "features": key_features(s, k.id)
        } for k in keys])

@app.post("/update/api/dashboard_keys")
@require_auth
def create_dashboard_key():
    data = request.get_json() or {}
    tag = (data.get("tag") or "").strip()
    expiry_seconds = data.get("expiry_seconds")
    if not tag:
        return jsonify({"error": "Tag is required"}), 400
    # prevent duplicate tag names (case-insensitive)
    with SessionLocal() as s:
        existing_tag = s.query(DashboardKey).filter(DashboardKey.tag.ilike(tag)).first()
        if existing_tag:
            return jsonify({"error": "Tag with this name already exists"}), 400
    # generate unique key
    for _ in range(10):
        key_value = generate_dashboard_key()
        with SessionLocal() as s:
            if not s.query(DashboardKey).filter(DashboardKey.key_value == key_value).first():
                break
    else:
        return jsonify({"error": "Failed to generate unique key"}), 500
    expires_at = None
    if isinstance(expiry_seconds, int) and expiry_seconds > 0:
        expires_at = datetime.utcnow() + timedelta(seconds=expiry_seconds)
    with SessionLocal() as s:
        k = DashboardKey(tag=tag, key_value=key_value, expires_at=expires_at, is_active=True)
        s.add(k); s.commit(); s.refresh(k)
        return jsonify({
            "id": k.id, "tag": k.tag, "key_value": k.key_value,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "created_at": k.created_at.isoformat(),
            "is_active": k.is_active
        })

@app.post("/update/api/dashboard_keys/<int:key_id>/features")
@require_auth
def update_key_features(key_id):
    payload = request.get_json(silent=True) or {}
    features = payload.get("features")
    if not isinstance(features, dict) or set(features) - set(FEATURE_NAMES) or any(type(v) is not bool for v in features.values()):
        return jsonify({"error": "Features must contain boolean feature settings"}), 400
    with SessionLocal() as db:
        if db.get(DashboardKey, key_id) is None:
            return jsonify({"error": "Access key not found"}), 404
        merged = key_features(db, key_id)
        merged.update(features)
        row = db.get(KeyFeatures, key_id)
        if row is None:
            row = KeyFeatures(key_id=key_id)
            db.add(row)
        row.features_json = json.dumps(merged)
        db.commit()
        return jsonify({"ok": True, "features": merged})


@app.get("/api/dashboard_config")
def dashboard_config():
    tag = get_request_tag()
    if not tag:
        return jsonify({"error": "Invalid or expired access key"}), 403
    with SessionLocal() as db:
        key = db.query(DashboardKey).filter_by(key_value=request.headers.get("X-Dashboard-Key")).one()
        override = db.query(TagInterval).filter_by(tag=tag).first()
        seconds = override.seconds if override else global_sample_seconds(db)
        features = key_features(db, key.id)
        monitor_count = db.query(Status).filter(
            exists().where((StatusTag.status_id == Status.id) & (StatusTag.tag == tag))
        ).count() if features["monitors"] else 0
        incident_count = db.query(Incident).filter(
            exists().where((IncidentTag.incident_id == Incident.id) & (IncidentTag.tag == tag))
        ).count() if features["incidents"] else 0
        message_count = db.query(DevMessage).filter(
            exists().where((DevMessageTag.dev_message_id == DevMessage.id) & (DevMessageTag.tag == tag))
        ).count() if features["messages"] else 0
        alarm_count = db.query(SSHAlarm).filter(
            SSHAlarm.is_active == True,
            exists().where((SSHAlarmTag.alarm_id == SSHAlarm.id) & (SSHAlarmTag.tag == tag))
        ).count() if features["alarms"] else 0
        alarm_counts = {"active": alarm_count, "history": 0, "resolved": 0}
        if features["alarms"]:
            for state in ("history", "resolved"):
                alarm_counts[state] = db.query(SSHAlarm).filter(SSHAlarm.is_active == False, SSHAlarm.alarm_type == state,
                    exists().where((SSHAlarmTag.alarm_id == SSHAlarm.id) & (SSHAlarmTag.tag == tag))).count()
        return jsonify({"tag": tag, "features": features, "sample_secs": seconds, "alarm_counts": alarm_counts,
                        "counts": {"monitors": monitor_count, "incidents": incident_count,
                                   "messages": message_count, "alarms": alarm_count}})


@app.post("/update/api/dashboard_keys/<int:key_id>/disable")
@require_auth
def disable_dashboard_key(key_id):
    with SessionLocal() as s:
        k = s.get(DashboardKey, key_id)
        if not k:
            return jsonify({"error": "Not found"}), 404
        if k.tag == DEFAULT_DASHBOARD_TAG:
            return jsonify({"error": "Default key cannot be disabled"}), 400
        k.is_active = False
        s.commit()
        return jsonify({"ok": True})

@app.post("/update/api/dashboard_keys/<int:key_id>/enable")
@require_auth
def enable_dashboard_key(key_id):
    with SessionLocal() as s:
        k = s.get(DashboardKey, key_id)
        if not k:
            return jsonify({"error": "Not found"}), 404
        k.is_active = True
        s.commit()
        return jsonify({"ok": True})

@app.post("/update/api/dashboard_keys/<int:key_id>/refresh")
@require_auth
def refresh_dashboard_key(key_id):
    """
    Refresh the NASCM-Default key by generating a new unique key value.
    Keeps the tag the same, sets active, and clears expiry.
    """
    with SessionLocal() as s:
        k = s.get(DashboardKey, key_id)
        if not k:
            return jsonify({"error": "Not found"}), 404
        if k.tag != DEFAULT_DASHBOARD_TAG:
            return jsonify({"error": "Only default tag can be refreshed"}), 400
        # Generate a unique new key
        for _ in range(10):
            new_value = generate_dashboard_key()
            exists_key = s.query(DashboardKey).filter(DashboardKey.key_value == new_value).first()
            if not exists_key:
                break
        else:
            return jsonify({"error": "Failed to generate unique key"}), 500
        k.key_value = new_value
        k.is_active = True
        k.expires_at = None
        s.commit()
        return jsonify({"ok": True, "key_value": k.key_value})

@app.get("/update/api/dashboard_keys_enabled")
@require_auth
def list_enabled_dashboard_keys():
    with SessionLocal() as s:
        now = datetime.utcnow()
        rows = s.query(DashboardKey).filter(
            DashboardKey.is_active == True
        ).order_by(DashboardKey.tag.asc()).all()
        # filter out expired
        enabled = [r for r in rows if (r.expires_at is None or r.expires_at > now)]
        return jsonify([{ "id": r.id, "tag": r.tag, "key_value": r.key_value } for r in enabled])

@app.get("/update/api/sampler_intervals")
@require_auth
def list_sampler_intervals():
    """Return the global interval and per-tag overrides"""
    out = []
    # global default
    with SessionLocal() as s:
        out.append({"tag": None, "seconds": global_sample_seconds(s)})
        for ti in s.query(TagInterval).order_by(TagInterval.tag.asc()).all():
            out.append({"tag": ti.tag, "seconds": ti.seconds})
    return jsonify(out)

# Admin-only: fetch all items regardless of tag (for update page)
@app.get("/update/api/status_all")
@require_auth
def update_status_all():
    with SessionLocal() as s:
        rows = s.query(Status).order_by(Status.created_at.desc()).all()
        out = []
        for r in rows:
            tags = [t.tag for t in s.query(StatusTag).filter(StatusTag.status_id == r.id).all()]
            out.append({
                "id": r.id,
            "display_id": r.public_id,
                "kind": r.kind,
                "target": r.target,
                "server_name": r.server_name,
                "graph_type": r.graph_type,
                "graph_color": r.graph_color,
                "metric": metric_config_dict(s, r.id, admin=True),
                "dashboard_tag": r.dashboard_tag,
                "tags": sorted(tags),
                "created_at": r.created_at.isoformat()
            })
        return jsonify(out)

@app.get("/update/api/dev_messages_all")
@require_auth
def update_dev_messages_all():
    with SessionLocal() as s:
        rows = s.query(DevMessage).order_by(DevMessage.created_at.desc()).all()
        out = []
        for r in rows:
            tags = [t.tag for t in s.query(DevMessageTag).filter(DevMessageTag.dev_message_id == r.id).all()]
            out.append({
                "id": r.id,
            "display_id": r.public_id,
                "title": r.title,
                "message": r.message,
                "dashboard_tag": r.dashboard_tag,
                "tags": sorted(tags),
                "created_at": r.created_at.isoformat()
            })
        return jsonify(out)

@app.get("/update/api/incidents_all")
@require_auth
def update_incidents_all():
    with SessionLocal() as s:
        rows = s.query(Incident).order_by(Incident.created_at.desc()).all()
        out = []
        for r in rows:
            tags = [t.tag for t in s.query(IncidentTag).filter(IncidentTag.incident_id == r.id).all()]
            out.append({
                "id": r.id,
            "display_id": r.public_id,
                "title": r.title,
                "tag": r.tag,
                "message": r.message,
                "dashboard_tag": r.dashboard_tag,
                "tags": sorted(tags),
                "created_at": r.created_at.isoformat()
            })
        return jsonify(out)

@app.get("/update/api/ssh_alarms_all")
@require_auth
def update_ssh_alarms_all():
    alarm_type = request.args.get("type", "active")
    tag = request.args.get("tag") or None
    with SessionLocal() as s:
        q = s.query(SSHAlarm)
        if alarm_type == "active":
            q = q.filter(SSHAlarm.is_active == True)
        elif alarm_type in ("history", "resolved"):
            q = q.filter(SSHAlarm.is_active == False, SSHAlarm.alarm_type == alarm_type)
        else:
            return jsonify({"error": "Invalid alarm type"}), 400
        if tag:
            q = q.filter(
                exists().where((SSHAlarmTag.alarm_id == SSHAlarm.id) & (SSHAlarmTag.tag == tag))
            )
        rows = q.order_by(SSHAlarm.created_at.desc()).all()
        return jsonify([{
            "id": r.id,
            "display_id": r.public_id,
            "server_name": r.server_name,
            "alarm_type": r.alarm_type,
            "source": "automatic" if s.get(AutoAlarmState, r.id) else "manual",
            "severity": r.severity,
            "message": r.message,
            "details": r.details,
            "dashboard_tag": r.dashboard_tag,
            "created_at": r.created_at.isoformat(),
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
            "is_active": r.is_active
        } for r in rows])

@app.delete("/update/api/dashboard_keys/<int:key_id>")
@require_auth
def delete_dashboard_key(key_id):
    with SessionLocal() as s:
        k = s.get(DashboardKey, key_id)
        if not k:
            return jsonify({"error": "Not found"}), 404
        if k.tag == DEFAULT_DASHBOARD_TAG:
            return jsonify({"error": "Default key cannot be deleted"}), 400
        s.query(KeyFeatures).filter_by(key_id=key_id).delete(synchronize_session=False)
        s.delete(k)
        s.commit()
        return jsonify({"ok": True})


@app.post("/update/api/test_ssh_connection/<int:sid>")
@require_auth
def test_ssh_connection_api(sid):
    with SessionLocal() as s:
        server = s.get(SSHServer, sid)
        if not server: return jsonify({"success": False, "error": "Server not found"}), 404

        server_config = {
            'server_name': server.server_name,
            'ip_address': server.ip_address,
            'username': server.username,
            'password': server.password,
            'port': server.port
        }

        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=server_config['ip_address'],
                port=server_config['port'],
                username=server_config['username'],
                password=server_config['password'],
                timeout=10
            )
            ssh.close()
            return jsonify({"success": True})
        except ImportError:
            return jsonify({"success": False, "error": "paramiko not installed"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})


@app.post("/update/api/test_ssh_alarms/<int:sid>")
@require_auth
def test_ssh_alarms_api(sid):
    with SessionLocal() as s:
        server = s.get(SSHServer, sid)
        if not server:
            return jsonify({"success": False, "error": "Server not found"}), 404

        try:
            server_config = {
                'server_name': server.server_name,
                'ip_address': server.ip_address,
                'username': server.username,
                'password': server.password,
                'port': server.port
            }

            print(f"[API] Testing SSH alarms for {server.server_name}")
            alarms = fetch_ssh_alarms(server_config)

            if alarms is None:
                return jsonify({"success": False, "error": "SSH check failed; existing alarms retained"}), 502
            new_alarms = sync_detected_alarms(s, server.server_name, alarms)

            # Update last fetch time
            server.last_fetch = datetime.utcnow()
            s.commit()

            return jsonify({
                "success": True,
                "alarms_count": len(alarms),
                "new_alarms": new_alarms,
                "message": f"Found {len(alarms)} alarms, {new_alarms} new"
            })

        except Exception as e:
            print(f"[API ERROR] SSH alarm test failed: {str(e)}")
            return jsonify({"success": False, "error": str(e)})


@app.post("/update/api/fetch_all_ssh_alarms")
@require_auth
def fetch_all_ssh_alarms_api():
    with SessionLocal() as s:
        servers = s.query(SSHServer).filter(SSHServer.is_active == True).all()
        servers_checked = 0
        new_alarms = 0

        for server in servers:
            servers_checked += 1
            server_config = {
                'server_name': server.server_name,
                'ip_address': server.ip_address,
                'username': server.username,
                'password': server.password,
                'port': server.port
            }

            alarms = fetch_ssh_alarms(server_config)
            if alarms is None:
                continue
            new_alarms += sync_detected_alarms(s, server.server_name, alarms)

            # Update last fetch time
            server.last_fetch = datetime.utcnow()

        s.commit()
        return jsonify({"ok": True, "servers_checked": servers_checked, "new_alarms": new_alarms})


@app.post("/update/api/fetch_enabled_ssh_alarms")
@require_auth
def fetch_enabled_ssh_alarms_api():
    """Fetch alarms only from servers with auto_fetch_enabled = True"""
    with SessionLocal() as s:
        servers = s.query(SSHServer).filter(
            SSHServer.is_active == True,
            SSHServer.auto_fetch_enabled == True
        ).all()
        servers_checked = 0
        new_alarms = 0

        for server in servers:
            servers_checked += 1
            server_config = {
                'server_name': server.server_name,
                'ip_address': server.ip_address,
                'username': server.username,
                'password': server.password,
                'port': server.port
            }

            alarms = fetch_ssh_alarms(server_config)
            if alarms is None:
                continue
            new_alarms += sync_detected_alarms(s, server.server_name, alarms)

            # Update last fetch time
            server.last_fetch = datetime.utcnow()

        s.commit()
        return jsonify({"ok": True, "servers_checked": servers_checked, "new_alarms": new_alarms})


# ---------------- Sampling background task ----------------
async def sampler_loop():
    loop = asyncio.get_running_loop()
    while True:
        start = time.time()
        try:
            with SessionLocal() as s:
                # Load per-tag intervals into a dict
                global_seconds = global_sample_seconds(s)
                tag_intervals = {ti.tag: ti.seconds for ti in s.query(TagInterval).all()}
                # Build tag -> statuses mapping using tag tables
                statuses_by_tag = {}
                configured_ids = s.query(MetricConfig.status_id)
                active_statuses = s.query(Status).filter(Status.active == True, ~Status.id.in_(configured_ids)).all()
                for st in active_statuses:
                    # Fetch tags for this status
                    st_tags = [t.tag for t in s.query(StatusTag).filter(StatusTag.status_id == st.id).all()]
                    if not st_tags:
                        st_tags = [DEFAULT_DASHBOARD_TAG]
                    for t in st_tags:
                        statuses_by_tag.setdefault(t, []).append(st)
                now_ts = time.time()
                for tag, sts in statuses_by_tag.items():
                    interval = tag_intervals.get(tag, global_seconds)
                    last = SAMPLE_LAST_RUN_BY_TAG.get(tag, 0)
                    if now_ts - last < max(1, interval):
                        continue
                    # It's time to sample this tag's statuses
                    for st in sts:
                        if st.kind == "ping":
                            ok, ms = await loop.run_in_executor(None, ping_once, st.target, 3)
                        elif st.kind == "tcp":
                            ok, ms = await loop.run_in_executor(None, tcp_check, st.target, 3)
                        else:  # html
                            ok, ms = await loop.run_in_executor(None, html_check, st.target, 6)
                        sd = StatusData(status_id=st.id, ts=datetime.utcnow(), latency_ms=ms, success=bool(ok))
                        s.add(sd)
                    SAMPLE_LAST_RUN_BY_TAG[tag] = now_ts
                s.commit()
                # prune old datapoints to keep DB small (keep last 2000 per status)
                try:
                    for st in active_statuses:
                        cnt = s.query(StatusData).filter(StatusData.status_id == st.id).count()
                        if cnt > 2200:
                            # delete oldest
                            to_delete = cnt - 2000
                            q = s.query(StatusData).filter(StatusData.status_id == st.id).order_by(StatusData.ts.asc()).limit(to_delete).all()
                            for r in q: s.delete(r)
                    s.commit()
                except Exception:
                    s.rollback()
        except Exception as e:
            print("sampler error:", e)
        elapsed = time.time() - start
        # Sleep a short base time to keep loop responsive to per-tag timing
        await asyncio.sleep(max(1.0, min(5.0, SAMPLE_SECS_RUNTIME/5)))


METRIC_LAST_RUN = {}


def ssh_metric_value(server_config, command):
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(server_config["ip_address"], port=server_config["port"], username=server_config["username"], password=server_config["password"], timeout=8, auth_timeout=8, banner_timeout=8)
        _, stdout, stderr = ssh.exec_command(command, timeout=10)
        output = stdout.read(65537)
        if len(output) > 65536 or stdout.channel.recv_exit_status() != 0:
            return False, None
        text = output.decode(errors="replace").strip()
        # Never silently turn several readings or an error string into one metric.
        if not re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\s*(?:%|°?C|°?F|ms|s|MB|GB|Mbps)?", text):
            return False, None
        value = float(re.match(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", text).group())
        return (True, value) if math.isfinite(value) else (False, None)
    except Exception:
        return False, None
    finally:
        ssh.close()


def ssh_metric_output(server_config, command):
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(server_config["ip_address"], port=server_config["port"], username=server_config["username"], password=server_config["password"], timeout=8, auth_timeout=8, banner_timeout=8)
        _, stdout, _ = ssh.exec_command(command, timeout=10)
        output = stdout.read(65537)
        if len(output) > 65536 or stdout.channel.recv_exit_status() != 0:
            return False, None
        return True, output.decode(errors="replace").rstrip()
    except Exception:
        return False, None
    finally:
        ssh.close()


async def metric_sampler_loop():
    loop = asyncio.get_running_loop()
    while True:
        try:
            with SessionLocal() as db:
                jobs = []
                now = time.monotonic()
                for status, config in db.query(Status, MetricConfig).join(MetricConfig, MetricConfig.status_id == Status.id).filter(Status.active == True).all():
                    if now - METRIC_LAST_RUN.get(status.id, -float("inf")) < config.interval_secs:
                        continue
                    server = db.get(SSHServer, config.ssh_server_id) if config.ssh_server_id else None
                    connection = {name: getattr(server, name) for name in ("ip_address", "port", "username", "password")} if server and server.is_active else None
                    jobs.append((status.id, status.kind, status.target, config.command, connection, status.graph_type))
                    METRIC_LAST_RUN[status.id] = now
        except Exception as error:
            print(f"Metric monitor scheduling failed: {type(error).__name__}")
            await asyncio.sleep(1)
            continue
        async def sample(job):
            sid, kind, target, command, connection, display = job
            try:
                if display == "none":
                    ok, output = await loop.run_in_executor(None, ssh_metric_output, connection, command) if connection else (False, None)
                    if ok:
                        with SessionLocal() as db:
                            if db.get(MetricConfig, sid) is not None:
                                reading = db.get(MetricTextReading, sid) or MetricTextReading(status_id=sid)
                                reading.output, reading.updated_at = output, datetime.utcnow()
                                db.add(reading); db.commit()
                    return
                if kind == "ssh":
                    ok, value = await loop.run_in_executor(None, ssh_metric_value, connection, command) if connection else (False, None)
                else:
                    checker = {"ping": ping_once, "tcp": tcp_check, "html": html_check}[kind]
                    ok, value = await loop.run_in_executor(None, checker, target)
                with SessionLocal() as db:
                    if db.get(MetricConfig, sid) is not None:
                        db.add(StatusData(status_id=sid, ts=datetime.utcnow(), latency_ms=value, success=ok))
                        old_ids = db.query(StatusData.id).filter_by(status_id=sid).order_by(StatusData.id.desc()).offset(2000).all()
                        if old_ids:
                            last_good = db.query(StatusData.id).filter_by(status_id=sid, success=True).filter(StatusData.latency_ms.isnot(None)).order_by(StatusData.id.desc()).first()
                            removable = [r.id for r in old_ids if not last_good or r.id != last_good.id]
                            if removable:
                                db.query(StatusData).filter(StatusData.id.in_(removable)).delete(synchronize_session=False)
                        db.commit()
            except Exception as error:
                print(f"Metric monitor {sid} sample failed: {type(error).__name__}")
        await asyncio.gather(*(sample(job) for job in jobs))
        await asyncio.sleep(1)


async def ssh_alarm_fetcher_loop():
    """Background task to automatically fetch SSH alarms based on server intervals"""
    loop = asyncio.get_running_loop()
    while True:
        try:
            await asyncio.sleep(60)  # Check every minute
            with SessionLocal() as s:
                servers = s.query(SSHServer).filter(
                    SSHServer.is_active == True,
                    SSHServer.auto_fetch_enabled == True
                ).all()
                for server in servers:
                    # Check if it's time to fetch alarms for this server
                    if server.last_fetch is None or \
                       (datetime.utcnow() - server.last_fetch).total_seconds() >= server.fetch_interval:

                        server_config = {
                            'server_name': server.server_name,
                            'ip_address': server.ip_address,
                            'username': server.username,
                            'password': server.password,
                            'port': server.port
                        }

                        # Fetch alarms in background thread
                        alarms = await loop.run_in_executor(None, fetch_ssh_alarms, server_config)

                        if alarms is None:
                            continue
                        sync_detected_alarms(s, server.server_name, alarms)

                        # Update last fetch time
                        server.last_fetch = datetime.utcnow()
                        s.commit()
                        print(f"Fetched alarms for {server.server_name}: {len(alarms)} alarms found")

        except Exception as e:
            print(f"SSH alarm fetcher error: {e}")
            await asyncio.sleep(30)


# ---------------- Main runner ----------------
async def main():
    # start sampler background task and serve Flask using hypercorn or builtin dev server if hypercorn not present.
    sampler_task = asyncio.create_task(sampler_loop())
    ssh_fetcher_task = asyncio.create_task(ssh_alarm_fetcher_loop())
    metric_task = asyncio.create_task(metric_sampler_loop())
    try:
        # prefer hypercorn if available for async-friendly serving
        try:
            from hypercorn.asyncio import serve
            from hypercorn.config import Config
            config = Config(); config.bind = ["0.0.0.0:8000"]
            print("Starting hypercorn on 0.0.0.0:8000")
            await serve(app, config)
        except Exception:
            # fallback to Flask builtin (blocking) — run in a thread-safe way
            print("Hypercorn not available; running Flask development server on 0.0.0.0:8000 (not for production)")
            from threading import Thread
            def runfl():
                app.run(host="0.0.0.0", port=8000)
            t = Thread(target=runfl, daemon=True)
            t.start()
            while True:
                await asyncio.sleep(3600)
    finally:
        metric_task.cancel()
        try:
            await metric_task
        except asyncio.CancelledError:
            pass
        sampler_task.cancel()
        ssh_fetcher_task.cancel()
        try:
            await sampler_task
        except asyncio.CancelledError:
            pass
        try:
            await ssh_fetcher_task
        except asyncio.CancelledError:
            pass


# ---------------- UI root ----------------
@app.route("/")
def index():
    with SessionLocal() as db:
        seconds = global_sample_seconds(db)
    return render_template("dashboard.html", sample_secs=seconds, allowed_contact=ALLOWED_ERROR_CONTACT)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
