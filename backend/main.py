# ============================================================
# ABACUS SECURITY MONITOR
# Custom Central Security Monitoring Backend
#
# Version: 0.6.0
#
# Architecture:
#
#   Custom Endpoint Agent
#            |
#            v
#      FastAPI Ingestion
#            |
#            v
#          SQLite
#            |
#      +-----+------+
#      |            |
#      v            v
#  Detection     Device State
#      |
#      v
#   Risk Engine
#      |
#      v
#     Alerts
#      |
#      v
#    Dashboard
#
# ============================================================

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional, Sequence
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
import json
import logging
import os
import uuid
import ipaddress

from backend.correlation import correlate, CORRELATION_ENGINE_VERSION


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = DATA_DIR / "security.db"

APP_NAME = "Abacus Security Monitor"
APP_VERSION = "0.8.4-alpha"


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("AbacusSecurityMonitor")


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title=APP_NAME,
    description="Custom in-house endpoint and security monitoring platform",
    version=APP_VERSION
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# DATABASE
# ============================================================

def get_connection():
    """
    Create a SQLite connection.

    SQLite is intentionally being used at this stage because
    the project is currently a prototype / small pilot.

    We can move to PostgreSQL later if telemetry volume requires it.
    """

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    return connection


def _safe_int(value: Any) -> Optional[int]:
    """
    Safely convert a telemetry value to an integer.

    Network telemetry can contain missing, string, or malformed
    port values. Detection code should never fail because of one
    malformed telemetry field.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def init_database():
    """
    Create all required database tables.
    """

    connection = get_connection()

    cursor = connection.cursor()

    # --------------------------------------------------------
    # TELEMETRY
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            event_id TEXT UNIQUE,

            device_id TEXT NOT NULL,

            timestamp TEXT NOT NULL,

            telemetry_type TEXT NOT NULL,

            agent_version TEXT,

            payload TEXT NOT NULL,

            received_at TEXT NOT NULL
        )
        """
    )

    # --------------------------------------------------------
    # DEVICES
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,

            hostname TEXT,

            username TEXT,

            platform TEXT,

            platform_version TEXT,

            platform_release TEXT,

            machine TEXT,

            processor TEXT,

            agent_version TEXT,

            first_seen TEXT,

            last_seen TEXT,

            status TEXT DEFAULT 'online',

            risk_score REAL DEFAULT 0
        )
        """
    )

    # --------------------------------------------------------
    # ALERTS
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            alert_id TEXT UNIQUE NOT NULL,

            device_id TEXT,

            timestamp TEXT NOT NULL,

            severity TEXT NOT NULL,

            title TEXT NOT NULL,

            description TEXT,

            rule_id TEXT,

            risk_score REAL DEFAULT 0,

            status TEXT DEFAULT 'open',

            evidence TEXT,

            fingerprint TEXT,

            first_seen TEXT,

            last_seen TEXT,

            occurrence_count INTEGER DEFAULT 1
        )
        """
    )

    # --------------------------------------------------------
    # ALERT ENGINE V0.5 MIGRATION
    #
    # Existing databases are upgraded in-place so development
    # history is preserved.
    # --------------------------------------------------------

    alert_columns = {
        row["name"]
        for row in cursor.execute(
            "PRAGMA table_info(alerts)"
        ).fetchall()
    }

    migrations = {
        "fingerprint": "ALTER TABLE alerts ADD COLUMN fingerprint TEXT",
        "first_seen": "ALTER TABLE alerts ADD COLUMN first_seen TEXT",
        "last_seen": "ALTER TABLE alerts ADD COLUMN last_seen TEXT",
        "occurrence_count": "ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER DEFAULT 1",
    }

    for column, statement in migrations.items():
        if column not in alert_columns:
            cursor.execute(statement)

    # Backfill legacy alerts with a stable detection fingerprint.
    cursor.execute(
        """
        UPDATE alerts
        SET fingerprint =
            COALESCE(device_id, '') || '|' ||
            COALESCE(rule_id, '') || '|' ||
            COALESCE(title, ''),
            first_seen = COALESCE(first_seen, timestamp),
            last_seen = COALESCE(last_seen, timestamp),
            occurrence_count = COALESCE(occurrence_count, 1)
        WHERE fingerprint IS NULL
        """
    )

    # Helpful indexes for alert lifecycle queries.
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint_status
        ON alerts(fingerprint, status)
        """
    )

    # --------------------------------------------------------
    # COLLAPSE LEGACY DUPLICATES
    #
    # Keep one active record per fingerprint and retain the
    # historical duplicate count. Older duplicate rows are
    # marked as "deduplicated", not deleted.
    # --------------------------------------------------------

    duplicate_groups = cursor.execute(
        """
        SELECT fingerprint, COUNT(*) AS count
        FROM alerts
        WHERE status IN ('open', 'acknowledged')
          AND fingerprint IS NOT NULL
        GROUP BY fingerprint
        HAVING COUNT(*) > 1
        """
    ).fetchall()

    for group in duplicate_groups:
        fingerprint = group["fingerprint"]

        rows = cursor.execute(
            """
            SELECT id, alert_id, timestamp, risk_score, evidence
            FROM alerts
            WHERE fingerprint = ?
              AND status IN ('open', 'acknowledged')
            ORDER BY id ASC
            """,
            (fingerprint,)
        ).fetchall()

        if not rows:
            continue

        keeper = rows[0]
        latest = rows[-1]

        total_occurrences = sum(
            int(
                cursor.execute(
                    "SELECT COALESCE(occurrence_count, 1) FROM alerts WHERE id = ?",
                    (row["id"],)
                ).fetchone()[0] or 1
            )
            for row in rows
        )

        cursor.execute(
            """
            UPDATE alerts
            SET last_seen = ?,
                occurrence_count = ?,
                risk_score = ?
            WHERE id = ?
            """,
            (
                latest["timestamp"],
                total_occurrences,
                latest["risk_score"],
                keeper["id"]
            )
        )

        duplicate_ids = [
            row["id"]
            for row in rows[1:]
        ]

        placeholders = ",".join("?" for _ in duplicate_ids)

        cursor.execute(
            f"""
            UPDATE alerts
            SET status = 'deduplicated'
            WHERE id IN ({placeholders})
            """,
            duplicate_ids
        )

    # --------------------------------------------------------
    # RISK HISTORY
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id TEXT NOT NULL,

            timestamp TEXT NOT NULL,

            risk_score REAL NOT NULL,

            reason TEXT
        )
        """
    )

    # --------------------------------------------------------
    # RISK CONDITIONS V0.6
    #
    # A condition represents a currently observable security
    # signal, rather than a permanent accumulated risk increment.
    # --------------------------------------------------------

    # --------------------------------------------------------
    # RISK CONDITIONS V0.8.4 MIGRATION
    #
    # Condition identity is endpoint-scoped. A destination such as
    # destination:1.2.3.4:443 may legitimately exist on many devices,
    # so condition_key must NOT be globally unique.
    #
    # Existing v0.6/v0.8 databases used condition_key as the primary key.
    # SQLite cannot alter that primary-key definition in place, so the
    # table is rebuilt once with a composite primary key. Existing rows
    # and history are preserved.
    # --------------------------------------------------------

    risk_condition_columns = {
        row["name"]
        for row in cursor.execute(
            "PRAGMA table_info(risk_conditions)"
        ).fetchall()
    }

    if not risk_condition_columns:
        cursor.execute(
            """
            CREATE TABLE risk_conditions (
                condition_key TEXT NOT NULL,
                device_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT,
                severity TEXT,
                confidence TEXT,
                mitre_id TEXT,
                state TEXT NOT NULL DEFAULT 'NEW',
                risk_contribution REAL NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                evidence TEXT,
                PRIMARY KEY (device_id, condition_key)
            )
            """
        )
    else:
        risk_pk = cursor.execute(
            "PRAGMA table_info(risk_conditions)"
        ).fetchall()
        pk_columns = [
            row["name"]
            for row in sorted(
                risk_pk,
                key=lambda row: row["pk"]
            )
            if row["pk"]
        ]

        if pk_columns != ["device_id", "condition_key"]:
            logger.info(
                "[DB-MIGRATION] Rebuilding risk_conditions for "
                "device-scoped condition identity"
            )

            cursor.execute(
                """
                CREATE TABLE risk_conditions_new (
                    condition_key TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT,
                    severity TEXT,
                    confidence TEXT,
                    mitre_id TEXT,
                    state TEXT NOT NULL DEFAULT 'NEW',
                    risk_contribution REAL NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    evidence TEXT,
                    PRIMARY KEY (device_id, condition_key)
                )
                """
            )

            cursor.execute(
                """
                INSERT INTO risk_conditions_new (
                    condition_key, device_id, source_type, rule_id, title,
                    category, severity, confidence, mitre_id, state,
                    risk_contribution, first_seen, last_seen,
                    occurrence_count, evidence
                )
                SELECT
                    condition_key, device_id, source_type, rule_id, title,
                    category, severity, confidence, mitre_id, state,
                    risk_contribution, first_seen, last_seen,
                    occurrence_count, evidence
                FROM risk_conditions
                """
            )

            cursor.execute("DROP TABLE risk_conditions")
            cursor.execute(
                "ALTER TABLE risk_conditions_new RENAME TO risk_conditions"
            )

            logger.info(
                "[DB-MIGRATION] risk_conditions migrated successfully"
            )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_risk_conditions_device
        ON risk_conditions(device_id)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_risk_conditions_state
        ON risk_conditions(device_id, state)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_risk_conditions_source
        ON risk_conditions(device_id, source_type)
        """
    )

    # --------------------------------------------------------
    # INCIDENTS V0.7
    #
    # An incident is a correlated security story built from one or
    # more risk conditions. Conditions remain the raw evidence layer.
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_key TEXT UNIQUE NOT NULL,

            device_id TEXT NOT NULL,

            correlation_rule_id TEXT NOT NULL,

            title TEXT NOT NULL,

            category TEXT,

            description TEXT,

            severity TEXT,

            confidence TEXT,

            attack_stage TEXT,

            mitre_id TEXT,

            state TEXT NOT NULL DEFAULT 'NEW',

            risk_score REAL NOT NULL DEFAULT 0,

            base_risk REAL NOT NULL DEFAULT 0,

            correlation_bonus REAL NOT NULL DEFAULT 0,

            first_seen TEXT NOT NULL,

            last_seen TEXT NOT NULL,

            occurrence_count INTEGER NOT NULL DEFAULT 1,

            condition_count INTEGER NOT NULL DEFAULT 0,

            condition_keys TEXT,

            evidence TEXT,

            rationale TEXT,

            source_types TEXT,

            users TEXT,

            processes TEXT,

            destinations TEXT,

            created_at TEXT NOT NULL,

            updated_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incidents_device
        ON incidents(device_id)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incidents_state
        ON incidents(device_id, state)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incidents_rule
        ON incidents(device_id, correlation_rule_id)
        """
    )

    # --------------------------------------------------------
    # INDEXES
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_telemetry_device
        ON telemetry(device_id)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp
        ON telemetry(timestamp)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_telemetry_type
        ON telemetry(telemetry_type)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_device
        ON alerts(device_id)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_status
        ON alerts(status)
        """
    )

    connection.commit()
    connection.close()

    logger.info("Database initialized")


# Initialize database when application starts.
init_database()


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def utc_now() -> str:
    """
    Return current UTC timestamp in ISO format.
    """

    return datetime.now(timezone.utc).isoformat()


def parse_json(value: str) -> Any:
    """
    Safely parse JSON stored in SQLite.
    """

    try:
        return json.loads(value)
    except Exception:
        return {}

# ============================================================
# RISK CLASSIFICATION
# ============================================================

def risk_level(score: float) -> str:
    """
    Convert the backend risk score into a stable risk level.

    Risk bands:
        0-24   -> LOW
        25-49  -> MEDIUM
        50-74  -> HIGH
        75-100 -> CRITICAL
    """

    try:
        score = float(score or 0.0)
    except (TypeError, ValueError):
        score = 0.0

    score = max(0.0, min(100.0, score))

    if score >= 75.0:
        return "CRITICAL"

    if score >= 50.0:
        return "HIGH"

    if score >= 25.0:
        return "MEDIUM"

    return "LOW"
def calculate_online(last_seen: Optional[str]) -> bool:
    """
    Determine whether a device is currently online.

    For now, a device is considered online if telemetry was
    received within the last 2 minutes.

    This can later become heartbeat-based.
    """

    if not last_seen:
        return False

    try:
        timestamp = datetime.fromisoformat(last_seen)

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        age = datetime.now(timezone.utc) - timestamp

        return age.total_seconds() <= 120

    except Exception:
        return False


# ============================================================
# PYDANTIC MODELS
# ============================================================

class Telemetry(BaseModel):
    """
    Telemetry packet received from the custom endpoint agent.
    """

    event_id: Optional[str] = None

    device_id: str

    timestamp: Optional[str] = None

    telemetry_type: str

    payload: Dict[str, Any]

    agent_version: Optional[str] = None


class AlertStatusUpdate(BaseModel):
    status: str = Field(
        ...,
        description="open, acknowledged, resolved, dismissed"
    )


# ============================================================
# DEVICE MANAGEMENT
# ============================================================

def register_or_update_device(
    device_id: str,
    telemetry_type: str,
    payload: Dict[str, Any],
    timestamp: str,
    agent_version: Optional[str]
):
    """
    Create or update device inventory.

    Device information normally arrives through telemetry_type=device.
    Other telemetry types also update last_seen.
    """

    connection = get_connection()
    cursor = connection.cursor()

    existing = cursor.execute(
        """
        SELECT device_id
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,)
    ).fetchone()

    if telemetry_type == "device":

        hostname = payload.get("hostname")
        username = payload.get("username")

        # Support the current agent schema while keeping
        # compatibility with the backend schema.
        platform = (
            payload.get("platform")
            or payload.get("os")
            or "unknown"
        )

        platform_version = (
            payload.get("platform_version")
            or payload.get("os_version")
            or "unknown"
        )

        platform_release = payload.get(
            "platform_release"
        )
        machine = payload.get("machine")
        processor = payload.get("processor")

        if existing:

            cursor.execute(
                """
                UPDATE devices

                SET hostname = ?,
                    username = ?,
                    platform = ?,
                    platform_version = ?,
                    platform_release = ?,
                    machine = ?,
                    processor = ?,
                    agent_version = ?,
                    last_seen = ?,
                    status = 'online'

                WHERE device_id = ?
                """,
                (
                    hostname,
                    username,
                    platform,
                    platform_version,
                    platform_release,
                    machine,
                    processor,
                    agent_version,
                    timestamp,
                    device_id
                )
            )

        else:

            cursor.execute(
                """
                INSERT INTO devices (
                    device_id,
                    hostname,
                    username,
                    platform,
                    platform_version,
                    platform_release,
                    machine,
                    processor,
                    agent_version,
                    first_seen,
                    last_seen,
                    status,
                    risk_score
                )

                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', 0)
                """,
                (
                    device_id,
                    hostname,
                    username,
                    platform,
                    platform_version,
                    platform_release,
                    machine,
                    processor,
                    agent_version,
                    timestamp,
                    timestamp
                )
            )

    else:

        if existing:

            cursor.execute(
                """
                UPDATE devices

                SET last_seen = ?,
                    status = 'online',
                    agent_version = COALESCE(?, agent_version)

                WHERE device_id = ?
                """,
                (
                    timestamp,
                    agent_version,
                    device_id
                )
            )

        else:

            cursor.execute(
                """
                INSERT INTO devices (
                    device_id,
                    first_seen,
                    last_seen,
                    status,
                    agent_version,
                    risk_score
                )

                VALUES (?, ?, ?, 'online', ?, 0)
                """,
                (
                    device_id,
                    timestamp,
                    timestamp,
                    agent_version
                )
            )

    connection.commit()
    connection.close()


# ============================================================
# DETECTION ENGINE
# ============================================================

from backend.detection import detect as custom_detect


DETECTION_ENGINE_VERSION = "0.8.2"
# =========================================================
# NETWORK DESTINATION / BEHAVIOR HISTORY
# =========================================================

def get_seen_network_destinations(
    device_id: str,
    current_event_id: Optional[str],
    current_connections: list[dict],
) -> set[tuple[str, str]]:
    """
    Return public network destinations previously observed for this device.

    Key:
        (remote_ip, remote_port)

    The current telemetry event is explicitly excluded from the historical
    query. Destination rarity is endpoint-level rather than process-level:
    a destination already known to the endpoint should not become "rare"
    merely because a different legitimate process contacted it.
    """

    if not device_id or not current_connections:
        return set()

    current_destinations: set[tuple[str, str]] = set()

    for conn in current_connections:
        if not isinstance(conn, dict):
            continue

        remote_ip = conn.get("remote_ip")
        remote_port = _safe_int(conn.get("remote_port"))

        if not remote_ip or not remote_port:
            raddr = conn.get("raddr") or {}
            if isinstance(raddr, dict):
                remote_ip = remote_ip or raddr.get("ip")
                remote_port = remote_port or _safe_int(raddr.get("port"))

        if not remote_ip or not remote_port:
            continue

        current_destinations.add(
            (str(remote_ip).strip(), str(remote_port).strip())
        )

    if not current_destinations:
        return set()

    seen: set[tuple[str, str]] = set()

    connection = get_connection()
    try:
        if current_event_id:
            rows = connection.execute(
                """
                SELECT payload
                FROM telemetry
                WHERE device_id = ?
                  AND telemetry_type = 'network'
                  AND (event_id IS NULL OR event_id != ?)
                ORDER BY id DESC
                LIMIT 5000
                """,
                (device_id, current_event_id),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT payload
                FROM telemetry
                WHERE device_id = ?
                  AND telemetry_type = 'network'
                ORDER BY id DESC
                LIMIT 5000
                """,
                (device_id,),
            ).fetchall()
    finally:
        connection.close()

    for row in rows:
        payload = parse_json(row["payload"])
        connections = payload.get("connections", [])

        if not isinstance(connections, list):
            continue

        for item in connections:
            if not isinstance(item, dict):
                continue

            remote_ip = item.get("remote_ip")
            remote_port = _safe_int(item.get("remote_port"))

            if not remote_ip or not remote_port:
                raddr = item.get("raddr") or {}
                if isinstance(raddr, dict):
                    remote_ip = remote_ip or raddr.get("ip")
                    remote_port = remote_port or _safe_int(raddr.get("port"))

            if not remote_ip or not remote_port:
                continue

            key = (
                str(remote_ip).strip(),
                str(remote_port).strip(),
            )

            if key in current_destinations:
                seen.add(key)

    return seen

def get_network_behavior_history(
    device_id: str,
    current_event_id: Optional[str],
    lookback_events: int = 20,
) -> dict:
    """
    Build lightweight historical network behavior for the detection engine.

    The current event is explicitly excluded.

    Returned data is intentionally summarized rather than dumping historical
    telemetry into detection.py. This keeps the detection engine stateless.
    """

    history = {
        "event_count": 0,
        "distinct_remote_ips": set(),
        "distinct_destinations": set(),
        "distinct_ports": set(),
        "internal_remote_ips": set(),
        "public_remote_ips": set(),
        "events": [],
    }

    if not device_id:
        return history

    connection = get_connection()

    try:
        if current_event_id:
            rows = connection.execute(
                """
                SELECT event_id, timestamp, received_at, payload
                FROM telemetry
                WHERE device_id = ?
                  AND telemetry_type = 'network'
                  AND (event_id IS NULL OR event_id != ?)
                ORDER BY id DESC
                LIMIT ?
                """,
                (device_id, current_event_id, lookback_events),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT event_id, timestamp, received_at, payload
                FROM telemetry
                WHERE device_id = ?
                  AND telemetry_type = 'network'
                ORDER BY id DESC
                LIMIT ?
                """,
                (device_id, lookback_events),
            ).fetchall()
    finally:
        connection.close()

    for row in rows:
        payload = parse_json(row["payload"])

        if not isinstance(payload, dict):
            continue

        connections = payload.get("connections", [])

        if not isinstance(connections, list):
            continue

        event_ips = set()
        event_destinations = set()
        event_ports = set()

        for item in connections:
            if not isinstance(item, dict):
                continue

            remote_ip = item.get("remote_ip")
            remote_port = _safe_int(item.get("remote_port"))

            if not remote_ip or not remote_port:
                raddr = item.get("raddr") or {}

                if isinstance(raddr, dict):
                    remote_ip = remote_ip or raddr.get("ip")
                    remote_port = (
                        remote_port
                        or _safe_int(raddr.get("port"))
                    )

            if not remote_ip or not remote_port:
                continue

            remote_ip = str(remote_ip).strip()
            remote_port = str(remote_port).strip()

            destination = f"{remote_ip}:{remote_port}"

            event_ips.add(remote_ip)
            event_destinations.add(destination)
            event_ports.add(remote_port)

            try:
                import ipaddress

                ip_obj = ipaddress.ip_address(remote_ip)

                if ip_obj.is_private:
                    history["internal_remote_ips"].add(remote_ip)
                elif ip_obj.is_global:
                    history["public_remote_ips"].add(remote_ip)

            except ValueError:
                continue

        history["distinct_remote_ips"].update(event_ips)
        history["distinct_destinations"].update(event_destinations)
        history["distinct_ports"].update(event_ports)

        history["events"].append(
            {
                "event_id": row["event_id"],
                "timestamp": row["timestamp"],
                "received_at": row["received_at"],
                "connection_count": len(connections),
                "distinct_remote_ips": len(event_ips),
                "distinct_destinations": len(event_destinations),
                "distinct_ports": len(event_ports),
            }
        )

    history["event_count"] = len(history["events"])

    return history

def run_detection(
    device_id: str,
    telemetry_type: str,
    payload: Dict[str, Any],
    current_event_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Run the custom Abacus Detection Engine.

    v0.6 keeps detection separate from risk calculation:
        Telemetry -> Detection -> Condition -> Risk -> Alert

    Detection Engine v0.8 condition metadata is preserved so the
    risk engine can track the lifetime of each security condition.
    """

    if not isinstance(payload, dict):
        return []

    # --------------------------------------------------------
    # NORMALIZE TELEMETRY
    # --------------------------------------------------------

    normalized = {}

    if telemetry_type == "processes":
        processes = payload.get("processes")

        if processes is None:
            processes = payload.get("top_processes", [])

        normalized["processes"] = (
            processes if isinstance(processes, list) else []
        )

    elif telemetry_type == "network":
        connections = payload.get("connections", [])

        normalized["connections"] = (
            connections if isinstance(connections, list) else []
        )

        normalized["seen_destinations"] = get_seen_network_destinations(
            device_id=device_id,
            current_event_id=current_event_id,
            current_connections=normalized["connections"],
        )

        # Provide bounded endpoint history to the stateless detection engine.
        # The current event is excluded inside get_network_behavior_history().
        normalized["network_history"] = get_network_behavior_history(
            device_id=device_id,
            current_event_id=current_event_id,
            lookback_events=20,
        )

    else:
        normalized["processes"] = (
            payload.get("processes")
            or payload.get("top_processes")
            or []
        )

        normalized["connections"] = (
            payload.get("connections")
            or []
        )

    # --------------------------------------------------------
    # RUN CUSTOM DETECTION ENGINE
    # --------------------------------------------------------

    try:
        detections = custom_detect(normalized)
    except Exception:
        logger.exception(
            "Custom detection engine failed | "
            "Device=%s | Type=%s",
            device_id,
            telemetry_type
        )
        return []

    if not detections:
        return []

    # --------------------------------------------------------
    # NORMALIZE DETECTION OUTPUT
    # --------------------------------------------------------

    normalized_detections = []

    for detection in detections:

        if not isinstance(detection, dict):
            continue

        rule_id = detection.get("rule_id", "UNKNOWN")
        title = detection.get("title", "Security detection")
        category = detection.get("category") or "unknown"

        # v0.8 supplies a stable condition key. Keep a fallback
        # for compatibility with older detection engines.
        condition_key = (
            detection.get("condition_key")
            or detection.get("signal_key")
            or detection.get("fingerprint")
            or f"{device_id}|{telemetry_type}|{rule_id}|{title}"
        )

        normalized_detections.append(
            {
                "rule_id": rule_id,

                "severity": str(
                    detection.get("severity", "LOW")
                ).upper(),

                "title": title,

                "description": detection.get(
                    "description",
                    ""
                ),

                "risk": float(
                    detection.get(
                        "risk_increment",
                        detection.get("risk", 0)
                    ) or 0
                ),

                "evidence": detection.get(
                    "evidence",
                    []
                ),

                "confidence": detection.get(
                    "confidence"
                ),

                "category": category,

                "mitre_technique": detection.get(
                    "mitre_technique"
                ),

                "mitre_id": detection.get(
                    "mitre_id"
                ),

                "fingerprint": detection.get(
                    "fingerprint"
                ),

                "signal_key": detection.get(
                    "signal_key"
                ),

                "condition_key": condition_key,

                "condition_state": detection.get(
                    "condition_state",
                    "NEW"
                ),

                "detected_at": detection.get(
                    "detected_at"
                )
            }
        )

    return normalized_detections


# ============================================================
# RISK ENGINE V0.6
# ============================================================

RISK_CONDITION_STALE_SECONDS = 60
RISK_CONDITION_RESOLVING_SECONDS = 30

CONFIDENCE_WEIGHTS = {
    "HIGH": 1.00,
    "MEDIUM": 0.85,
    "LOW": 0.65
}


def get_current_risk(device_id: str) -> float:
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT risk_score
            FROM devices
            WHERE device_id = ?
            """,
            (device_id,)
        ).fetchone()

        return float(row["risk_score"] or 0) if row else 0.0

    finally:
        connection.close()


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except Exception:
        return None


def _confidence_weight(confidence: Optional[str]) -> float:
    return CONFIDENCE_WEIGHTS.get(
        str(confidence or "").upper(),
        0.75
    )


def _condition_effective_risk(row) -> float:
    """
    Convert a stored condition into its bounded current
    contribution to device risk.

    Repeated observations reinforce a condition gradually,
    but never allow one condition to grow without bound.
    """

    base = max(
        0.0,
        min(
            100.0,
            float(row["risk_contribution"] or 0)
        )
    )

    confidence = _confidence_weight(
        row["confidence"]
    )

    occurrences = max(
        1,
        int(row["occurrence_count"] or 1)
    )

    # Persistence reinforcement:
    # +5% per additional observation, capped at +50%.
    persistence_multiplier = min(
        1.50,
        1.0 + ((occurrences - 1) * 0.05)
    )

    state_multiplier = {
        "NEW": 1.00,
        "ACTIVE": 1.00,
        "REINFORCED": min(
            1.50,
            persistence_multiplier
        ),
        "RESOLVING": 0.50
    }.get(
        str(row["state"] or "").upper(),
        0.0
    )

    return min(
        100.0,
        base
        * confidence
        * state_multiplier
    )


def _active_condition_rows(connection, device_id: str):
    return connection.execute(
        """
        SELECT *
        FROM risk_conditions
        WHERE device_id = ?
          AND state IN ('NEW', 'ACTIVE', 'REINFORCED', 'RESOLVING')
        """,
        (device_id,)
    ).fetchall()


def _condition_dict_from_row(row) -> Dict[str, Any]:
    return {
        "condition_key": row["condition_key"],
        "device_id": row["device_id"],
        "source_type": row["source_type"],
        "rule_id": row["rule_id"],
        "title": row["title"],
        "category": row["category"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "mitre_id": row["mitre_id"],
        "state": row["state"],
        "risk_contribution": row["risk_contribution"],
        "effective_risk": _condition_effective_risk(row),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "occurrence_count": row["occurrence_count"] or 1,
        "evidence": parse_json(row["evidence"]),
    }


def _incident_effective_risk(row) -> float:
    base = max(0.0, min(100.0, float(row["risk_score"] or 0)))
    state = str(row["state"] or "").upper()
    if state == "RESOLVING":
        return round(base * 0.50, 2)
    if state in ("NEW", "ACTIVE", "REINFORCED"):
        return round(base, 2)
    return 0.0


def _refresh_incident_states(connection, device_id: str, now: Optional[datetime] = None):
    now = now or datetime.now(timezone.utc)
    rows = connection.execute(
        "SELECT incident_key, state, last_seen FROM incidents WHERE device_id = ?",
        (device_id,)
    ).fetchall()

    changed = False
    for row in rows:
        last_seen = _parse_timestamp(row["last_seen"])
        if last_seen is None:
            continue
        age = max(0.0, (now - last_seen).total_seconds())
        state = str(row["state"] or "").upper()

        if age >= RISK_CONDITION_STALE_SECONDS:
            new_state = "RESOLVED"
        elif age >= RISK_CONDITION_RESOLVING_SECONDS:
            new_state = "RESOLVING"
        else:
            # Existing active incidents retain their lifecycle state.
            new_state = state if state in ("NEW", "ACTIVE", "REINFORCED") else "ACTIVE"

        if new_state != state:
            connection.execute(
                "UPDATE incidents SET state = ?, updated_at = ? WHERE incident_key = ?",
                (new_state, now.isoformat(), row["incident_key"])
            )
            changed = True

    if changed:
        connection.commit()


def _calculate_device_risk(
    connection,
    device_id: str,
    now: Optional[datetime] = None,
) -> float:
    """
    Calculate device risk from incidents plus genuinely uncorrelated
    conditions. Conditions belonging to an active/resolving incident are
    excluded from the raw condition sum to prevent double counting.
    """
    now = now or datetime.now(timezone.utc)
    _calculate_condition_risk(connection, device_id, now)
    _refresh_incident_states(connection, device_id, now)

    incident_rows = connection.execute(
        """
        SELECT * FROM incidents
        WHERE device_id = ?
          AND state IN ('NEW', 'ACTIVE', 'REINFORCED', 'RESOLVING')
        """,
        (device_id,)
    ).fetchall()

    incident_risk = 0.0
    correlated_keys = set()

    for row in incident_rows:
        incident_risk += _incident_effective_risk(row)
        correlated_keys.update(parse_json(row["condition_keys"]) if row["condition_keys"] else [])

    condition_risk = 0.0
    for row in _active_condition_rows(connection, device_id):
        if row["condition_key"] in correlated_keys:
            continue
        condition_risk += _condition_effective_risk(row)

    return round(min(100.0, max(0.0, incident_risk + condition_risk)), 2)


def _calculate_condition_risk(
    connection,
    device_id: str,
    now: Optional[datetime] = None
) -> float:
    """
    Reconcile condition freshness and calculate device risk from
    conditions that are still active.

    This is intentionally state-based. Risk is no longer a pile of
    historical increments.
    """

    now = now or datetime.now(timezone.utc)

    rows = connection.execute(
        """
        SELECT *
        FROM risk_conditions
        WHERE device_id = ?
        """,
        (device_id,)
    ).fetchall()

    total_risk = 0.0

    for row in rows:

        last_seen = _parse_timestamp(
            row["last_seen"]
        )

        if last_seen is None:
            continue

        age_seconds = max(
            0.0,
            (now - last_seen).total_seconds()
        )

        state = str(
            row["state"] or ""
        ).upper()

        # Conditions are considered active while they are being
        # observed. A short gap enters RESOLVING instead of
        # disappearing instantly.
        if age_seconds >= RISK_CONDITION_STALE_SECONDS:

            if state != "RESOLVED":
                connection.execute(
                    """
                    UPDATE risk_conditions
                    SET state = 'RESOLVED'
                    WHERE device_id = ?
                      AND condition_key = ?
                    """,
                    (device_id, row["condition_key"])
                )

                logger.info(
                    "[RISK-CONDITION-RESOLVED] %s | %s | "
                    "age=%.1fs",
                    row["rule_id"],
                    row["title"],
                    age_seconds
                )

            continue

        if age_seconds >= RISK_CONDITION_RESOLVING_SECONDS:

            if state not in ("RESOLVING", "RESOLVED"):
                connection.execute(
                    """
                    UPDATE risk_conditions
                    SET state = 'RESOLVING'
                    WHERE device_id = ?
                      AND condition_key = ?
                    """,
                    (device_id, row["condition_key"])
                )

                state = "RESOLVING"

        elif state == "RESOLVING":
            connection.execute(
                """
                UPDATE risk_conditions
                SET state = 'ACTIVE'
                WHERE device_id = ?
                      AND condition_key = ?
                """,
                (device_id, row["condition_key"])
            )
            state = "ACTIVE"

        # Re-read semantics using a small dict-like proxy is not
        # necessary. The current state only affects the multiplier.
        if state in ("NEW", "ACTIVE", "REINFORCED", "RESOLVING"):
            base = max(
                0.0,
                min(
                    100.0,
                    float(row["risk_contribution"] or 0)
                )
            )

            confidence = _confidence_weight(
                row["confidence"]
            )

            occurrences = max(
                1,
                int(row["occurrence_count"] or 1)
            )

            persistence_multiplier = min(
                1.50,
                1.0 + ((occurrences - 1) * 0.05)
            )

            state_multiplier = {
                "NEW": 1.00,
                "ACTIVE": 1.00,
                "REINFORCED": persistence_multiplier,
                "RESOLVING": 0.50
            }.get(state, 0.0)

            total_risk += (
                base
                * confidence
                * state_multiplier
            )

    return round(
        min(100.0, max(0.0, total_risk)),
        2
    )




def refresh_device_risk(
    device_id: str,
    reason: str = "risk state refresh"
) -> float:
    """
    Recalculate and persist the current device risk.

    Risk is calculated by _calculate_device_risk(), which applies
    incident precedence and excludes conditions already represented
    by correlated incidents.

    Risk lifecycle:

        Detection
            ↓
        Risk Condition
            ↓
        Correlation / Incident
            ↓
        Device Risk
            ↓
        Risk Level
    """

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    connection = get_connection()

    try:
        # --------------------------------------------------------
        # CURRENT SCORE
        # --------------------------------------------------------

        row = connection.execute(
            """
            SELECT risk_score
            FROM devices
            WHERE device_id = ?
            """,
            (device_id,)
        ).fetchone()

        if not row:
            return 0.0

        previous_score = float(
            row["risk_score"] or 0.0
        )

        # --------------------------------------------------------
        # CALCULATE CURRENT RISK
        # --------------------------------------------------------

        new_score = _calculate_device_risk(
            connection,
            device_id,
            now
        )

        new_score = round(
            max(0.0, min(100.0, new_score)),
            2
        )

        # --------------------------------------------------------
        # PERSIST DEVICE RISK
        # --------------------------------------------------------

        connection.execute(
            """
            UPDATE devices
            SET risk_score = ?
            WHERE device_id = ?
            """,
            (
                new_score,
                device_id
            )
        )

        # --------------------------------------------------------
        # RISK HISTORY
        # --------------------------------------------------------

        # Record meaningful changes only.
        # This prevents the risk_history table from being flooded
        # by identical API refreshes.
        if abs(new_score - previous_score) >= 0.01:

            connection.execute(
                """
                INSERT INTO risk_history (
                    device_id,
                    timestamp,
                    risk_score,
                    reason
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    device_id,
                    now_iso,
                    new_score,
                    reason
                )
            )

        connection.commit()

        logger.info(
            "[RISK-REFRESH] Device=%s | "
            "Previous=%.2f | Current=%.2f | Reason=%s",
            device_id,
            previous_score,
            new_score,
            reason
        )

        return new_score

    finally:
        connection.close()

def upsert_risk_condition(
    device_id: str,
    telemetry_type: str,
    detection: Dict[str, Any]
) -> str:
    """
    Create or reinforce one stable security condition.

    A condition survives across telemetry snapshots while the
    underlying behavior continues to be observed.
    """

    condition_key = str(
        detection.get("condition_key")
        or detection.get("signal_key")
        or detection.get("fingerprint")
        or f"{device_id}|{telemetry_type}|"
           f"{detection.get('rule_id', 'UNKNOWN')}|"
           f"{detection.get('title', 'Security detection')}"
    )

    now = utc_now()

    connection = get_connection()

    try:
        existing = connection.execute(
            """
            SELECT
                occurrence_count,
                first_seen,
                state
            FROM risk_conditions
            WHERE device_id = ?
              AND condition_key = ?
            """,
            (device_id, condition_key)
        ).fetchone()

        if existing:

            previous_state = str(
                existing["state"] or ""
            ).upper()

            occurrence_count = (
                int(existing["occurrence_count"] or 1)
                + 1
            )

            new_state = (
                "REINFORCED"
                if previous_state in (
                    "ACTIVE",
                    "REINFORCED",
                    "RESOLVING"
                )
                else "ACTIVE"
            )

            connection.execute(
                """
                UPDATE risk_conditions
                SET
                    source_type = ?,
                    rule_id = ?,
                    title = ?,
                    category = ?,
                    severity = ?,
                    confidence = ?,
                    mitre_id = ?,
                    state = ?,
                    risk_contribution = ?,
                    last_seen = ?,
                    occurrence_count = ?,
                    evidence = ?
                WHERE device_id = ?
                  AND condition_key = ?
                """,
                (
                    telemetry_type,
                    detection.get("rule_id", "UNKNOWN"),
                    detection.get(
                        "title",
                        "Security detection"
                    ),
                    detection.get("category"),
                    detection.get("severity", "LOW"),
                    detection.get("confidence"),
                    detection.get("mitre_id"),
                    new_state,
                    float(
                        detection.get("risk", 0) or 0
                    ),
                    now,
                    occurrence_count,
                    json.dumps(
                        detection.get("evidence", []),
                        default=str
                    ),
                    device_id,
                    condition_key
                )
            )

            logger.info(
                "[RISK-CONDITION-%s] %s | %s | "
                "occurrences=%s",
                new_state,
                detection.get("rule_id", "UNKNOWN"),
                detection.get(
                    "title",
                    "Security detection"
                ),
                occurrence_count
            )

        else:

            connection.execute(
                """
                INSERT INTO risk_conditions (
                    condition_key,
                    device_id,
                    source_type,
                    rule_id,
                    title,
                    category,
                    severity,
                    confidence,
                    mitre_id,
                    state,
                    risk_contribution,
                    first_seen,
                    last_seen,
                    occurrence_count,
                    evidence
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, 'NEW',
                    ?, ?, ?, 1, ?
                )
                """,
                (
                    condition_key,
                    device_id,
                    telemetry_type,
                    detection.get("rule_id", "UNKNOWN"),
                    detection.get(
                        "title",
                        "Security detection"
                    ),
                    detection.get("category"),
                    detection.get("severity", "LOW"),
                    detection.get("confidence"),
                    detection.get("mitre_id"),
                    float(
                        detection.get("risk", 0) or 0
                    ),
                    now,
                    now,
                    json.dumps(
                        detection.get("evidence", []),
                        default=str
                    )
                )
            )

            logger.warning(
                "[RISK-CONDITION-NEW] %s | %s",
                detection.get("rule_id", "UNKNOWN"),
                detection.get(
                    "title",
                    "Security detection"
                )
            )

        connection.commit()

        return condition_key

    finally:
        connection.close()


def reconcile_condition_source(
    device_id: str,
    telemetry_type: str,
    observed_condition_keys: List[str]
) -> None:
    """
    Reconcile only the conditions belonging to the telemetry
    source that was just observed.

    This prevents a process snapshot from incorrectly resolving
    an unrelated network condition, and vice versa.
    """

    observed = set(
        str(key)
        for key in observed_condition_keys
        if key
    )

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT condition_key
            FROM risk_conditions
            WHERE device_id = ?
              AND source_type = ?
              AND state != 'RESOLVED'
            """,
            (
                device_id,
                telemetry_type
            )
        ).fetchall()

        now = datetime.now(timezone.utc)

        for row in rows:

            condition_key = row["condition_key"]

            if condition_key in observed:
                continue

            condition = connection.execute(
                """
                SELECT last_seen, state, rule_id, title
                FROM risk_conditions
                WHERE device_id = ?
              AND condition_key = ?
                """,
                (device_id, condition_key)
            ).fetchone()

            if not condition:
                continue

            last_seen = _parse_timestamp(
                condition["last_seen"]
            )

            if not last_seen:
                continue

            age_seconds = (
                now - last_seen
            ).total_seconds()

            if age_seconds >= RISK_CONDITION_STALE_SECONDS:

                connection.execute(
                    """
                    UPDATE risk_conditions
                    SET state = 'RESOLVED'
                    WHERE device_id = ?
                      AND condition_key = ?
                    """,
                    (device_id, condition_key)
                )

            elif age_seconds >= RISK_CONDITION_RESOLVING_SECONDS:

                connection.execute(
                    """
                    UPDATE risk_conditions
                    SET state = 'RESOLVING'
                    WHERE device_id = ?
                      AND condition_key = ?
                    """,
                    (device_id, condition_key)
                )

        connection.commit()

    finally:
        connection.close()


def update_device_risk(
    device_id: str,
    risk_increment: float,
    reason: str,
    detection: Optional[Dict[str, Any]] = None,
    telemetry_type: str = "unknown"
) -> float:
    """
    Compatibility wrapper for callers that still use the old
    update_device_risk() interface.

    New code should pass detection so risk is condition-based.
    """

    if detection is not None:

        condition = dict(detection)

        if not condition.get("condition_key"):
            condition["condition_key"] = (
                condition.get("signal_key")
                or condition.get("fingerprint")
                or f"{device_id}|{telemetry_type}|"
                   f"{condition.get('rule_id', 'UNKNOWN')}|"
                   f"{condition.get('title', reason)}"
            )

        condition["risk"] = float(
            condition.get(
                "risk",
                risk_increment
            ) or 0
        )

        upsert_risk_condition(
            device_id,
            telemetry_type,
            condition
        )

        return refresh_device_risk(
            device_id,
            reason=f"condition observed: {reason}"
        )

    # Legacy fallback: record a synthetic one-shot condition.
    synthetic = {
        "condition_key": (
            f"{device_id}|legacy|{reason}"
        ),
        "rule_id": "LEGACY",
        "title": reason,
        "category": "legacy",
        "severity": "LOW",
        "confidence": "MEDIUM",
        "risk": risk_increment,
        "evidence": []
    }

    upsert_risk_condition(
        device_id,
        telemetry_type,
        synthetic
    )

    return refresh_device_risk(
        device_id,
        reason=f"legacy condition observed: {reason}"
    )


# ============================================================
# ALERT LIFECYCLE
# ============================================================

def resolve_stale_alerts(
    device_id: str,
    stale_after_seconds: int = 60
) -> int:
    """
    Resolve open alerts whose detection has not been observed
    within the configured stale window.

    Historical records are preserved.

    Only OPEN alerts are automatically resolved.
    ACKNOWLEDGED alerts remain acknowledged until a human
    explicitly changes their state.
    """

    now = datetime.now(timezone.utc)

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                alert_id,
                last_seen,
                title,
                rule_id
            FROM alerts
            WHERE device_id = ?
              AND status = 'open'
            """,
            (device_id,)
        ).fetchall()

        resolved_count = 0

        for row in rows:
            last_seen = row["last_seen"]

            if not last_seen:
                continue

            try:
                last_seen_dt = datetime.fromisoformat(last_seen)

                if last_seen_dt.tzinfo is None:
                    last_seen_dt = last_seen_dt.replace(
                        tzinfo=timezone.utc
                    )

                age_seconds = (
                    now - last_seen_dt
                ).total_seconds()

            except Exception:
                continue

            if age_seconds >= stale_after_seconds:
                connection.execute(
                    """
                    UPDATE alerts
                    SET status = 'resolved'
                    WHERE alert_id = ?
                      AND status = 'open'
                    """,
                    (row["alert_id"],)
                )

                resolved_count += 1

                logger.info(
                    "[ALERT-RESOLVED] %s | %s | "
                    "last_seen_age=%.1fs",
                    row["rule_id"],
                    row["title"],
                    age_seconds
                )

        connection.commit()

        return resolved_count

    finally:
        connection.close()

# ============================================================
# ALERT ENGINE
# ============================================================

def create_alert(
    device_id: str,
    detection: Dict[str, Any],
    risk_score: float
):
    """
    Alert Engine v0.5

    Alerts are keyed by a stable fingerprint:
        device + rule + title

    Repeated observations of the same active condition update
    the existing alert instead of creating another alert.
    """

    timestamp = utc_now()

    severity = detection.get(
        "severity",
        "LOW"
    )

    title = detection.get(
        "title",
        "Security event"
    )

    rule_id = detection.get(
        "rule_id",
        "UNKNOWN"
    )

    evidence = detection.get(
        "evidence",
        {}
    )

    fingerprint = (
        f"{device_id}|{rule_id}|{title}"
    )

    connection = get_connection()

    # --------------------------------------------------------
    # ACTIVE ALERT LOOKUP
    # --------------------------------------------------------

    existing = connection.execute(
        """
        SELECT
            alert_id,
            occurrence_count,
            first_seen,
            last_seen
        FROM alerts
        WHERE fingerprint = ?
          AND status IN ('open', 'acknowledged')
        ORDER BY id DESC
        LIMIT 1
        """,
        (fingerprint,)
    ).fetchone()

    if existing:

        occurrence_count = (
            int(existing["occurrence_count"] or 1)
            + 1
        )

        connection.execute(
            """
            UPDATE alerts
            SET
                last_seen = ?,
                occurrence_count = ?,
                risk_score = ?,
                severity = ?,
                evidence = ?
            WHERE alert_id = ?
            """,
            (
                timestamp,
                occurrence_count,
                risk_score,
                severity,
                json.dumps(
                    evidence,
                    default=str
                ),
                existing["alert_id"]
            )
        )

        connection.commit()
        connection.close()

        logger.info(
            "[ALERT-DEDUPE] %s | %s | occurrences=%s",
            severity,
            title,
            occurrence_count
        )

        return {
            "alert_id": existing["alert_id"],
            "deduplicated": True,
            "occurrence_count": occurrence_count
        }

    # --------------------------------------------------------
    # CREATE NEW ALERT
    # --------------------------------------------------------

    alert_id = str(uuid.uuid4())

    connection.execute(
        """
        INSERT INTO alerts (
            alert_id,
            device_id,
            timestamp,
            severity,
            title,
            description,
            rule_id,
            risk_score,
            status,
            evidence,
            fingerprint,
            first_seen,
            last_seen,
            occurrence_count
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, 1)
        """,
        (
            alert_id,
            device_id,
            timestamp,
            severity,
            title,
            detection.get(
                "description",
                ""
            ),
            rule_id,
            risk_score,
            json.dumps(
                evidence,
                default=str
            ),
            fingerprint,
            timestamp,
            timestamp
        )
    )

    connection.commit()
    connection.close()

    logger.warning(
        "[ALERT] %s | %s | Device=%s | Risk=%.1f",
        severity,
        title,
        device_id,
        risk_score
    )

    return {
        "alert_id": alert_id,
        "deduplicated": False,
        "occurrence_count": 1
    }


# ============================================================
# INCIDENT CORRELATION
# ============================================================

def _load_active_conditions_for_device(device_id: str) -> List[Dict[str, Any]]:
    connection = get_connection()
    try:
        rows = _active_condition_rows(connection, device_id)
        return [_condition_dict_from_row(row) for row in rows]
    finally:
        connection.close()


def upsert_incident(device_id: str, candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Persist one correlated incident candidate and advance its lifecycle."""
    incident_key = str(candidate["incident_key"])
    now = utc_now()
    connection = get_connection()

    try:
        existing = connection.execute(
            "SELECT state, occurrence_count, first_seen FROM incidents WHERE incident_key = ?",
            (incident_key,)
        ).fetchone()

        if existing:
            previous_state = str(existing["state"] or "").upper()
            occurrence_count = int(existing["occurrence_count"] or 1) + 1
            if previous_state == "NEW":
                state = "ACTIVE"
            elif previous_state in ("ACTIVE", "REINFORCED", "RESOLVING"):
                state = "REINFORCED"
            else:
                state = "ACTIVE"
            first_seen = existing["first_seen"] or candidate["first_seen"] or now

            connection.execute(
                """
                UPDATE incidents SET
                    title = ?, category = ?, description = ?, severity = ?,
                    confidence = ?, attack_stage = ?, mitre_id = ?, state = ?,
                    risk_score = ?, base_risk = ?, correlation_bonus = ?,
                    last_seen = ?, occurrence_count = ?, condition_count = ?,
                    condition_keys = ?, evidence = ?, rationale = ?,
                    source_types = ?, users = ?, processes = ?, destinations = ?,
                    updated_at = ?
                WHERE incident_key = ?
                """,
                (
                    candidate["title"], candidate.get("category"), candidate.get("description"),
                    candidate.get("severity"), candidate.get("confidence"), candidate.get("attack_stage"),
                    candidate.get("mitre_id"), state, float(candidate.get("risk_score", 0)),
                    float(candidate.get("base_risk", 0)), float(candidate.get("correlation_bonus", 0)),
                    candidate.get("last_seen") or now, occurrence_count,
                    int(candidate.get("condition_count", 0)), json.dumps(candidate.get("condition_keys", [])),
                    json.dumps(candidate.get("evidence", []), default=str),
                    json.dumps(candidate.get("rationale", []), default=str),
                    json.dumps(candidate.get("source_types", [])), json.dumps(candidate.get("users", [])),
                    json.dumps(candidate.get("processes", [])), json.dumps(candidate.get("destinations", [])),
                    now, incident_key
                )
            )
        else:
            occurrence_count = 1
            state = "NEW"
            first_seen = candidate.get("first_seen") or now
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_key, device_id, correlation_rule_id, title, category,
                    description, severity, confidence, attack_stage, mitre_id, state,
                    risk_score, base_risk, correlation_bonus, first_seen, last_seen,
                    occurrence_count, condition_count, condition_keys, evidence,
                    rationale, source_types, users, processes, destinations,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_key, device_id, candidate["correlation_rule_id"], candidate["title"],
                    candidate.get("category"), candidate.get("description"), candidate.get("severity"),
                    candidate.get("confidence"), candidate.get("attack_stage"), candidate.get("mitre_id"),
                    state, float(candidate.get("risk_score", 0)), float(candidate.get("base_risk", 0)),
                    float(candidate.get("correlation_bonus", 0)), first_seen, candidate.get("last_seen") or now,
                    occurrence_count, int(candidate.get("condition_count", 0)),
                    json.dumps(candidate.get("condition_keys", [])), json.dumps(candidate.get("evidence", []), default=str),
                    json.dumps(candidate.get("rationale", []), default=str), json.dumps(candidate.get("source_types", [])),
                    json.dumps(candidate.get("users", [])), json.dumps(candidate.get("processes", [])),
                    json.dumps(candidate.get("destinations", [])), now, now
                )
            )

        connection.commit()
        return {
            **candidate,
            "state": state,
            "occurrence_count": occurrence_count,
            "first_seen": first_seen,
        }
    finally:
        connection.close()


def refresh_incidents(device_id: str) -> List[Dict[str, Any]]:
    """Correlate current conditions and persist/update incident state."""
    conditions = _load_active_conditions_for_device(device_id)
    candidates = correlate(device_id, conditions)

    persisted = [upsert_incident(device_id, candidate) for candidate in candidates]

    connection = get_connection()
    try:
        _refresh_incident_states(connection, device_id)
        connection.commit()
    finally:
        connection.close()

    return persisted


def get_incidents_for_device(
    device_id: str,
    include_resolved: bool = False,
) -> List[Dict[str, Any]]:
    connection = get_connection()
    try:
        _refresh_incident_states(connection, device_id)
        connection.commit()

        query = "SELECT * FROM incidents WHERE device_id = ?"
        params: List[Any] = [device_id]
        if not include_resolved:
            query += " AND state != 'RESOLVED'"
        query += " ORDER BY id DESC"

        rows = connection.execute(query, params).fetchall()
        result = []
        for row in rows:
            result.append({
                "incident_key": row["incident_key"],
                "device_id": row["device_id"],
                "correlation_rule_id": row["correlation_rule_id"],
                "title": row["title"],
                "category": row["category"],
                "description": row["description"],
                "severity": row["severity"],
                "confidence": row["confidence"],
                "attack_stage": row["attack_stage"],
                "mitre_id": row["mitre_id"],
                "state": row["state"],
                "risk_score": row["risk_score"],
                "effective_risk": _incident_effective_risk(row),
                "base_risk": row["base_risk"],
                "correlation_bonus": row["correlation_bonus"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "occurrence_count": row["occurrence_count"] or 1,
                "condition_count": row["condition_count"] or 0,
                "condition_keys": parse_json(row["condition_keys"]),
                "evidence": parse_json(row["evidence"]),
                "rationale": parse_json(row["rationale"]),
                "source_types": parse_json(row["source_types"]),
                "users": parse_json(row["users"]),
                "processes": parse_json(row["processes"]),
                "destinations": parse_json(row["destinations"]),
                "engine_version": CORRELATION_ENGINE_VERSION,
            })
        return result
    finally:
        connection.close()


# ============================================================
# TELEMETRY PROCESSING
# ============================================================

def store_telemetry(data: Telemetry):

    timestamp = data.timestamp or utc_now()
    event_id = data.event_id or str(uuid.uuid4())
    received_at = utc_now()

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO telemetry (
                event_id, device_id, timestamp, telemetry_type,
                agent_version, payload, received_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id, data.device_id, timestamp, data.telemetry_type,
                data.agent_version, json.dumps(data.payload, default=str), received_at
            )
        )
    except sqlite3.IntegrityError:
        connection.close()
        logger.info("Duplicate telemetry ignored: %s", event_id)
        return {"stored": False, "duplicate": True, "event_id": event_id}

    connection.commit()
    connection.close()

    register_or_update_device(
        device_id=data.device_id,
        telemetry_type=data.telemetry_type,
        payload=data.payload,
        timestamp=timestamp,
        agent_version=data.agent_version
    )

    detections = run_detection(
        device_id=data.device_id,
        telemetry_type=data.telemetry_type,
        payload=data.payload,
        current_event_id=event_id,
    )

    observed_condition_keys = []

    for detection in detections:
        condition_key = upsert_risk_condition(
            device_id=data.device_id,
            telemetry_type=data.telemetry_type,
            detection=detection
        )
        observed_condition_keys.append(condition_key)

    # Conditions absent from the telemetry snapshot begin resolving.
    reconcile_condition_source(
        device_id=data.device_id,
        telemetry_type=data.telemetry_type,
        observed_condition_keys=observed_condition_keys
    )

    # Correlate the complete current condition set after reconciliation.
    incidents = refresh_incidents(data.device_id)

    # Device risk is now incident-aware. Correlated conditions are not counted
    # a second time underneath the incident.
    final_risk = refresh_device_risk(
        device_id=data.device_id,
        reason="telemetry correlation and risk refresh"
    )

    created_alerts = []

    # A network scan is the primary behavioral story. Individual rare
    # destinations observed in the same telemetry snapshot remain stored as
    # risk conditions and forensic evidence, but they should not create a
    # separate operator alert for every destination when the scan already
    # explains them.
    has_network_scan = any(
        detection.get("rule_id") == "NET-SCAN-001"
        for detection in detections
    )

    for detection in detections:
        if (
            has_network_scan
            and detection.get("rule_id") == "NET-RARE-DEST-001"
        ):
            logger.info(
                "[ALERT-SUPPRESSED] NET-RARE-DEST-001 is supporting evidence "
                "for NET-SCAN-001 | Device=%s",
                data.device_id,
            )
            continue

        condition_key = str(
            detection.get("condition_key")
            or detection.get("signal_key")
            or detection.get("fingerprint")
            or ""
        )
        alert_result = create_alert(
            device_id=data.device_id,
            detection=detection,
            risk_score=final_risk
        )
        created_alerts.append({
            "alert_id": alert_result["alert_id"],
            "rule_id": detection.get("rule_id"),
            "severity": detection.get("severity"),
            "title": detection.get("title"),
            "risk_score": final_risk,
            "deduplicated": alert_result["deduplicated"],
            "occurrence_count": alert_result["occurrence_count"],
            "condition_key": condition_key,
            "condition_state": detection.get("condition_state", "ACTIVE")
        })

    resolved_alerts = resolve_stale_alerts(
        device_id=data.device_id,
        stale_after_seconds=60
    )

    return {
        "stored": True,
        "duplicate": False,
        "event_id": event_id,
        "detections": len(detections),
        "alerts": created_alerts,
        "incidents": incidents,
        "risk_score": final_risk,
        "risk_level": risk_level(final_risk),
        "active_conditions": len(observed_condition_keys),
        "active_incidents": len([
            i for i in incidents
            if i.get("state") in ("NEW", "ACTIVE", "REINFORCED", "RESOLVING")
        ]),
        "resolved_alerts": resolved_alerts
    }


# ============================================================
# API ROUTES
# ============================================================


@app.get("/")
def root():

    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "architecture": "custom-in-house-security-monitor"
    }


# ------------------------------------------------------------
# HEALTH
# ------------------------------------------------------------

@app.get("/api/health")
def health():

    connection = get_connection()

    telemetry_count = connection.execute(
        "SELECT COUNT(*) AS count FROM telemetry"
    ).fetchone()["count"]

    device_count = connection.execute(
        "SELECT COUNT(*) AS count FROM devices"
    ).fetchone()["count"]

    open_alert_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM alerts
        WHERE status = 'open'
        """
    ).fetchone()["count"]

    connection.close()

    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "database": "connected",
        "telemetry_events": telemetry_count,
        "devices": device_count,
        "open_alerts": open_alert_count,
        "timestamp": utc_now()
    }


# ------------------------------------------------------------
# TELEMETRY INGESTION
# ------------------------------------------------------------

@app.post("/api/telemetry")
def receive_telemetry(data: Telemetry):

    logger.info(
        "Telemetry received | Device=%s | Type=%s | Agent=%s",
        data.device_id,
        data.telemetry_type,
        data.agent_version
    )

    try:

        result = store_telemetry(data)

        return {
            "status": "success",
            **result
        }

    except Exception as e:

        logger.exception(
            "Telemetry processing failed"
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ------------------------------------------------------------
# GET TELEMETRY
# ------------------------------------------------------------

@app.get("/api/telemetry")
def get_telemetry(
    device_id: Optional[str] = None,
    telemetry_type: Optional[str] = None,
    limit: int = Query(
        default=100,
        ge=1,
        le=1000
    )
):

    connection = get_connection()

    query = """
        SELECT
            t.id,
            t.event_id,
            t.device_id,
            d.hostname,
            t.timestamp,
            t.telemetry_type,
            t.agent_version,
            t.payload,
            t.received_at

        FROM telemetry t

        LEFT JOIN devices d
            ON d.device_id = t.device_id

        WHERE 1=1
    """

    params = []

    if device_id:
        query += """
            AND t.device_id = ?
        """
        params.append(device_id)

    if telemetry_type:
        query += """
            AND t.telemetry_type = ?
        """
        params.append(telemetry_type)

    query += """
        ORDER BY t.id DESC
        LIMIT ?
    """

    params.append(limit)

    rows = connection.execute(
        query,
        params
    ).fetchall()

    connection.close()

    results = []

    for row in rows:

        results.append(
            {
                "id": row["id"],
                "event_id": row["event_id"],
                "device_id": row["device_id"],
                "hostname": row["hostname"] or "Unknown",
                "timestamp": row["timestamp"],
                "telemetry_type": row["telemetry_type"],
                "agent_version": row["agent_version"],
                "payload": parse_json(row["payload"]),
                "received_at": row["received_at"]
            }
        )

    return {
        "count": len(results),
        "telemetry": results
    }


# ------------------------------------------------------------
# DEVICES
# ------------------------------------------------------------

@app.get("/api/devices")
def get_devices():
    """
    Return monitored endpoint inventory with the latest
    measured endpoint health telemetry.

    The backend remains the source of truth.

    Metrics are read from the latest telemetry generated
    by Angelmode. No values are invented by the dashboard.
    """

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM devices
            ORDER BY risk_score DESC, last_seen DESC
            """
        ).fetchall()

        devices = []

        for row in rows:

            device_id = row["device_id"]

            online = calculate_online(
                row["last_seen"]
            )

            # ====================================================
            # LATEST SYSTEM TELEMETRY
            # ====================================================

            system_row = connection.execute(
                """
                SELECT
                    timestamp,
                    received_at,
                    payload
                FROM telemetry
                WHERE device_id = ?
                  AND telemetry_type = 'system'
                ORDER BY id DESC
                LIMIT 1
                """,
                (device_id,)
            ).fetchone()

            system = {}

            if system_row:
                system = parse_json(
                    system_row["payload"]
                ) or {}

            cpu = system.get(
                "cpu",
                {}
            ) or {}

            memory = system.get(
                "memory",
                {}
            ) or {}

            disk = system.get(
                "disk",
                {}
            ) or {}

            # ====================================================
            # LATEST NETWORK TELEMETRY
            # ====================================================

            network_row = connection.execute(
                """
                SELECT
                    timestamp,
                    received_at,
                    payload
                FROM telemetry
                WHERE device_id = ?
                  AND telemetry_type = 'network'
                ORDER BY id DESC
                LIMIT 1
                """,
                (device_id,)
            ).fetchone()

            network = {}

            if network_row:
                network = parse_json(
                    network_row["payload"]
                ) or {}

            # ====================================================
            # BUILD DEVICE RESPONSE
            # ====================================================

            # Reconcile stale conditions before rendering the
            # device risk. This keeps the API source of truth
            # accurate even when no new detection arrives.
            refresh_device_risk(
                device_id,
                reason="device inventory risk refresh"
            )

            refreshed_row = connection.execute(
                """
                SELECT risk_score
                FROM devices
                WHERE device_id = ?
                """,
                (device_id,)
            ).fetchone()

            risk_score_value = float(
                refreshed_row["risk_score"] or 0
            ) if refreshed_row else 0.0

            devices.append(
                {
                    "device_id": row["device_id"],
                    "hostname": row["hostname"],
                    "username": row["username"],

                    "platform": row["platform"],
                    "platform_version": row["platform_version"],
                    "platform_release": row["platform_release"],

                    "machine": row["machine"],
                    "processor": row["processor"],

                    "agent_version": row["agent_version"],

                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],

                    "status": (
                        "online"
                        if online
                        else "offline"
                    ),

                    # =================================================
                    # BACKEND-OWNED RISK
                    # =================================================

                    "risk_score": round(
                        risk_score_value,
                        2
                    ),

                    "risk_level": risk_level(
                        risk_score_value
                    ),

                    # =================================================
                    # LATEST ENDPOINT HEALTH
                    # =================================================

                    "cpu_percent": cpu.get(
                        "percent"
                    ),

                    "memory_percent": memory.get(
                        "percent"
                    ),

                    "disk_percent": disk.get(
                        "percent"
                    ),

                    "process_count": system.get(
                        "process_count"
                    ),

                    "network_connections": network.get(
                        "connection_count"
                    ),

                    # =================================================
                    # TELEMETRY FRESHNESS
                    # =================================================

                    "system_telemetry_timestamp": (
                        system_row["timestamp"]
                        if system_row
                        else None
                    ),

                    "network_telemetry_timestamp": (
                        network_row["timestamp"]
                        if network_row
                        else None
                    ),

                    "system_telemetry_received_at": (
                        system_row["received_at"]
                        if system_row
                        else None
                    ),

                    "network_telemetry_received_at": (
                        network_row["received_at"]
                        if network_row
                        else None
                    )
                }
            )

        return {
            "count": len(devices),
            "devices": devices
        }

    finally:
        connection.close()

# ------------------------------------------------------------
# SINGLE DEVICE
# ------------------------------------------------------------

@app.get("/api/devices/{device_id}")
def get_device(device_id: str):

    connection = get_connection()

    device = connection.execute(
        """
        SELECT *
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,)
    ).fetchone()

    connection.close()

    if not device:

        raise HTTPException(
            status_code=404,
            detail="Device not found"
        )

    return {
        "device_id": device["device_id"],
        "hostname": device["hostname"],
        "username": device["username"],
        "platform": device["platform"],
        "platform_version": device["platform_version"],
        "platform_release": device["platform_release"],
        "machine": device["machine"],
        "processor": device["processor"],
        "agent_version": device["agent_version"],
        "first_seen": device["first_seen"],
        "last_seen": device["last_seen"],
        "status": (
            "online"
            if calculate_online(device["last_seen"])
            else "offline"
        ),
        "risk_score": device["risk_score"]
    }


# ------------------------------------------------------------
# DEVICE TELEMETRY
# ------------------------------------------------------------

@app.get("/api/devices/{device_id}/telemetry")
def get_device_telemetry(
    device_id: str,
    telemetry_type: Optional[str] = None,
    limit: int = Query(
        default=100,
        ge=1,
        le=1000
    )
):

    return get_telemetry(
        device_id=device_id,
        telemetry_type=telemetry_type,
        limit=limit
    )


# ------------------------------------------------------------
# DEVICE RISK
# ------------------------------------------------------------

@app.get("/api/devices/{device_id}/risk")
def get_device_risk(device_id: str):
    """
    Return the current risk state and risk history for a device.

    Risk is recalculated from the current condition/incident state
    before the response is returned so the API remains authoritative.
    """
    refresh_device_risk(
        device_id,
        reason="risk API refresh"
    )

    connection = get_connection()

    try:
        device = connection.execute(
            """
            SELECT
                device_id,
                hostname,
                risk_score
            FROM devices
            WHERE device_id = ?
            """,
            (device_id,)
        ).fetchone()

        if not device:
            raise HTTPException(
                status_code=404,
                detail="Device not found"
            )

        history_rows = connection.execute(
            """
            SELECT
                timestamp,
                risk_score,
                reason
            FROM risk_history
            WHERE device_id = ?
            ORDER BY timestamp DESC
            LIMIT 50
            """,
            (device_id,)
        ).fetchall()

        risk_score_value = float(
            device["risk_score"] or 0.0
        )

        return {
            "device_id": device["device_id"],
            "hostname": device["hostname"],
            "risk_score": round(risk_score_value, 2),
            "risk_level": risk_level(risk_score_value),
            "history": [
                {
                    "timestamp": row["timestamp"],
                    "risk_score": round(
                        float(row["risk_score"] or 0.0),
                        2
                    ),
                    "reason": row["reason"]
                }
                for row in history_rows
            ]
        }

    finally:
        connection.close()

# ============================================================
# DEVICE RISK CONDITIONS
# ============================================================

@app.get("/api/devices/{device_id}/conditions")
def get_device_conditions(
    device_id: str,
    include_resolved: bool = False
):
    """
    Return the condition state behind the device risk score.

    This makes Godmode explainable: every risk score can be traced
    back to active or recently resolved conditions.
    """

    # Refresh before returning so stale conditions do not remain
    # falsely active just because no new telemetry arrived.
    refresh_device_risk(
        device_id,
        reason="condition API refresh"
    )

    connection = get_connection()

    try:
        device = connection.execute(
            """
            SELECT device_id, hostname, risk_score
            FROM devices
            WHERE device_id = ?
            """,
            (device_id,)
        ).fetchone()

        if not device:
            raise HTTPException(
                status_code=404,
                detail="Device not found"
            )

        query = """
            SELECT *
            FROM risk_conditions
            WHERE device_id = ?
        """

        params = [device_id]

        if not include_resolved:
            query += """
                AND state != 'RESOLVED'
            """

        query += """
            ORDER BY
                CASE state
                    WHEN 'REINFORCED' THEN 1
                    WHEN 'ACTIVE' THEN 2
                    WHEN 'NEW' THEN 3
                    WHEN 'RESOLVING' THEN 4
                    ELSE 5
                END,
                last_seen DESC
        """

        rows = connection.execute(
            query,
            params
        ).fetchall()

        conditions = []

        for row in rows:

            conditions.append(
                {
                    "condition_key": row["condition_key"],
                    "device_id": row["device_id"],
                    "source_type": row["source_type"],
                    "rule_id": row["rule_id"],
                    "title": row["title"],
                    "category": row["category"],
                    "severity": row["severity"],
                    "confidence": row["confidence"],
                    "mitre_id": row["mitre_id"],
                    "state": row["state"],
                    "risk_contribution": row[
                        "risk_contribution"
                    ],
                    "effective_risk": round(
                        _condition_effective_risk(row),
                        2
                    ),
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "occurrence_count": (
                        row["occurrence_count"] or 1
                    ),
                    "evidence": parse_json(
                        row["evidence"]
                    )
                }
            )

        return {
            "device_id": device["device_id"],
            "hostname": device["hostname"],
            "risk_score": float(
                device["risk_score"] or 0
            ),
            "risk_level": risk_level(
                device["risk_score"]
            ),
            "count": len(conditions),
            "conditions": conditions,
            "correlation_engine_version": CORRELATION_ENGINE_VERSION
        }

    finally:
        connection.close()


# ============================================================
# INCIDENTS
# ============================================================

@app.get("/api/devices/{device_id}/incidents")
def get_device_incidents(
    device_id: str,
    include_resolved: bool = False,
):
    """Return correlated security incidents for a device."""
    connection = get_connection()
    try:
        device = connection.execute(
            "SELECT device_id, hostname FROM devices WHERE device_id = ?",
            (device_id,)
        ).fetchone()
    finally:
        connection.close()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    incidents = get_incidents_for_device(device_id, include_resolved)
    active = [
        i for i in incidents
        if i["state"] in ("NEW", "ACTIVE", "REINFORCED", "RESOLVING")
    ]

    return {
        "device_id": device_id,
        "hostname": device["hostname"],
        "count": len(incidents),
        "active_count": len(active),
        "incidents": incidents,
    }


@app.get("/api/correlation/rules")
def get_correlation_catalogue():
    """Expose the active correlation catalogue for Godmode introspection."""
    from backend.correlation import get_correlation_rules
    return {
        "engine_version": CORRELATION_ENGINE_VERSION,
        "count": len(get_correlation_rules()),
        "rules": get_correlation_rules(),
    }


# ============================================================
# ALERTS
# ============================================================

@app.get("/api/alerts")
def get_alerts(
    device_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(
        default=100,
        ge=1,
        le=1000
    )
):

    connection = get_connection()

    query = """
        SELECT *
        FROM alerts
        WHERE 1=1
    """

    params = []

    if device_id:

        query += """
            AND device_id = ?
        """

        params.append(device_id)

    if severity:

        query += """
            AND severity = ?
        """

        params.append(severity.upper())

    if status:

        query += """
            AND status = ?
        """

        params.append(status)

    query += """
        ORDER BY id DESC
        LIMIT ?
    """

    params.append(limit)

    rows = connection.execute(
        query,
        params
    ).fetchall()

    connection.close()

    alerts = []

    for row in rows:

        alerts.append(
            {
                "id": row["id"],
                "alert_id": row["alert_id"],
                "device_id": row["device_id"],
                "timestamp": row["timestamp"],
                "severity": row["severity"],
                "title": row["title"],
                "description": row["description"],
                "rule_id": row["rule_id"],
                "risk_score": row["risk_score"],
                "status": row["status"],
                "evidence": parse_json(row["evidence"]),
                "fingerprint": row["fingerprint"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "occurrence_count": row["occurrence_count"] or 1
            }
        )

    return {
        "count": len(alerts),
        "alerts": alerts
    }


# ------------------------------------------------------------
# UPDATE ALERT
# ------------------------------------------------------------

@app.patch("/api/alerts/{alert_id}")
def update_alert(
    alert_id: str,
    update: AlertStatusUpdate
):

    allowed_statuses = {
        "open",
        "acknowledged",
        "resolved",
        "dismissed",
        "deduplicated"
    }

    if update.status not in allowed_statuses:

        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid status. Allowed values: "
                + ", ".join(sorted(allowed_statuses))
            )
        )

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE alerts

        SET status = ?

        WHERE alert_id = ?
        """,
        (
            update.status,
            alert_id
        )
    )

    if cursor.rowcount == 0:

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    connection.commit()
    connection.close()

    return {
        "status": "success",
        "alert_id": alert_id,
        "new_status": update.status
    }


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.get("/api/stats")
def get_stats():
    """
    Return measured security-console metrics.

    IMPORTANT:
    The backend is the source of truth for risk classification,
    telemetry freshness, alert state and ingestion rate.
    The dashboard only renders these values.
    """

    connection = get_connection()

    try:
        # ========================================================
        # DEVICE COUNTS
        # ========================================================

        total_devices = connection.execute(
            """
            SELECT COUNT(*)
            FROM devices
            """
        ).fetchone()[0]

        device_rows = connection.execute(
            """
            SELECT
                device_id,
                last_seen,
                risk_score
            FROM devices
            """
        ).fetchall()

        online_devices = sum(
            1
            for row in device_rows
            if calculate_online(row["last_seen"])
        )

        offline_devices = total_devices - online_devices

        # ========================================================
        # TELEMETRY
        # ========================================================

        total_telemetry = connection.execute(
            """
            SELECT COUNT(*)
            FROM telemetry
            """
        ).fetchone()[0]

        now = datetime.now(timezone.utc)

        five_minutes_ago = (
            now - timedelta(minutes=5)
        ).isoformat()

        recent_telemetry = connection.execute(
            """
            SELECT COUNT(*)
            FROM telemetry
            WHERE received_at >= ?
            """,
            (five_minutes_ago,)
        ).fetchone()[0]

        latest_telemetry = connection.execute(
            """
            SELECT
                timestamp,
                received_at,
                device_id,
                telemetry_type
            FROM telemetry
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

        # ========================================================
        # ALERTS
        # ========================================================

        total_alerts = connection.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            """
        ).fetchone()[0]

        open_alerts = connection.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'open'
            """
        ).fetchone()[0]

        acknowledged_alerts = connection.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'acknowledged'
            """
        ).fetchone()[0]

        deduplicated_alerts = connection.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'deduplicated'
            """
        ).fetchone()[0]

        # Active = alerts that still require attention.
        active_alerts = (
            open_alerts +
            acknowledged_alerts
        )

        severity_counts = {}

        for severity in (
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ):
            severity_counts[
                severity.lower()
            ] = connection.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = ?
                  AND status IN ('open', 'acknowledged')
                """,
                (severity,)
            ).fetchone()[0]

        # ========================================================
        # RISK
        # ========================================================

        # Reconcile condition freshness before exposing aggregate
        # risk. Dashboard values remain backend-owned.
        for row in device_rows:
            refresh_device_risk(
                row["device_id"],
                reason="stats risk refresh"
            )

        refreshed_risk_rows = connection.execute(
            """
            SELECT risk_score
            FROM devices
            """
        ).fetchall()

        risk_scores = [
            float(row["risk_score"] or 0)
            for row in refreshed_risk_rows
        ]

        max_risk = max(
            risk_scores,
            default=0.0
        )

        active_conditions = connection.execute(
            """
            SELECT COUNT(*)
            FROM risk_conditions
            WHERE state IN (
                'NEW',
                'ACTIVE',
                'REINFORCED',
                'RESOLVING'
            )
            """
        ).fetchone()[0]

        resolving_conditions = connection.execute(
            """
            SELECT COUNT(*)
            FROM risk_conditions
            WHERE state = 'RESOLVING'
            """
        ).fetchone()[0]

        # Incident state is the correlated risk layer above conditions.
        active_incidents = connection.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE state IN ('NEW', 'ACTIVE', 'REINFORCED', 'RESOLVING')
            """
        ).fetchone()[0]

        resolving_incidents = connection.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE state = 'RESOLVING'
            """
        ).fetchone()[0]

        total_incidents = connection.execute(
            "SELECT COUNT(*) FROM incidents"
        ).fetchone()[0]

        # ========================================================
        # TELEMETRY FRESHNESS
        # ========================================================

        latest_age_seconds = None

        if latest_telemetry:
            received_at = latest_telemetry["received_at"]

            if received_at:
                try:
                    latest_dt = datetime.fromisoformat(
                        received_at
                    )

                    if latest_dt.tzinfo is None:
                        latest_dt = latest_dt.replace(
                            tzinfo=timezone.utc
                        )

                    latest_age_seconds = max(
                        0,
                        (
                            now - latest_dt
                        ).total_seconds()
                    )

                except Exception:
                    latest_age_seconds = None

        # ========================================================
        # CONSOLE STATUS
        # ========================================================

        console_status = "healthy"

        if latest_age_seconds is not None:
            if latest_age_seconds > 300:
                console_status = "stale"

        # ========================================================
        # RETURN
        # ========================================================

        return {
            "console": {
                "status": console_status,
                "version": APP_VERSION,
                "timestamp": utc_now()
            },

            "devices": {
                "total": total_devices,
                "online": online_devices,
                "offline": offline_devices
            },

            "telemetry": {
                "total": total_telemetry,
                "events_last_5m": recent_telemetry,
                "events_per_minute": round(
                    recent_telemetry / 5,
                    2
                ),
                "latest_timestamp": (
                    latest_telemetry["timestamp"]
                    if latest_telemetry
                    else None
                ),
                "latest_received_at": (
                    latest_telemetry["received_at"]
                    if latest_telemetry
                    else None
                ),
                "latest_device_id": (
                    latest_telemetry["device_id"]
                    if latest_telemetry
                    else None
                ),
                "latest_type": (
                    latest_telemetry["telemetry_type"]
                    if latest_telemetry
                    else None
                ),
                "latest_age_seconds": (
                    round(
                        latest_age_seconds,
                        1
                    )
                    if latest_age_seconds is not None
                    else None
                )
            },

            "alerts": {
                "total": total_alerts,
                "open": open_alerts,
                "active": active_alerts,
                "acknowledged": acknowledged_alerts,
                "deduplicated": deduplicated_alerts,
                **severity_counts
            },

            "risk": {
                "max": round(
                    max_risk,
                    2
                ),
                "level": risk_level(
                    max_risk
                )
            },

            "risk_conditions": {
                "active": active_conditions,
                "resolving": resolving_conditions
            },

            "incidents": {
                "total": total_incidents,
                "active": active_incidents,
                "resolving": resolving_incidents,
                "engine_version": CORRELATION_ENGINE_VERSION
            },

            "timestamp": utc_now()
        }

    finally:
        connection.close()
# ============================================================
# ENDPOINT HEALTH
# ============================================================

@app.get("/api/devices/{device_id}/health")
def get_device_health(
    device_id: str
):
    """
    Return the latest measured endpoint health telemetry.

    This endpoint exposes actual Angelmode measurements.
    It does not generate or estimate values.
    """

    connection = get_connection()

    try:
        # --------------------------------------------------------
        # VERIFY DEVICE
        # --------------------------------------------------------

        device = connection.execute(
            """
            SELECT
                device_id,
                hostname,
                status,
                agent_version,
                last_seen,
                risk_score
            FROM devices
            WHERE device_id = ?
            """,
            (device_id,)
        ).fetchone()

        if not device:
            raise HTTPException(
                status_code=404,
                detail="Device not found"
            )

        # --------------------------------------------------------
        # LATEST SYSTEM TELEMETRY
        # --------------------------------------------------------

        system_row = connection.execute(
            """
            SELECT
                timestamp,
                received_at,
                payload
            FROM telemetry
            WHERE device_id = ?
              AND telemetry_type = 'system'
            ORDER BY id DESC
            LIMIT 1
            """,
            (device_id,)
        ).fetchone()

        # --------------------------------------------------------
        # LATEST NETWORK TELEMETRY
        # --------------------------------------------------------

        network_row = connection.execute(
            """
            SELECT
                timestamp,
                received_at,
                payload
            FROM telemetry
            WHERE device_id = ?
              AND telemetry_type = 'network'
            ORDER BY id DESC
            LIMIT 1
            """,
            (device_id,)
        ).fetchone()

        # --------------------------------------------------------
        # EXTRACT SYSTEM VALUES
        # --------------------------------------------------------

        system = {}

        if system_row:
            system = parse_json(
                system_row["payload"]
            )

        cpu = system.get("cpu", {})
        memory = system.get("memory", {})
        disk = system.get("disk", {})

        # --------------------------------------------------------
        # EXTRACT NETWORK VALUES
        # --------------------------------------------------------

        network = {}

        if network_row:
            network = parse_json(
                network_row["payload"]
            )

        # --------------------------------------------------------
        # FRESHNESS
        # --------------------------------------------------------

        last_seen_age_seconds = None

        if device["last_seen"]:

            try:
                last_seen_dt = datetime.fromisoformat(
                    device["last_seen"]
                )

                if last_seen_dt.tzinfo is None:
                    last_seen_dt = last_seen_dt.replace(
                        tzinfo=timezone.utc
                    )

                last_seen_age_seconds = max(
                    0,
                    (
                        datetime.now(timezone.utc)
                        - last_seen_dt
                    ).total_seconds()
                )

            except Exception:
                pass

        # --------------------------------------------------------
        # RETURN
        # --------------------------------------------------------

        return {
            "device": {
                "device_id": device["device_id"],
                "hostname": device["hostname"],
                "status": (
                    "online"
                    if calculate_online(
                        device["last_seen"]
                    )
                    else "offline"
                ),
                "agent_version": device["agent_version"],
                "last_seen": device["last_seen"],
                "last_seen_age_seconds": (
                    round(
                        last_seen_age_seconds,
                        1
                    )
                    if last_seen_age_seconds is not None
                    else None
                ),
                "risk_score": round(
                    float(
                        device["risk_score"] or 0
                    ),
                    2
                ),
                "risk_level": risk_level(
                    float(
                        device["risk_score"] or 0
                    )
                )
            },

            "system": {
                "cpu_percent": cpu.get(
                    "percent"
                ),
                "memory_percent": memory.get(
                    "percent"
                ),
                "disk_percent": disk.get(
                    "percent"
                ),
                "process_count": system.get(
                    "process_count"
                ),
                "boot_time": system.get(
                    "boot_time"
                ),
                "timestamp": (
                    system_row["timestamp"]
                    if system_row
                    else None
                )
            },

            "network": {
                "connection_count": network.get(
                    "connection_count"
                ),
                "timestamp": (
                    network_row["timestamp"]
                    if network_row
                    else None
                )
            },

            "timestamp": utc_now()
        }

    finally:
        connection.close()

# ============================================================
# RECENT ACTIVITY
# ============================================================

@app.get("/api/activity")
def get_activity(
    limit: int = Query(
        default=50,
        ge=1,
        le=500
    )
):

    connection = get_connection()

    telemetry_rows = connection.execute(
        """
        SELECT
            t.event_id,
            t.device_id,
            t.timestamp,
            t.telemetry_type,
            t.agent_version,
            d.hostname

        FROM telemetry t

        LEFT JOIN devices d
            ON d.device_id = t.device_id

        ORDER BY t.id DESC

        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    alert_rows = connection.execute(
        """
        SELECT
            a.alert_id,
            a.device_id,
            a.timestamp,
            a.severity,
            a.title,
            a.status,
            a.occurrence_count,
            a.last_seen,
            d.hostname

        FROM alerts a

        LEFT JOIN devices d
            ON d.device_id = a.device_id

        ORDER BY id DESC

        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    connection.close()

    activity = []

    # Telemetry activity.
    for row in telemetry_rows:

        activity.append(
            {
                "type": "telemetry",
                "event_id": row["event_id"],
                "device_id": row["device_id"],
                "timestamp": row["timestamp"],
                "telemetry_type": row["telemetry_type"],
                "agent_version": row["agent_version"]
            }
        )

    # Security alerts.
    for row in alert_rows:

        activity.append(
            {
                "type": "alert",
                "alert_id": row["alert_id"],
                "device_id": row["device_id"],
                "hostname": row["hostname"],
                "timestamp": row["timestamp"],
                "severity": row["severity"],
                "title": row["title"],
                "status": row["status"],
                "occurrence_count": row["occurrence_count"] or 1,
                "last_seen": row["last_seen"]
            }
        )

    # Sort everything by timestamp.
    activity.sort(
        key=lambda item: item.get(
            "timestamp",
            ""
        ),
        reverse=True
    )

    return {
        "count": len(activity[:limit]),
        "activity": activity[:limit]
    }


# ============================================================
# TELEMETRY TYPES
# ============================================================

@app.get("/api/telemetry/types")
def get_telemetry_types():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            telemetry_type,
            COUNT(*) AS count

        FROM telemetry

        GROUP BY telemetry_type

        ORDER BY count DESC
        """
    ).fetchall()

    connection.close()

    return {
        "types": [
            {
                "telemetry_type": row["telemetry_type"],
                "count": row["count"]
            }
            for row in rows
        ]
    }


# ============================================================
# RECENT NETWORK ACTIVITY
# ============================================================

@app.get("/api/network")
def get_network_activity(
    device_id: Optional[str] = None,
    limit: int = Query(
        default=50,
        ge=1,
        le=500
    )
):

    connection = get_connection()

    query = """
        SELECT
            event_id,
            device_id,
            timestamp,
            payload

        FROM telemetry

        WHERE telemetry_type = 'network'
    """

    params = []

    if device_id:

        query += """
            AND device_id = ?
        """

        params.append(device_id)

    query += """
        ORDER BY id DESC
        LIMIT ?
    """

    params.append(limit)

    rows = connection.execute(
        query,
        params
    ).fetchall()

    connection.close()

    network_events = []

    for row in rows:

        payload = parse_json(
            row["payload"]
        )

        network_events.append(
            {
                "event_id": row["event_id"],
                "device_id": row["device_id"],
                "timestamp": row["timestamp"],
                "connection_count": payload.get(
                    "connection_count",
                    0
                ),
                "connections": payload.get(
                    "connections",
                    []
                )
            }
        )

    return {
        "count": len(network_events),
        "network_events": network_events
    }


# ============================================================
# PROCESS ACTIVITY
# ============================================================

@app.get("/api/processes")
def get_process_activity(
    device_id: Optional[str] = None,
    limit: int = Query(
        default=50,
        ge=1,
        le=500
    )
):

    connection = get_connection()

    query = """
        SELECT
            event_id,
            device_id,
            timestamp,
            payload

        FROM telemetry

        WHERE telemetry_type = 'processes'
    """

    params = []

    if device_id:

        query += """
            AND device_id = ?
        """

        params.append(device_id)

    query += """
        ORDER BY id DESC
        LIMIT ?
    """

    params.append(limit)

    rows = connection.execute(
        query,
        params
    ).fetchall()

    connection.close()

    process_events = []

    for row in rows:

        payload = parse_json(
            row["payload"]
        )

        process_events.append(
            {
                "event_id": row["event_id"],
                "device_id": row["device_id"],
                "timestamp": row["timestamp"],
                "total_processes": payload.get(
                    "total_processes",
                    0
                ),
                "top_processes": payload.get(
                    "top_processes",
                    []
                )
            }
        )

    return {
        "count": len(process_events),
        "process_events": process_events
    }


# ============================================================
# SYSTEM TELEMETRY
# ============================================================

@app.get("/api/system")
def get_system_activity(
    device_id: Optional[str] = None,
    limit: int = Query(
        default=50,
        ge=1,
        le=500
    )
):

    connection = get_connection()

    query = """
        SELECT
            event_id,
            device_id,
            timestamp,
            payload

        FROM telemetry

        WHERE telemetry_type = 'system'
    """

    params = []

    if device_id:

        query += """
            AND device_id = ?
        """

        params.append(device_id)

    query += """
        ORDER BY id DESC
        LIMIT ?
    """

    params.append(limit)

    rows = connection.execute(
        query,
        params
    ).fetchall()

    connection.close()

    system_events = []

    for row in rows:

        payload = parse_json(
            row["payload"]
        )

        cpu = payload.get(
            "cpu",
            {}
        )

        memory = payload.get(
            "memory",
            {}
        )

        disk = payload.get(
            "disk",
            {}
        )

        system_events.append(
            {
                "event_id": row["event_id"],
                "device_id": row["device_id"],
                "timestamp": row["timestamp"],

                "cpu": cpu,

                "memory": memory,

                "disk": disk,

                "boot_time": payload.get(
                    "boot_time"
                )
            }
        )

    return {
        "count": len(system_events),
        "system_events": system_events
    }


# ============================================================
# DEVICE STATUS REFRESH
# ============================================================

@app.post("/api/devices/refresh-status")
def refresh_device_status():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT device_id, last_seen
        FROM devices
        """
    ).fetchall()

    updated = 0

    for row in rows:

        status = (
            "online"
            if calculate_online(row["last_seen"])
            else "offline"
        )

        connection.execute(
            """
            UPDATE devices

            SET status = ?

            WHERE device_id = ?
            """,
            (
                status,
                row["device_id"]
            )
        )

        updated += 1

    connection.commit()
    connection.close()

    return {
        "status": "success",
        "devices_updated": updated
    }


# ============================================================
# DATABASE INFORMATION
# ============================================================

@app.get("/api/database")
def database_info():

    connection = get_connection()

    telemetry = connection.execute(
        """
        SELECT COUNT(*)
        FROM telemetry
        """
    ).fetchone()[0]

    devices = connection.execute(
        """
        SELECT COUNT(*)
        FROM devices
        """
    ).fetchone()[0]

    alerts = connection.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        """
    ).fetchone()[0]

    connection.close()

    try:

        database_size = DATABASE_PATH.stat().st_size

    except FileNotFoundError:

        database_size = 0

    return {
        "database": str(
            DATABASE_PATH
        ),
        "size_bytes": database_size,
        "telemetry_records": telemetry,
        "devices": devices,
        "alerts": alerts
    }


# ============================================================
# APPLICATION STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():

    logger.info("=" * 70)
    logger.info("ABACUS SECURITY MONITOR")
    logger.info("=" * 70)
    logger.info(
        "Version: %s",
        APP_VERSION
    )
    logger.info(
        "Database: %s",
        DATABASE_PATH
    )
    logger.info(
        "Status: READY"
    )
    logger.info("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
