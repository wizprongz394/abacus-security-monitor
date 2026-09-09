# ============================================================
# ABACUS SECURITY MONITOR
# Custom Central Security Monitoring Backend
#
# Version: 0.4.0
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
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
import json
import logging
import os
import uuid


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = DATA_DIR / "security.db"

APP_NAME = "Abacus Security Monitor"
APP_VERSION = "0.4.0"


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

            evidence TEXT
        )
        """
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

def detect_system_anomalies(
    device_id: str,
    payload: Dict[str, Any]
) -> List[Dict[str, Any]]:

    detections = []

    cpu = payload.get("cpu", {})
    memory = payload.get("memory", {})
    disk = payload.get("disk", {})

    cpu_percent = cpu.get("percent", 0)
    memory_percent = memory.get("percent", 0)
    disk_percent = disk.get("percent", 0)

    # --------------------------------------------------------
    # HIGH CPU
    # --------------------------------------------------------

    if isinstance(cpu_percent, (int, float)) and cpu_percent >= 95:

        detections.append(
            {
                "rule_id": "SYS-001",
                "severity": "MEDIUM",
                "title": "Very high CPU utilization",
                "description": (
                    f"CPU utilization reached {cpu_percent:.1f}%."
                ),
                "risk": 15
            }
        )

    # --------------------------------------------------------
    # HIGH MEMORY
    # --------------------------------------------------------

    if isinstance(memory_percent, (int, float)) and memory_percent >= 95:

        detections.append(
            {
                "rule_id": "SYS-002",
                "severity": "MEDIUM",
                "title": "Very high memory utilization",
                "description": (
                    f"Memory utilization reached {memory_percent:.1f}%."
                ),
                "risk": 10
            }
        )

    # --------------------------------------------------------
    # LOW DISK
    # --------------------------------------------------------

    if isinstance(disk_percent, (int, float)) and disk_percent >= 95:

        detections.append(
            {
                "rule_id": "SYS-003",
                "severity": "LOW",
                "title": "Low available disk space",
                "description": (
                    f"Disk utilization reached {disk_percent:.1f}%."
                ),
                "risk": 5
            }
        )

    return detections


def detect_network_anomalies(
    device_id: str,
    payload: Dict[str, Any]
) -> List[Dict[str, Any]]:

    detections = []

    connections = payload.get("connections", [])

    if not isinstance(connections, list):
        return detections

    # --------------------------------------------------------
    # EXCESSIVE CONNECTION COUNT
    # --------------------------------------------------------

    connection_count = payload.get(
        "connection_count",
        len(connections)
    )

    if isinstance(connection_count, int) and connection_count > 500:

        detections.append(
            {
                "rule_id": "NET-001",
                "severity": "MEDIUM",
                "title": "Unusually high network connection count",
                "description": (
                    f"Endpoint reported {connection_count} "
                    "network connections."
                ),
                "risk": 20
            }
        )

    # --------------------------------------------------------
    # SUSPICIOUS DESTINATION PORTS
    # --------------------------------------------------------

    suspicious_ports = {
        23: "Telnet",
        445: "SMB",
        3389: "RDP",
        4444: "Common remote-control/test port",
        6667: "IRC"
    }

    for connection in connections:

        raddr = connection.get("raddr")

        if not raddr:
            continue

        try:
            remote_port = int(raddr.get("port", 0))
        except Exception:
            continue

        if remote_port in suspicious_ports:

            service_name = suspicious_ports[remote_port]

            detections.append(
                {
                    "rule_id": "NET-002",
                    "severity": "LOW",
                    "title": f"Connection to {service_name} port",
                    "description": (
                        f"Process "
                        f"{connection.get('process_name', 'unknown')} "
                        f"connected to remote port {remote_port}."
                    ),
                    "risk": 5,
                    "evidence": connection
                }
            )

    return detections


def detect_process_anomalies(
    device_id: str,
    payload: Dict[str, Any]
) -> List[Dict[str, Any]]:

    detections = []

    processes = payload.get("top_processes", [])

    if not isinstance(processes, list):
        return detections

    # --------------------------------------------------------
    # VERY HIGH CPU PROCESS
    # --------------------------------------------------------

    for process in processes:

        cpu = process.get("cpu_percent", 0)

        if not isinstance(cpu, (int, float)):
            continue

        if cpu >= 95:

            process_name = process.get(
                "name",
                "unknown"
            )

            detections.append(
                {
                    "rule_id": "PROC-001",
                    "severity": "MEDIUM",
                    "title": "Process using extremely high CPU",
                    "description": (
                        f"{process_name} is using "
                        f"{cpu:.1f}% CPU."
                    ),
                    "risk": 15,
                    "evidence": process
                }
            )

    return detections


def run_detection(
    device_id: str,
    telemetry_type: str,
    payload: Dict[str, Any]
) -> List[Dict[str, Any]]:

    detections = []

    if telemetry_type == "system":

        detections.extend(
            detect_system_anomalies(
                device_id,
                payload
            )
        )

    elif telemetry_type == "network":

        detections.extend(
            detect_network_anomalies(
                device_id,
                payload
            )
        )

    elif telemetry_type == "processes":

        detections.extend(
            detect_process_anomalies(
                device_id,
                payload
            )
        )

    return detections


# ============================================================
# RISK ENGINE
# ============================================================

def get_current_risk(device_id: str) -> float:

    connection = get_connection()

    row = connection.execute(
        """
        SELECT risk_score
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,)
    ).fetchone()

    connection.close()

    if not row:
        return 0

    return float(row["risk_score"] or 0)


def update_device_risk(
    device_id: str,
    risk_increment: float,
    reason: str
) -> float:
    """
    Risk Engine v0.5

    Features:
    - Current risk is bounded between 0 and 100.
    - Risk decays when the endpoint stays quiet.
    - Identical detections have a short cooldown.
    - Risk history is preserved.
    """

    now = utc_now()

    connection = get_connection()

    # --------------------------------------------------------
    # CURRENT RISK
    # --------------------------------------------------------

    row = connection.execute(
        """
        SELECT risk_score
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,)
    ).fetchone()

    current_score = (
        float(row["risk_score"] or 0)
        if row
        else 0.0
    )

    # --------------------------------------------------------
    # LAST RISK EVENT
    # --------------------------------------------------------

    last_event = connection.execute(
        """
        SELECT timestamp, reason
        FROM risk_history
        WHERE device_id = ?
        ORDER BY timestamp DESC
        LIMIT 1
        """,
        (device_id,)
    ).fetchone()

    # --------------------------------------------------------
    # RISK DECAY
    #
    # 1 point of risk is removed per minute of inactivity.
    # Maximum decay is applied before the next event.
    # --------------------------------------------------------

    decayed_score = current_score

    if last_event and last_event["timestamp"]:

        try:
            last_time = datetime.fromisoformat(
                last_event["timestamp"]
            )

            elapsed_seconds = (
                datetime.fromisoformat(now) - last_time
            ).total_seconds()

            elapsed_minutes = max(
                0,
                elapsed_seconds / 60
            )

            decay = elapsed_minutes * 1.0

            decayed_score = max(
                0,
                current_score - decay
            )

        except Exception:
            decayed_score = current_score

    # --------------------------------------------------------
    # DETECTION COOLDOWN
    #
    # The same reason repeatedly firing every 10 seconds
    # should NOT add +15 every time.
    #
    # Same detection within 60 seconds:
    #     no additional risk
    #
    # We still preserve the event elsewhere through telemetry.
    # --------------------------------------------------------

    recent_same_reason = connection.execute(
        """
        SELECT timestamp
        FROM risk_history
        WHERE device_id = ?
          AND reason = ?
        ORDER BY timestamp DESC
        LIMIT 1
        """,
        (
            device_id,
            reason
        )
    ).fetchone()

    apply_increment = True

    if recent_same_reason:

        try:

            previous_time = datetime.fromisoformat(
                recent_same_reason["timestamp"]
            )

            seconds_since_detection = (
                datetime.fromisoformat(now)
                - previous_time
            ).total_seconds()

            if seconds_since_detection < 60:
                apply_increment = False

        except Exception:
            pass

    # --------------------------------------------------------
    # APPLY NEW RISK
    # --------------------------------------------------------

    if apply_increment:
        new_score = min(
            100,
            max(
                0,
                decayed_score + risk_increment
            )
        )
    else:
        new_score = min(
            100,
            max(
                0,
                decayed_score
            )
        )

    # --------------------------------------------------------
    # SAVE CURRENT RISK
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
    # SAVE RISK HISTORY
    # --------------------------------------------------------

    history_reason = reason

    if not apply_increment:
        history_reason = (
            f"{reason} "
            "(cooldown - no additional risk)"
        )

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
            now,
            new_score,
            history_reason
        )
    )

    connection.commit()
    connection.close()

    return new_score

# ============================================================
# ALERT ENGINE
# ============================================================

def create_alert(
    device_id: str,
    detection: Dict[str, Any],
    risk_score: float
):

    alert_id = str(uuid.uuid4())

    timestamp = utc_now()

    evidence = detection.get(
        "evidence",
        {}
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
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
            evidence
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
        """,
        (
            alert_id,
            device_id,
            timestamp,
            detection.get(
                "severity",
                "LOW"
            ),
            detection.get(
                "title",
                "Security event"
            ),
            detection.get(
                "description",
                ""
            ),
            detection.get(
                "rule_id"
            ),
            risk_score,
            json.dumps(
                evidence,
                default=str
            )
        )
    )

    connection.commit()
    connection.close()

    logger.warning(
        "[ALERT] %s | %s | Device=%s | Risk=%.1f",
        detection.get("severity"),
        detection.get("title"),
        device_id,
        risk_score
    )

    return alert_id


# ============================================================
# TELEMETRY PROCESSING
# ============================================================

def store_telemetry(data: Telemetry):

    timestamp = data.timestamp or utc_now()

    event_id = data.event_id or str(uuid.uuid4())

    received_at = utc_now()

    connection = get_connection()
    cursor = connection.cursor()

    # --------------------------------------------------------
    # STORE TELEMETRY
    # --------------------------------------------------------

    try:

        cursor.execute(
            """
            INSERT INTO telemetry (
                event_id,
                device_id,
                timestamp,
                telemetry_type,
                agent_version,
                payload,
                received_at
            )

            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                data.device_id,
                timestamp,
                data.telemetry_type,
                data.agent_version,
                json.dumps(
                    data.payload,
                    default=str
                ),
                received_at
            )
        )

    except sqlite3.IntegrityError:

        # Duplicate event.
        connection.close()

        logger.info(
            "Duplicate telemetry ignored: %s",
            event_id
        )

        return {
            "stored": False,
            "duplicate": True,
            "event_id": event_id
        }

    connection.commit()
    connection.close()

    # --------------------------------------------------------
    # UPDATE DEVICE
    # --------------------------------------------------------

    register_or_update_device(
        device_id=data.device_id,
        telemetry_type=data.telemetry_type,
        payload=data.payload,
        timestamp=timestamp,
        agent_version=data.agent_version
    )

    # --------------------------------------------------------
    # RUN DETECTION
    # --------------------------------------------------------

    detections = run_detection(
        device_id=data.device_id,
        telemetry_type=data.telemetry_type,
        payload=data.payload
    )

    created_alerts = []

    # --------------------------------------------------------
    # PROCESS DETECTIONS
    # --------------------------------------------------------

    for detection in detections:

        risk_increment = detection.get(
            "risk",
            0
        )

        new_risk = update_device_risk(
            device_id=data.device_id,
            risk_increment=risk_increment,
            reason=detection.get(
                "title",
                "Security detection"
            )
        )

        alert_id = create_alert(
            device_id=data.device_id,
            detection=detection,
            risk_score=new_risk
        )

        created_alerts.append(
            {
                "alert_id": alert_id,
                "rule_id": detection.get("rule_id"),
                "severity": detection.get("severity"),
                "title": detection.get("title"),
                "risk_score": new_risk
            }
        )

    return {
        "stored": True,
        "duplicate": False,
        "event_id": event_id,
        "detections": len(detections),
        "alerts": created_alerts
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
            id,
            event_id,
            device_id,
            timestamp,
            telemetry_type,
            agent_version,
            payload,
            received_at

        FROM telemetry

        WHERE 1=1
    """

    params = []

    if device_id:

        query += """
            AND device_id = ?
        """

        params.append(device_id)

    if telemetry_type:

        query += """
            AND telemetry_type = ?
        """

        params.append(telemetry_type)

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

    results = []

    for row in rows:

        results.append(
            {
                "id": row["id"],
                "event_id": row["event_id"],
                "device_id": row["device_id"],
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

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT *
        FROM devices
        ORDER BY risk_score DESC, last_seen DESC
        """
    ).fetchall()

    connection.close()

    devices = []

    for row in rows:

        online = calculate_online(
            row["last_seen"]
        )

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
                "status": "online" if online else "offline",
                "risk_score": row["risk_score"]
            }
        )

    return {
        "count": len(devices),
        "devices": devices
    }


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

    connection = get_connection()

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

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Device not found"
        )

    history = connection.execute(
        """
        SELECT
            timestamp,
            risk_score,
            reason

        FROM risk_history

        WHERE device_id = ?

        ORDER BY id DESC

        LIMIT 50
        """,
        (device_id,)
    ).fetchall()

    connection.close()

    return {
        "device_id": device["device_id"],
        "hostname": device["hostname"],
        "risk_score": device["risk_score"],
        "history": [
            {
                "timestamp": row["timestamp"],
                "risk_score": row["risk_score"],
                "reason": row["reason"]
            }
            for row in history
        ]
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
                "evidence": parse_json(row["evidence"])
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
        "dismissed"
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

    connection = get_connection()

    total_devices = connection.execute(
        """
        SELECT COUNT(*)
        FROM devices
        """
    ).fetchone()[0]

    total_telemetry = connection.execute(
        """
        SELECT COUNT(*)
        FROM telemetry
        """
    ).fetchone()[0]

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

    critical_alerts = connection.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'CRITICAL'
        AND status != 'resolved'
        """
    ).fetchone()[0]

    high_alerts = connection.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'HIGH'
        AND status != 'resolved'
        """
    ).fetchone()[0]

    medium_alerts = connection.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'MEDIUM'
        AND status != 'resolved'
        """
    ).fetchone()[0]

    low_alerts = connection.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'LOW'
        AND status != 'resolved'
        """
    ).fetchone()[0]

    connection.close()

    # Determine online devices.
    connection = get_connection()

    device_rows = connection.execute(
        """
        SELECT last_seen
        FROM devices
        """
    ).fetchall()

    connection.close()

    online_devices = sum(
        1
        for row in device_rows
        if calculate_online(row["last_seen"])
    )

    return {
        "devices": {
            "total": total_devices,
            "online": online_devices,
            "offline": total_devices - online_devices
        },

        "telemetry": {
            "total": total_telemetry
        },

        "alerts": {
            "total": total_alerts,
            "open": open_alerts,
            "critical": critical_alerts,
            "high": high_alerts,
            "medium": medium_alerts,
            "low": low_alerts
        },

        "timestamp": utc_now()
    }


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
            event_id,
            device_id,
            timestamp,
            telemetry_type,
            agent_version

        FROM telemetry

        ORDER BY id DESC

        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    alert_rows = connection.execute(
        """
        SELECT
            alert_id,
            device_id,
            timestamp,
            severity,
            title,
            status

        FROM alerts

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
                "timestamp": row["timestamp"],
                "severity": row["severity"],
                "title": row["title"],
                "status": row["status"]
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