"""
Abacus Security Monitoring System
Detection Engine v0.8

Purpose:
- Convert raw telemetry into security-relevant detections.
- Separate resource anomalies from genuine security indicators.
- Provide structured detection objects to the risk/alert engine.

Design principles:
- Detections are evidence-based, not alarmist.
- Every detection carries MITRE ATT&CK context where applicable.
- Resource anomalies are LOW confidence unless correlated with
  behavioural indicators.
- Detection output is stable and versioned for downstream consumers.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable, Optional


# =========================================================
# ENGINE METADATA
# =========================================================

DETECTION_ENGINE_VERSION = "0.8.2"
DETECTION_ENGINE_NAME = "Abacus Detection Engine"


# =========================================================
# BASELINE KNOWLEDGE
# ---------------------------------------------------------
# These are intentionally conservative. They bias the engine
# toward *not* alerting on known-good behaviour.
# =========================================================

# Processes that are commonly high CPU / high memory legitimately
KNOWN_RESOURCE_HEAVY_PROCESSES: set[str] = {
    "system",
    "system idle process",
    "registry",
    "memory compression",
    "msmpeng.exe",         # Windows Defender
    "searchindexer.exe",   # Windows Search
    "dwm.exe",             # Desktop Window Manager
    "explorer.exe",
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "code.exe",
    "docker desktop.exe",
    "vmmem",
    "vmmemwsl",
    "python.exe",
    "python3",
    "node.exe",
    "java.exe",
    "javaw.exe",
}

# Folders we consider sensitive / unusual for a process to live in
SUSPICIOUS_EXECUTION_PATHS: tuple[str, ...] = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\public\\",
    "\\programdata\\",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)

# Ports that indicate common attack surfaces / C2 channels
SUSPICIOUS_REMOTE_PORTS: dict[int, str] = {
    23:    "Telnet (unencrypted, often abused)",
    445:   "SMB (lateral movement)",
    1433:  "MSSQL (credential attacks)",
    3306:  "MySQL (credential attacks)",
    3389:  "RDP (brute force / lateral movement)",
    4444:  "Metasploit default handler",
    5555:  "ADB / Android debug",
    6667:  "IRC (botnet C2)",
    8080:  "HTTP alt (proxy / C2)",
    9001:  "Tor OR port",
    9050:  "Tor SOCKS proxy",
    31337: "Back Orifice / elite C2",
}

# Windows persistence / autorun locations
PERSISTENCE_PATHS: tuple[str, ...] = (
    "\\start menu\\programs\\startup\\",
    "\\windows\\system32\\tasks\\",
    "\\windows\\system32\\drivers\\etc\\",
)


# High-value V0.8.1 indicators. Existing command rules remain authoritative;
# these rules add coverage without duplicating those existing signatures.
LOLBIN_NAMES: set[str] = {
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wmic.exe", "msiexec.exe",
}

DOWNLOAD_PATTERNS: tuple[str, ...] = (
    r"\binvoke-webrequest\b", r"\binvoke-restmethod\b",
    r"\bdownloadstring\b", r"\bdownloadfile\b",
    r"\bstart-bitstransfer\b",
    r"\bbitsadmin(?:\.exe)?\b.*(?:/transfer|http://|https://)",
    r"\bcurl(?:\.exe)?\b.*(?:https?://|ftp://)",
    r"\bwget(?:\.exe)?\b.*(?:https?://|ftp://)",
)

OBFUSCATION_PATTERNS: tuple[str, ...] = (
    r"-encodedcommand\b", r"(?<!\w)-enc(?:odedcommand)?\s+[a-z0-9+/=]{12,}",
    r"\[convert\]::frombase64string", r"\bfrombase64string\b",
)

PERSISTENCE_PATTERNS: tuple[str, ...] = (
    r"\bnew-service\b", r"\bsc(?:\.exe)?\b.*\bcreate\b",
)

WMI_EXECUTION_PATTERNS: tuple[str, ...] = (
    r"\binvoke-wmimethod\b", r"\binvoke-cimmethod\b",
)

REMOTE_ADMIN_PORTS: set[int] = {23, 445, 3389, 5985, 5986}


# =========================================================
# DETECTION OBJECT
# =========================================================

@dataclass
class Detection:
    """
    A structured detection object.

    Backward compatible with the v0.6 dict shape, but richer.
    Downstream engines can use `to_dict()` to get the legacy
    shape.
    """

    rule_id: str
    title: str
    description: str = ""

    severity: str = "LOW"            # LOW | MEDIUM | HIGH | CRITICAL
    confidence: str = "LOW"          # LOW | MEDIUM | HIGH
    category: str = "generic"        # resource_anomaly | behaviour | network | persistence | ...
    risk_increment: int = 0

    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None

    evidence: dict[str, Any] = field(default_factory=dict)

    # Stable signal identity used by downstream correlation/risk logic.
    # This must not depend on volatile telemetry such as CPU%, timestamps,
    # connection state, or changing evidence payloads.
    signal_key: str = ""

    # Condition lifecycle metadata. The risk engine can later persist and
    # evolve these states independently from raw detection generation.
    condition_state: str = "NEW"  # NEW | ACTIVE | REINFORCED | RESOLVING | RESOLVED | EXPIRED

    # Deterministic identifier for deduplication
    fingerprint: str = ""

    # When this detection was produced (engine-side)
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if not self.signal_key:
            self.signal_key = self._compute_signal_key()

        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()

    def _compute_signal_key(self) -> str:
        """
        Build a stable identity for the underlying security signal.

        Prefer explicit device/process/destination identity when available.
        Do not include volatile measurements such as CPU, memory, hit counts,
        connection status, or timestamps.
        """
        e = self.evidence or {}

        process_name = str(e.get("process_name") or "").strip().lower()
        pid = str(e.get("pid") or "").strip()
        destination = str(e.get("destination") or "").strip().lower()

        if process_name and pid:
            identity = f"process:{process_name}:pid:{pid}"
        elif process_name:
            identity = f"process:{process_name}"
        elif destination:
            identity = f"destination:{destination}"
        else:
            identity = "global"

        return f"{self.rule_id}|{self.category}|{identity}"

    def _compute_fingerprint(self) -> str:
        """
        Fingerprint the stable signal identity, not the complete evidence.

        This prevents changing CPU%, connection state, timestamps, etc. from
        turning one continuing condition into many unrelated detections.
        """
        raw = self.signal_key
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Legacy-compatible dictionary representation."""
        base = {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "risk_increment": self.risk_increment,
            "evidence": self.evidence,
            "signal_key": self.signal_key,
            "condition_state": self.condition_state,
            "fingerprint": self.fingerprint,
            "detected_at": self.detected_at,
        }

        if self.mitre_tactic:
            base["mitre_tactic"] = self.mitre_tactic
        if self.mitre_technique:
            base["mitre_technique"] = self.mitre_technique
        if self.mitre_technique_id:
            base["mitre_technique_id"] = self.mitre_technique_id

        return base


# =========================================================
# SIGNAL / CONDITION HELPERS
# =========================================================

def make_condition_key(detection: Detection, device_id: Optional[str] = None) -> str:
    """
    Stable condition identity for the risk/correlation engine.

    Device identity is deliberately kept outside Detection so the same
    detection engine can process telemetry from multiple endpoints.
    """
    prefix = str(device_id or "unknown-device").strip().lower()
    return f"{prefix}|{detection.signal_key}"


def condition_from_detection(
    detection: Detection,
    device_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Convert a Detection into the condition contract expected by Godmode.

    This is intentionally a pure transformation. Persistence and lifecycle
    decisions belong to the risk engine, not the detection engine.
    """
    return {
        "condition_id": make_condition_key(detection, device_id),
        "device_id": device_id,
        "rule_id": detection.rule_id,
        "signal_key": detection.signal_key,
        "fingerprint": detection.fingerprint,
        "title": detection.title,
        "category": detection.category,
        "severity": detection.severity,
        "confidence": detection.confidence,
        "risk_increment": detection.risk_increment,
        "condition_state": detection.condition_state,
        "evidence": detection.evidence,
        "mitre_tactic": detection.mitre_tactic,
        "mitre_technique": detection.mitre_technique,
        "mitre_technique_id": detection.mitre_technique_id,
        "detected_at": detection.detected_at,
    }


# =========================================================
# PUBLIC ENTRY POINT
# =========================================================

def detect(telemetry: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Main detection entry point.

    Returns a list of detection dictionaries (legacy shape,
    enriched with v0.7 fields).
    """

    if not isinstance(telemetry, dict):
        return []

    detections: list[Detection] = []

    detections.extend(detect_process_behavior(telemetry))
    detections.extend(
        detect_network_behavior(
            telemetry,
            seen_destinations=telemetry.get("seen_destinations"),
        )
    )

    # Deduplicate by fingerprint (collapse identical findings)
    deduped = _deduplicate(detections)

    return [d.to_dict() for d in deduped]


# =========================================================
# PROCESS DETECTIONS
# =========================================================

def detect_process_behavior(
    telemetry: dict[str, Any]
) -> list[Detection]:

    detections: list[Detection] = []

    # Angelmode v0.8 sends the live process list as "top_processes".
    # Keep compatibility with the older "processes" schema as well.
    processes = telemetry.get("top_processes")

    if processes is None:
        processes = telemetry.get("processes", [])

    if not isinstance(processes, list):
        return detections

    for process in processes:
        if not isinstance(process, dict):
            continue

        detections.extend(_analyze_single_process(process))

    return detections

def _analyze_single_process(process: dict[str, Any]) -> list[Detection]:
    """Run all process-level rules against a single process."""

    results: list[Detection] = []

    cpu = _safe_float(process.get("cpu_percent"))
    memory = _safe_float(process.get("memory_percent"))
    name = _process_name(process)
    pid = process.get("pid")
    exe = str(process.get("exe") or process.get("exe_path") or "")
    cmdline_value = process.get("cmdline") or process.get("command_line") or ""

    if isinstance(cmdline_value, (list, tuple)):
        cmdline = " ".join(str(part) for part in cmdline_value)
    else:
        cmdline = str(cmdline_value)
    username = str(process.get("username") or "")
    parent = str(process.get("parent_name") or process.get("ppid_name") or "")

    context = {
        "process_name": name,
        "pid": pid,
        "exe": exe,
        "cmdline": cmdline,
        "username": username,
        "parent_name": parent,
        "cpu_percent": cpu,
        "memory_percent": memory,
    }

    is_known_heavy = name.lower() in KNOWN_RESOURCE_HEAVY_PROCESSES

    # -----------------------------------------------------
    # RESOURCE ANOMALIES
    # -----------------------------------------------------

    if cpu >= 90 and not is_known_heavy:
        results.append(
            Detection(
                rule_id="PROC-RESOURCE-001",
                title="Process using extremely high CPU",
                description=(
                    f"Process '{name}' (PID {pid}) is consuming {cpu:.1f}% CPU "
                    "and is not a known high-CPU process."
                ),
                severity="LOW",
                confidence="LOW",
                category="resource_anomaly",
                risk_increment=4,
                evidence=context,
            )
        )

    if memory >= 90 and not is_known_heavy:
        results.append(
            Detection(
                rule_id="PROC-RESOURCE-002",
                title="Process using extremely high memory",
                description=(
                    f"Process '{name}' (PID {pid}) is consuming {memory:.1f}% memory "
                    "and is not a known high-memory process."
                ),
                severity="LOW",
                confidence="LOW",
                category="resource_anomaly",
                risk_increment=4,
                evidence=context,
            )
        )

    # -----------------------------------------------------
    # SUSPICIOUS EXECUTION PATH
    # -----------------------------------------------------

    lower_exe = exe.lower().replace("/", "\\")

    defender_trusted = (
        name.lower() == "msmpeng.exe"
        and "\\programdata\\microsoft\\windows defender\\platform\\" in lower_exe
    )

    if (
        exe
        and any(p in lower_exe for p in SUSPICIOUS_EXECUTION_PATHS)
        and not defender_trusted
    ):
        results.append(
            Detection(
                rule_id="PROC-PATH-001",
                title="Process executing from suspicious location",
                description=(
                    f"Process '{name}' (PID {pid}) is running from '{exe}', "
                    "a location not typically used to host legitimate executables."
                ),
                severity="MEDIUM",
                confidence="LOW",
                category="behaviour",
                risk_increment=15,
                mitre_tactic="Defense Evasion",
                mitre_technique="Match Legitimate Name or Location",
                mitre_technique_id="T1036.005",
                evidence=context,
            )
        )

    # -----------------------------------------------------
    # SUSPICIOUS COMMAND LINE PATTERNS
    # -----------------------------------------------------

    if cmdline:
        suspicious_cmdline = _match_suspicious_cmdline(cmdline)
        for rule_id, title, reason, risk in suspicious_cmdline:
            results.append(
                Detection(
                    rule_id=rule_id,
                    title=title,
                    description=f"{reason} (process: {name})",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    category="behaviour",
                    risk_increment=risk,
                    mitre_tactic="Execution",
                    mitre_technique="Command and Scripting Interpreter",
                    mitre_technique_id="T1059",
                    evidence={**context, "matched_pattern": reason},
                )
            )

    # -----------------------------------------------------
    # V0.8.1: LOLBIN WITH REMOTE / PROXY EXECUTION CONTEXT
    # -----------------------------------------------------

    lower_cmdline = cmdline.lower()
    if name.lower() in LOLBIN_NAMES and lower_cmdline:
        lolbin_context = ("http://", "https://", "ftp://", "-urlcache",
                          "-split", "/transfer", "javascript:", "vbscript:",
                          "scrobj.dll", "shell32.dll")
        if any(token in lower_cmdline for token in lolbin_context):
            results.append(Detection(
                rule_id="PROC-LOLBIN-001",
                title="LOLBin used with suspicious context",
                description=f"System utility '{name}' was executed with arguments associated with remote or proxy execution.",
                severity="MEDIUM", confidence="MEDIUM", category="behaviour",
                risk_increment=12, mitre_tactic="Execution",
                mitre_technique="System Binary Proxy Execution",
                mitre_technique_id="T1218", evidence=context,
            ))

    # -----------------------------------------------------
    # V0.8.1: REMOTE CONTENT RETRIEVAL NOT ALREADY COVERED
    # -----------------------------------------------------

    if lower_cmdline and any(re.search(p, lower_cmdline) for p in DOWNLOAD_PATTERNS):
        # Existing PROC-CMD-002 handles classic download-and-execute.
        # Emit only when the command looks like retrieval without that exact pattern.
        if not any(d.rule_id == "PROC-CMD-002" for d in results):
            results.append(Detection(
                rule_id="PROC-DOWNLOAD-001",
                title="Suspicious remote content retrieval",
                description=f"Process '{name or 'unknown'}' contains a command-line pattern associated with downloading remote content.",
                severity="MEDIUM", confidence="MEDIUM", category="behaviour",
                risk_increment=12, mitre_tactic="Command and Control",
                mitre_technique="Ingress Tool Transfer", mitre_technique_id="T1105",
                evidence={**context, "matched_indicator": "remote_content_retrieval"},
            ))

    # -----------------------------------------------------
    # V0.8.1: ADDITIONAL OBFUSCATION
    # -----------------------------------------------------

    if lower_cmdline and any(re.search(p, lower_cmdline) for p in OBFUSCATION_PATTERNS):
        if not any(d.rule_id == "PROC-CMD-001" for d in results):
            results.append(Detection(
                rule_id="PROC-OBFUSCATION-001",
                title="Encoded or obfuscated command",
                description=f"Process '{name or 'unknown'}' contains indicators of encoded or obfuscated execution.",
                severity="MEDIUM", confidence="MEDIUM", category="behaviour",
                risk_increment=12, mitre_tactic="Defense Evasion",
                mitre_technique="Obfuscated Files or Information",
                mitre_technique_id="T1027", evidence={**context, "matched_indicator": "command_obfuscation"},
            ))

    # -----------------------------------------------------
    # V0.8.1: SERVICE-BASED PERSISTENCE
    # -----------------------------------------------------

    if lower_cmdline and any(re.search(p, lower_cmdline) for p in PERSISTENCE_PATTERNS):
        results.append(Detection(
            rule_id="PROC-PERSIST-002",
            title="Potential service persistence",
            description=f"Process '{name or 'unknown'}' contains a command associated with creating or modifying a service.",
            severity="MEDIUM", confidence="MEDIUM", category="persistence",
            risk_increment=14, mitre_tactic="Persistence",
            mitre_technique="Create or Modify System Process: Windows Service",
            mitre_technique_id="T1543.003", evidence={**context, "matched_indicator": "service_persistence"},
        ))

    # -----------------------------------------------------
    # V0.8.1: ADDITIONAL WMI COMMANDLET COVERAGE
    # -----------------------------------------------------

    if lower_cmdline and any(re.search(p, lower_cmdline) for p in WMI_EXECUTION_PATTERNS):
        results.append(Detection(
            rule_id="PROC-WMI-001",
            title="Suspicious WMI execution",
            description=f"Process '{name or 'unknown'}' contains WMI execution behavior.",
            severity="MEDIUM", confidence="MEDIUM", category="behaviour",
            risk_increment=14, mitre_tactic="Execution",
            mitre_technique="Windows Management Instrumentation",
            mitre_technique_id="T1047", evidence={**context, "matched_indicator": "wmi_execution"},
        ))

    # -----------------------------------------------------
    # MASQUERADING (name looks like a system process but isn't)
    # -----------------------------------------------------

    if _looks_like_system_process(name) and exe and not _is_system_path(exe):
        results.append(
            Detection(
                rule_id="PROC-MASQ-001",
                title="Possible process masquerading",
                description=(
                    f"Process name '{name}' resembles a system binary, but "
                    f"its executable path does not match a system directory."
                ),
                severity="HIGH",
                confidence="MEDIUM",
                category="behaviour",
                risk_increment=25,
                mitre_tactic="Defense Evasion",
                mitre_technique="Masquerading",
                mitre_technique_id="T1036",
                evidence=context,
            )
        )

    # -----------------------------------------------------
    # SUSPICIOUS SCRIPTING INTERPRETERS RUNNING
    # -----------------------------------------------------

    if _is_suspicious_interpreter(name, cmdline):
        results.append(
            Detection(
                rule_id="PROC-SCRIPT-001",
                title="Scripting interpreter with suspicious arguments",
                description=(
                    f"Interpreter '{name}' is running with arguments often "
                    "associated with malicious scripting."
                ),
                severity="MEDIUM",
                confidence="MEDIUM",
                category="behaviour",
                risk_increment=18,
                mitre_tactic="Execution",
                mitre_technique="Command and Scripting Interpreter",
                mitre_technique_id="T1059",
                evidence=context,
            )
        )

    return results


# =========================================================
# NETWORK DETECTIONS
# =========================================================

def detect_network_behavior(
    telemetry: dict[str, Any],
    seen_destinations: set[tuple[str, str]] | None = None,
) -> list[Detection]:
    """Run network-level detections against endpoint telemetry.

    Supports the current Angelmode v0.8 flat schema and the older
    nested ``raddr`` schema.

    ``seen_destinations`` is supplied by Godmode's historical telemetry
    lookup and contains destinations previously observed on this endpoint.
    """

    detections: list[Detection] = []
    seen_destinations = seen_destinations or set()

    connections = telemetry.get("connections", [])
    if not isinstance(connections, list):
        return detections

    # ---------------------------------------------------------
    # V0.8.1: NETWORK SCAN / DISCOVERY BEHAVIOR
    # ---------------------------------------------------------
    # Godmode supplies summarized historical network behavior.
    # The detector remains stateless and does not query SQLite.
    network_history = telemetry.get("network_history") or {}

    historical_event_count = _safe_int(
        network_history.get("event_count")
    )

    historical_ips = network_history.get(
        "distinct_remote_ips",
        set(),
    )

    historical_destinations = network_history.get(
        "distinct_destinations",
        set(),
    )

    historical_ports = network_history.get(
        "distinct_ports",
        set(),
    )

    if not isinstance(historical_ips, set):
        historical_ips = set(historical_ips or [])

    if not isinstance(historical_destinations, set):
        historical_destinations = set(historical_destinations or [])

    if not isinstance(historical_ports, set):
        historical_ports = set(historical_ports or [])

    current_ips: set[str] = set()
    current_destinations: set[str] = set()
    current_ports: set[str] = set()

    for conn in connections:
        if not isinstance(conn, dict):
            continue

        remote_ip = conn.get("remote_ip")
        remote_port = _safe_int(conn.get("remote_port"))

        if not remote_ip or not remote_port:
            raddr = conn.get("raddr") or {}

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

        if _is_loopback(remote_ip):
            continue

        current_ips.add(remote_ip)
        current_ports.add(remote_port)
        current_destinations.add(
            f"{remote_ip}:{remote_port}"
        )

    new_ips = current_ips - historical_ips
    new_destinations = (
        current_destinations - historical_destinations
    )

    # Conservative threshold. A normal browser can create many
    # connections, so connection count alone must not trigger a scan.
    scan_threshold = 12

    if (
        historical_event_count >= 2
        and len(new_ips) >= scan_threshold
    ):
        detections.append(
            Detection(
                rule_id="NET-SCAN-001",
                title="Possible network scanning behavior",
                description=(
                    f"Endpoint contacted {len(new_ips)} new remote "
                    "IP addresses in the current network snapshot, "
                    "which is unusual compared with recent activity."
                ),
                severity="MEDIUM",
                confidence="MEDIUM",
                category="network",
                risk_increment=14,
                mitre_tactic="Discovery",
                mitre_technique="Network Service Scanning",
                mitre_technique_id="T1046",
                signal_key=(
                    f"scan:ips:{len(new_ips)}:"
                    f"{len(new_destinations)}"
                ),
                evidence={
                    "historical_event_count": historical_event_count,
                    "current_distinct_ips": len(current_ips),
                    "new_distinct_ips": len(new_ips),
                    "current_distinct_destinations": len(
                        current_destinations
                    ),
                    "new_distinct_destinations": len(
                        new_destinations
                    ),
                    "current_distinct_ports": len(current_ports),
                    "threshold": scan_threshold,
                },
            )
        )

    suspicious_destinations: dict[str, list[dict[str, Any]]] = {}
    rare_destinations: dict[str, list[dict[str, Any]]] = {}

    for conn in connections:
        if not isinstance(conn, dict):
            continue

        # -----------------------------------------------------
        # NETWORK SCHEMA NORMALIZATION
        # -----------------------------------------------------

        remote_ip = conn.get("remote_ip")
        remote_port = _safe_int(conn.get("remote_port"))

        if not remote_ip or not remote_port:
            raddr = conn.get("raddr") or {}
            if isinstance(raddr, dict):
                remote_ip = remote_ip or raddr.get("ip")
                remote_port = remote_port or _safe_int(raddr.get("port"))

        status = str(conn.get("status") or "").upper()

        process_name = str(
            conn.get("process")
            or conn.get("process_name")
            or ""
        ).strip()

        if not remote_ip or not remote_port:
            continue

        remote_ip = str(remote_ip).strip()

        # -----------------------------------------------------
        # LOOPBACK FILTER
        # -----------------------------------------------------

        if _is_loopback(remote_ip):
            continue

        # -----------------------------------------------------
        # RARE PUBLIC DESTINATION
        # -----------------------------------------------------

        destination_identity = (
            remote_ip,
            str(remote_port),
        )

        if (
            _is_public_ip(remote_ip)
            and destination_identity not in seen_destinations
        ):
            rare_destinations.setdefault(
                f"{remote_ip}:{remote_port}",
                [],
            ).append(
                {
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process_name": process_name,
                    "pid": conn.get("pid"),
                    "status": status,
                }
            )

        # -----------------------------------------------------
        # EXTERNAL ADMINISTRATIVE CONNECTION
        # -----------------------------------------------------
        #
        # Public administrative ports are handled by NET-PORT-001
        # through SUSPICIOUS_REMOTE_PORTS below. Rare-destination
        # detection is emitted once, after the connection scan,
        # so each destination gets one stable condition identity.

        # -----------------------------------------------------
        # V0.8.1: EXTERNAL REMOTE ADMINISTRATION
        # -----------------------------------------------------

        if remote_port in REMOTE_ADMIN_PORTS and _is_public_ip(remote_ip):
            detections.append(Detection(
                rule_id="NET-EXTERNAL-ADMIN-001",
                title="External remote administration connection",
                description=(f"Connection to public destination {remote_ip}:{remote_port} "
                             "uses a remote administration or lateral-movement service."),
                severity="MEDIUM", confidence="MEDIUM", category="network",
                risk_increment=14, mitre_tactic="Lateral Movement",
                mitre_technique="Remote Services", mitre_technique_id="T1021",
                evidence={"remote_ip": remote_ip, "remote_port": remote_port,
                          "process_name": process_name, "pid": conn.get("pid"),
                          "status": status, "destination_scope": "public"},
            ))

        # -----------------------------------------------------
        # SUSPICIOUS PORT CHECK
        # -----------------------------------------------------

        if remote_port in SUSPICIOUS_REMOTE_PORTS:
            key = f"{remote_ip}:{remote_port}"

            suspicious_destinations.setdefault(
                key,
                [],
            ).append(
                {
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "port_reason": SUSPICIOUS_REMOTE_PORTS[remote_port],
                    "process_name": process_name,
                    "pid": conn.get("pid"),
                    "status": status,
                }
            )

    # ---------------------------------------------------------
    # EMIT ONE DETECTION PER RARE DESTINATION
    # ---------------------------------------------------------

    for key, hits in rare_destinations.items():
        sample = hits[0]

        detections.append(
            Detection(
                rule_id="NET-RARE-DEST-001",
                title="Rare network destination",
                description=(
                    f"Process '{sample['process_name'] or 'unknown'}' "
                    f"communicated with public destination "
                    f"{sample['remote_ip']}:{sample['remote_port']}, "
                    "which has not previously been observed on this endpoint."
                ),
                severity="LOW",
                confidence="LOW",
                category="network",
                risk_increment=8,
                mitre_tactic="Command and Control",
                mitre_technique="Application Layer Protocol",
                mitre_technique_id="T1071",
                signal_key=f"destination:{key}",
                evidence={
                    "destination": key,
                    "remote_ip": sample["remote_ip"],
                    "remote_port": sample["remote_port"],
                    "process_name": sample["process_name"],
                    "hit_count": len(hits),
                    "connections": hits[:5],
                    "destination_scope": "public",
                    "historical_match": False,
                },
            )
        )

    # ---------------------------------------------------------
    # EMIT ONE DETECTION PER SUSPICIOUS DESTINATION
    # ---------------------------------------------------------

    for key, hits in suspicious_destinations.items():
        sample = hits[0]
        port_reason = sample["port_reason"]

        detections.append(
            Detection(
                rule_id="NET-PORT-001",
                title="Connection to suspicious remote port",
                description=(
                    f"Observed {len(hits)} connection(s) to "
                    f"{sample['remote_ip']}:{sample['remote_port']} "
                    f"({port_reason})."
                ),
                severity="MEDIUM",
                confidence="MEDIUM",
                category="network",
                risk_increment=12,
                mitre_tactic="Command and Control",
                mitre_technique="Application Layer Protocol",
                mitre_technique_id="T1071",
                evidence={
                    "destination": key,
                    "hit_count": len(hits),
                    "connections": hits[:5],
                },
            )
        )

    return detections


# =========================================================
# HELPERS — PROCESS
# =========================================================

def _process_name(process: dict[str, Any]) -> str:
    return str(
        process.get("name")
        or process.get("process_name")
        or ""
    ).strip()


def _looks_like_system_process(name: str) -> bool:
    """Very conservative list of system process names."""
    if not name:
        return False

    lower = name.lower()

    system_names = {
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "smss.exe",
        "spoolsv.exe",
        "explorer.exe",
        "taskhostw.exe",
    }

    return lower in system_names


def _is_system_path(path: str) -> bool:
    """
    Determine whether an executable resides in a trusted
    Windows system location.

    This deliberately distinguishes:
        C:\\Windows\\explorer.exe
    from:
        C:\\Windows\\Temp\\explorer.exe

    The latter must remain suspicious.
    """

    if not path:
        return False

    normalized = os.path.normpath(
        str(path)
    ).replace("/", "\\").lower()

    # Standard Windows system directories.
    trusted_prefixes = (
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
    )

    if any(prefix in normalized for prefix in trusted_prefixes):
        return True

    # Executables directly under C:\\Windows\\
    # are valid for specific Windows components such as explorer.exe.
    windows_marker = "\\windows\\"

    if windows_marker in normalized:
        relative = normalized.split(
            windows_marker,
            1
        )[1]

        # Only trust files directly inside Windows root.
        # Do NOT trust arbitrary subdirectories such as Windows\\Temp.
        if "\\" not in relative:
            return True

    return False


def _is_suspicious_interpreter(name: str, cmdline: str) -> bool:
    """Detect suspicious use of PowerShell / cmd / bash etc."""

    lower_name = name.lower()
    lower_cmd = cmdline.lower()

    if not lower_name:
        return False

    interpreters = {
        "powershell.exe": ("-enc", "-encodedcommand", "downloadstring",
                           "invoke-expression", "iex(", "bypass"),
        "pwsh.exe":       ("-enc", "-encodedcommand", "downloadstring",
                           "invoke-expression", "iex("),
        "cmd.exe":        ("/c powershell", "/c curl", "/c wget",
                           "bitsadmin", "certutil -urlcache"),
        "wscript.exe":    ("javascript:", "vbscript:"),
        "cscript.exe":    ("javascript:", "vbscript:"),
        "bash":           ("curl | sh", "wget | sh", "/dev/tcp/"),
    }

    for interp, indicators in interpreters.items():
        if lower_name == interp or lower_name.endswith(f"\\{interp}"):
            if any(ind in lower_cmd for ind in indicators):
                return True

    return False


def _match_suspicious_cmdline(
    cmdline: str
) -> list[tuple[str, str, str, int]]:
    """
    Return a list of (rule_id, title, reason, risk_increment)
    tuples for suspicious command-line patterns.

    Kept as a table so it's easy to extend without touching
    the detection loop.
    """

    results: list[tuple[str, str, str, int]] = []
    lower = cmdline.lower()

    patterns = [
        (
            "PROC-CMD-001",
            "Encoded PowerShell command",
            "Base64-encoded PowerShell command (common in fileless malware)",
            r"(-enc\s|-encodedcommand\s|-e\s+[a-z0-9+/=]{20,})",
            25,
        ),
        (
            "PROC-CMD-002",
            "Download-and-execute pattern",
            "Command attempts to download and execute remote content",
            r"(downloadstring|downloadfile|invoke-webrequest|curl\s+.*\|\s*(sh|bash)|wget\s+.*\|\s*(sh|bash))",
            30,
        ),
        (
            "PROC-CMD-003",
            "Hidden window PowerShell",
            "PowerShell invoked with hidden window and execution bypass",
            r"(-windowstyle\s+hidden.*-executionpolicy\s+bypass|-executionpolicy\s+bypass.*-windowstyle\s+hidden)",
            25,
        ),
        (
            "PROC-CMD-004",
            "Certutil abuse",
            "certutil used to download files (LOLBin abuse)",
            r"certutil(\.exe)?\s+.*-urlcache",
            22,
        ),
        (
            "PROC-CMD-005",
            "Scheduled task creation",
            "Command creates a scheduled task (common persistence)",
            r"schtasks(\s|\.exe).*\/create",
            18,
        ),
        (
            "PROC-CMD-006",
            "Registry persistence",
            "Command writes to a persistence-related registry key",
            r"(reg(?:\.exe)?\s+add.*\\software\\microsoft\\windows\\currentversion\\run(?:once)?(?:\\|$))",
            22,
        ),

        (
            "PROC-CMD-007",
            "WMI execution",
            "Command uses WMI to execute or persist",
            r"(wmic(?:\.exe)?\s+.*process\s+call\s+create|wmic(?:\.exe)?\s+.*/node:)",
            20,
        ),
    ]

    for rule_id, title, reason, pattern, risk in patterns:
        if re.search(pattern, lower):
            results.append((rule_id, title, reason, risk))

    return results


# =========================================================
# HELPERS — NETWORK
# =========================================================

def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_global
    except ValueError:
        return False


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


# =========================================================
# HELPERS — GENERAL
# =========================================================

def _safe_float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _deduplicate(
    detections: Iterable[Detection]
) -> list[Detection]:
    """
    Collapse detections that share a fingerprint.

    When duplicates are found, the higher-risk version is kept
    and its evidence.hit_count is bumped so downstream engines
    know how many times the pattern fired.
    """

    seen: dict[str, Detection] = {}

    for detection in detections:
        key = detection.fingerprint

        if key not in seen:
            seen[key] = detection
            continue

        existing = seen[key]

        # Bump hit count on evidence, but never inflate risk merely because
        # the same signal was observed repeatedly in one telemetry snapshot.
        existing.evidence.setdefault("hit_count", 1)
        existing.evidence["hit_count"] += 1

        # Keep the more severe version if they disagree
        if _severity_rank(detection.severity) > _severity_rank(existing.severity):
            seen[key] = detection

    return list(seen.values())


def _severity_rank(severity: str) -> int:
    return {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }.get(str(severity).upper(), 0)


# =========================================================
# MODULE SELF-TEST (optional)
# =========================================================

if __name__ == "__main__":
    sample = {
        "processes": [
            {
                "name": "powershell.exe",
                "pid": 4321,
                "cpu_percent": 12,
                "memory_percent": 3,
                "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmdline": "powershell.exe -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            },
            {
                "name": "svchost.exe",
                "pid": 900,
                "cpu_percent": 3,
                "memory_percent": 2,
                "exe": "C:\\Users\\Public\\svchost.exe",
                "cmdline": "svchost.exe",
            },
        ],
        "connections": [
            {
                "raddr": {"ip": "203.0.113.45", "port": 4444},
                "status": "ESTABLISHED",
                "process_name": "unknown.exe",
                "pid": 1234,
            },
        ],
    }

    import json
    print(json.dumps(detect(sample), indent=2))