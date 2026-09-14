"""
ABACUS Security Monitor
Correlation Engine v0.2.0

Purpose
-------
Turns related detection/risk-condition signals into coherent incident candidates.

Architecture
------------
    detection.py
        |
        v
    risk_conditions
        |
        v
    correlation.py
        |
        v
    incident candidate
        |
        v
    incident/risk engine

Design principles
-----------------
1. A condition is an observation. An incident is a correlated story.
2. Do not sum overlapping conditions blindly.
3. Correlation increases confidence and context, not certainty.
4. Stable identities are preferred over volatile evidence such as CPU values.
5. One condition may belong to one incident candidate in a correlation pass.
6. Uncorrelated conditions remain valid conditions.
7. Correlation is deterministic and side-effect free.
8. This module does not execute response actions.
9. Network conclusions require contextual evidence, not merely a suspicious port.
10. Scores are bounded and explainable.

Initial correlation families
----------------------------
CORR-EXEC-001   Suspicious process execution
CORR-C2-001     Possible command and control
CORR-EXFIL-001  Possible data exfiltration
CORR-RECON-001  Possible reconnaissance

The engine accepts the dictionaries returned by:
    GET /api/devices/{device_id}/conditions

It can also accept normalized Detection-like dictionaries.

No database dependency is required.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


CORRELATION_ENGINE_VERSION = "0.2.1"

# Correlation windows are deliberately bounded. A relationship should not
# remain valid forever simply because two signals happened to occur on a host.
DEFAULT_WINDOW_SECONDS = 300

# Maximum contribution from correlation itself. This prevents a large number
# of weak corroborating signals from becoming an automatic critical incident.
MAX_CORRELATION_BONUS = 20.0

SEVERITY_WEIGHT = {
    "CRITICAL": 1.00,
    "HIGH": 0.90,
    "MEDIUM": 0.65,
    "LOW": 0.35,
    "INFO": 0.10,
}

CONFIDENCE_WEIGHT = {
    "HIGH": 1.00,
    "MEDIUM": 0.80,
    "LOW": 0.55,
    "UNKNOWN": 0.40,
}

SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass(frozen=True)
class CorrelationRule:
    rule_id: str
    title: str
    category: str
    description: str
    required_rule_ids: Tuple[str, ...]
    minimum_conditions: int
    window_seconds: int
    base_risk: float
    correlation_bonus: float
    severity: str
    confidence: str
    attack_stage: str
    mitre_id: Optional[str] = None


@dataclass
class IncidentCandidate:
    incident_key: str
    correlation_rule_id: str
    device_id: str
    title: str
    category: str
    description: str
    severity: str
    confidence: str
    attack_stage: str
    mitre_id: Optional[str]
    state: str
    risk_score: float
    base_risk: float
    correlation_bonus: float
    first_seen: str
    last_seen: str
    condition_count: int
    condition_keys: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    rationale: List[str] = field(default_factory=list)
    source_types: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    processes: List[str] = field(default_factory=list)
    destinations: List[str] = field(default_factory=list)
    occurrence_count: int = 1
    engine_version: str = CORRELATION_ENGINE_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Correlation catalogue
# ---------------------------------------------------------------------------

CORRELATION_RULES: Tuple[CorrelationRule, ...] = (
    CorrelationRule(
        rule_id="CORR-EXEC-001",
        title="Suspicious process execution",
        category="execution",
        description=(
            "Correlates multiple process-execution signals belonging to the "
            "same process into one suspicious execution incident."
        ),
        required_rule_ids=(
            "PROC-CMD-001",
            "PROC-SCRIPT-001",
            "PROC-PATH-001",
            "PROC-EXEC-001",
            "PROC-MASQ-001",
        ),
        minimum_conditions=2,
        window_seconds=300,
        base_risk=22.0,
        correlation_bonus=10.0,
        severity="HIGH",
        confidence="HIGH",
        attack_stage="execution",
        mitre_id="T1059",
    ),
    CorrelationRule(
        rule_id="CORR-C2-001",
        title="Possible command and control",
        category="command_and_control",
        description=(
            "Correlates repeated or periodic outbound behavior with "
            "destination rarity, unusual ports, or behavioral beaconing."
        ),
        required_rule_ids=(
            "NET-PORT-001",
            "NET-BEACON-001",
            "NET-RARE-DEST-001",
            "NET-PERIODIC-001",
            "NET-JITTER-001",
        ),
        minimum_conditions=2,
        window_seconds=300,
        base_risk=30.0,
        correlation_bonus=12.0,
        severity="HIGH",
        confidence="MEDIUM",
        attack_stage="command_and_control",
        mitre_id="T1071",
    ),
    CorrelationRule(
        rule_id="CORR-EXFIL-001",
        title="Possible data exfiltration",
        category="exfiltration",
        description=(
            "Correlates unusual outbound volume with destination rarity, "
            "directional asymmetry, or unusual session behavior."
        ),
        required_rule_ids=(
            "NET-OUTBOUND-SPIKE-001",
            "NET-RARE-DEST-001",
            "NET-BYTE-ASYMMETRY-001",
            "NET-DEST-ENTROPY-001",
            "NET-LARGE-TRANSFER-001",
        ),
        minimum_conditions=2,
        window_seconds=600,
        base_risk=35.0,
        correlation_bonus=15.0,
        severity="HIGH",
        confidence="MEDIUM",
        attack_stage="exfiltration",
        mitre_id="T1041",
    ),
    CorrelationRule(
        rule_id="CORR-RECON-001",
        title="Possible network reconnaissance",
        category="reconnaissance",
        description=(
            "Correlates destination/port diversity and failed connection "
            "behavior into a reconnaissance incident."
        ),
        required_rule_ids=(
            "NET-SCAN-001",
            "NET-RARE-DEST-001",
            "NET-PORT-DIVERSITY-001",
            "NET-DEST-DIVERSITY-001",
            "NET-CONNECTION-FAILURE-001",
            "NET-RARE-PORT-001",
        ),
        minimum_conditions=2,
        window_seconds=300,
        base_risk=24.0,
        correlation_bonus=10.0,
        severity="MEDIUM",
        confidence="MEDIUM",
        attack_stage="discovery",
        mitre_id="T1046",
    ),
)


RULES_BY_ID = {rule.rule_id: rule for rule in CORRELATION_RULES}


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _text(value: Any) -> str:
    return str(value or "").strip()


def _upper(value: Any) -> str:
    return _text(value).upper()


def _lower(value: Any) -> str:
    return _text(value).lower()


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        dt = value
    else:
        raw = _text(value)
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _condition_key(condition: Dict[str, Any]) -> str:
    return _text(
        condition.get("condition_key")
        or condition.get("signal_key")
        or condition.get("fingerprint")
        or condition.get("rule_id")
        or "unknown-condition"
    )


def _rule_id(condition: Dict[str, Any]) -> str:
    return _text(condition.get("rule_id"))


def _source_type(condition: Dict[str, Any]) -> str:
    return _lower(condition.get("source_type") or condition.get("telemetry_type"))


def _evidence(condition: Dict[str, Any]) -> Dict[str, Any]:
    value = condition.get("evidence")
    return value if isinstance(value, dict) else {}


def _process_identity(condition: Dict[str, Any]) -> str:
    evidence = _evidence(condition)
    name = _lower(
        evidence.get("process_name")
        or evidence.get("name")
        or condition.get("process_name")
    )
    pid = _text(evidence.get("pid") or condition.get("pid"))

    # PID is useful during a single correlation window but is not a durable
    # identity. The correlation window prevents old PID reuse from joining.
    if name and pid:
        return f"{name}:pid:{pid}"
    if name:
        return name
    return ""


def _user_identity(condition: Dict[str, Any]) -> str:
    evidence = _evidence(condition)
    return _lower(
        evidence.get("username")
        or evidence.get("user")
        or condition.get("username")
        or condition.get("user")
    )


def _destination_identity(condition: Dict[str, Any]) -> str:
    evidence = _evidence(condition)
    value = (
        evidence.get("remote_ip")
        or evidence.get("destination_ip")
        or evidence.get("remote_host")
        or evidence.get("destination")
        or condition.get("remote_ip")
        or condition.get("destination_ip")
    )
    return _text(value)


def _port_identity(condition: Dict[str, Any]) -> Optional[int]:
    evidence = _evidence(condition)
    value = (
        evidence.get("remote_port")
        or evidence.get("destination_port")
        or condition.get("remote_port")
        or condition.get("destination_port")
    )
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _is_external_destination(value: str) -> bool:
    if not value:
        return False

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        # Hostnames cannot safely be classified as internal here.
        # Treat them as unknown rather than external.
        return False

    return not (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    )


def _severity_max(values: Iterable[str]) -> str:
    normalized = [_upper(v) for v in values if _text(v)]
    if not normalized:
        return "LOW"
    return max(normalized, key=lambda v: SEVERITY_RANK.get(v, 0))


def _confidence_from_conditions(conditions: Sequence[Dict[str, Any]]) -> str:
    if not conditions:
        return "UNKNOWN"

    # Correlation requires agreement from multiple observations. The median-ish
    # approach avoids one LOW-confidence signal being allowed to erase stronger
    # evidence while also avoiding "any HIGH means HIGH".
    weights = sorted(
        CONFIDENCE_WEIGHT.get(
            _upper(c.get("confidence") or "UNKNOWN"), 0.40
        )
        for c in conditions
    )

    middle = weights[len(weights) // 2]

    if middle >= 0.95:
        return "HIGH"
    if middle >= 0.70:
        return "MEDIUM"
    return "LOW"


def _stable_incident_key(
    device_id: str,
    correlation_rule_id: str,
    grouping_identity: str,
) -> str:
    raw = f"{device_id}|{correlation_rule_id}|{grouping_identity}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _condition_time(condition: Dict[str, Any]) -> Optional[datetime]:
    return (
        _parse_timestamp(condition.get("last_seen"))
        or _parse_timestamp(condition.get("first_seen"))
        or _parse_timestamp(condition.get("detected_at"))
    )


def _within_window(
    conditions: Sequence[Dict[str, Any]],
    window_seconds: int,
) -> bool:
    timestamps = [
        ts for ts in (_condition_time(c) for c in conditions) if ts is not None
    ]

    if len(timestamps) < 2:
        # A missing timestamp should not prevent deterministic correlation in
        # unit tests or during migration, but we don't claim time certainty.
        return True

    return (max(timestamps) - min(timestamps)).total_seconds() <= window_seconds


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------

def _execution_group_key(condition: Dict[str, Any]) -> str:
    process = _process_identity(condition)
    user = _user_identity(condition)

    if process:
        return f"process:{process}|user:{user}"

    # Fall back to condition identity only when process evidence is absent.
    return f"condition:{_condition_key(condition)}"


def _network_group_key(condition: Dict[str, Any]) -> str:
    destination = _destination_identity(condition)
    user = _user_identity(condition)

    if destination:
        return f"destination:{destination}|user:{user}"

    # For scanning/recon signals, the device/user/time window is more useful
    # than inventing a destination identity.
    return f"network|user:{user}"


def _group_key(
    rule: CorrelationRule,
    condition: Dict[str, Any],
) -> str:
    if rule.category == "execution":
        return _execution_group_key(condition)

    # Reconnaissance is a host-level behavioral story. A scan signal and the
    # rare destinations it explains may have different destination identities,
    # so grouping reconnaissance by destination would prevent them from ever
    # becoming one incident. Keep C2/exfiltration grouping destination-aware.
    if rule.category == "reconnaissance":
        user = _user_identity(condition)
        return f"reconnaissance|user:{user}"

    return _network_group_key(condition)


def _group_conditions(
    conditions: Sequence[Dict[str, Any]],
    rule: CorrelationRule,
) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}

    for condition in conditions:
        rid = _rule_id(condition)

        if rid not in rule.required_rule_ids:
            continue

        if _upper(condition.get("state") or "ACTIVE") not in {
            "NEW",
            "ACTIVE",
            "REINFORCED",
        }:
            continue

        key = _group_key(rule, condition)
        groups.setdefault(key, []).append(condition)

    return groups


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _condition_quality(condition: Dict[str, Any]) -> float:
    severity = _upper(condition.get("severity") or "LOW")
    confidence = _upper(condition.get("confidence") or "UNKNOWN")

    severity_weight = SEVERITY_WEIGHT.get(severity, 0.35)
    confidence_weight = CONFIDENCE_WEIGHT.get(confidence, 0.40)

    return round(severity_weight * confidence_weight, 4)


def _dedupe_conditions(
    conditions: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    seen = set()
    result = []

    for condition in conditions:
        key = _condition_key(condition)
        if key in seen:
            continue
        seen.add(key)
        result.append(condition)

    return result


def _calculate_incident_score(
    rule: CorrelationRule,
    conditions: Sequence[Dict[str, Any]],
) -> Tuple[float, float, List[str]]:
    conditions = _dedupe_conditions(conditions)

    if not conditions:
        return 0.0, 0.0, []

    strongest = max(
        conditions,
        key=lambda c: (
            SEVERITY_WEIGHT.get(_upper(c.get("severity") or "LOW"), 0.35)
            * CONFIDENCE_WEIGHT.get(
                _upper(c.get("confidence") or "UNKNOWN"), 0.40
            )
        ),
    )

    strongest_risk = float(
        strongest.get("effective_risk")
        or strongest.get("risk_contribution")
        or 0.0
    )

    # The strongest signal forms the core. Other distinct signals provide
    # bounded corroboration instead of being fully summed again.
    base = max(rule.base_risk, strongest_risk)

    distinct_rule_count = len({_rule_id(c) for c in conditions})
    distinct_source_count = len({_source_type(c) for c in conditions if _source_type(c)})

    bonus = 0.0
    rationale = []

    if distinct_rule_count >= 2:
        bonus += min(rule.correlation_bonus, 10.0)
        rationale.append(
            f"{distinct_rule_count} distinct detection rules corroborate the behavior"
        )

    if distinct_source_count >= 2:
        bonus += 4.0
        rationale.append(
            f"Evidence spans {distinct_source_count} telemetry sources"
        )

    if len(conditions) >= 3:
        bonus += 2.0
        rationale.append("At least three related conditions are active")

    # Never let correlation itself contribute more than the global cap.
    bonus = min(bonus, MAX_CORRELATION_BONUS)

    # Keep the score bounded and explainable.
    score = min(100.0, round(base + bonus, 2))

    if strongest_risk:
        rationale.insert(
            0,
            f"Strongest observed condition contributes {strongest_risk:.2f}",
        )

    return score, round(bonus, 2), rationale


# ---------------------------------------------------------------------------
# Individual correlation families
# ---------------------------------------------------------------------------

def _correlate_execution(
    device_id: str,
    conditions: Sequence[Dict[str, Any]],
    rule: CorrelationRule,
) -> List[IncidentCandidate]:
    incidents: List[IncidentCandidate] = []

    for grouping_identity, group in _group_conditions(conditions, rule).items():
        group = _dedupe_conditions(group)

        if len({_rule_id(c) for c in group}) < rule.minimum_conditions:
            continue

        if not _within_window(group, rule.window_seconds):
            continue

        process_names = sorted(
            {
                _process_identity(c).split(":pid:", 1)[0]
                for c in group
                if _process_identity(c)
            }
        )

        users = sorted(
            {u for u in (_user_identity(c) for c in group) if u}
        )

        score, bonus, rationale = _calculate_incident_score(rule, group)

        timestamps = [
            ts for ts in (_condition_time(c) for c in group) if ts is not None
        ]

        now = datetime.now(timezone.utc)
        first_seen = _iso(min(timestamps)) if timestamps else _iso(now)
        last_seen = _iso(max(timestamps)) if timestamps else _iso(now)

        process_label = ", ".join(process_names) or "unknown process"
        title = f"{rule.title}: {process_label}"

        incident_key = _stable_incident_key(
            device_id,
            rule.rule_id,
            grouping_identity,
        )

        incidents.append(
            IncidentCandidate(
                incident_key=incident_key,
                correlation_rule_id=rule.rule_id,
                device_id=device_id,
                title=title,
                category=rule.category,
                description=rule.description,
                severity=_severity_max(
                    [rule.severity]
                    + [c.get("severity", "LOW") for c in group]
                ),
                confidence=_confidence_from_conditions(group),
                attack_stage=rule.attack_stage,
                mitre_id=rule.mitre_id,
                state="NEW",
                risk_score=score,
                base_risk=round(score - bonus, 2),
                correlation_bonus=bonus,
                first_seen=first_seen,
                last_seen=last_seen,
                condition_count=len(group),
                condition_keys=sorted(_condition_key(c) for c in group),
                evidence=[_evidence(c) for c in group if _evidence(c)],
                rationale=rationale,
                source_types=sorted(
                    {s for s in (_source_type(c) for c in group) if s}
                ),
                users=users,
                processes=process_names,
                destinations=sorted(
                    {
                        d
                        for d in (_destination_identity(c) for c in group)
                        if d
                    }
                ),
                occurrence_count=max(
                    [int(c.get("occurrence_count") or 1) for c in group]
                    or [1]
                ),
            )
        )

    return incidents


def _correlate_c2(
    device_id: str,
    conditions: Sequence[Dict[str, Any]],
    rule: CorrelationRule,
) -> List[IncidentCandidate]:
    incidents: List[IncidentCandidate] = []

    for grouping_identity, group in _group_conditions(conditions, rule).items():
        group = _dedupe_conditions(group)

        if len({_rule_id(c) for c in group}) < rule.minimum_conditions:
            continue

        if not _within_window(group, rule.window_seconds):
            continue

        destinations = sorted(
            {
                d
                for d in (_destination_identity(c) for c in group)
                if d
            }
        )

        external_destinations = [
            d for d in destinations if _is_external_destination(d)
        ]

        ports = sorted(
            {
                p
                for p in (_port_identity(c) for c in group)
                if p is not None
            }
        )

        score, bonus, rationale = _calculate_incident_score(rule, group)

        if external_destinations:
            bonus = min(MAX_CORRELATION_BONUS, bonus + 3.0)
            score = min(100.0, round(score + 3.0, 2))
            rationale.append("At least one destination is externally routable")

        if ports:
            rationale.append(
                "Observed destination ports: " + ", ".join(map(str, ports))
            )

        timestamps = [
            ts for ts in (_condition_time(c) for c in group) if ts is not None
        ]
        now = datetime.now(timezone.utc)

        incidents.append(
            IncidentCandidate(
                incident_key=_stable_incident_key(
                    device_id, rule.rule_id, grouping_identity
                ),
                correlation_rule_id=rule.rule_id,
                device_id=device_id,
                title=rule.title,
                category=rule.category,
                description=rule.description,
                severity=_severity_max(
                    [rule.severity]
                    + [c.get("severity", "LOW") for c in group]
                ),
                confidence=_confidence_from_conditions(group),
                attack_stage=rule.attack_stage,
                mitre_id=rule.mitre_id,
                state="NEW",
                risk_score=score,
                base_risk=round(score - bonus, 2),
                correlation_bonus=bonus,
                first_seen=_iso(min(timestamps)) if timestamps else _iso(now),
                last_seen=_iso(max(timestamps)) if timestamps else _iso(now),
                condition_count=len(group),
                condition_keys=sorted(_condition_key(c) for c in group),
                evidence=[_evidence(c) for c in group if _evidence(c)],
                rationale=rationale,
                source_types=sorted(
                    {s for s in (_source_type(c) for c in group) if s}
                ),
                users=sorted(
                    {u for u in (_user_identity(c) for c in group) if u}
                ),
                processes=sorted(
                    {
                        _process_identity(c)
                        for c in group
                        if _process_identity(c)
                    }
                ),
                destinations=destinations,
                occurrence_count=max(
                    [int(c.get("occurrence_count") or 1) for c in group]
                    or [1]
                ),
            )
        )

    return incidents


def _correlate_exfiltration(
    device_id: str,
    conditions: Sequence[Dict[str, Any]],
    rule: CorrelationRule,
) -> List[IncidentCandidate]:
    # Exfiltration requires at least one outbound-volume/transfer signal.
    # This prevents a rare destination plus an unrelated anomaly from being
    # labeled as exfiltration.
    exfil_rule_ids = {
        "NET-OUTBOUND-SPIKE-001",
        "NET-BYTE-ASYMMETRY-001",
        "NET-LARGE-TRANSFER-001",
    }

    if not any(_rule_id(c) in exfil_rule_ids for c in conditions):
        return []

    return _correlate_c2_like_network_family(
        device_id,
        conditions,
        rule,
        extra_rationale="Outbound-volume or transfer evidence is present",
    )


def _correlate_recon(
    device_id: str,
    conditions: Sequence[Dict[str, Any]],
    rule: CorrelationRule,
) -> List[IncidentCandidate]:
    # Recon needs diversity/failure evidence. One unusual port is not enough.
    recon_rule_ids = {
        "NET-SCAN-001",
        "NET-RARE-DEST-001",
        "NET-PORT-DIVERSITY-001",
        "NET-DEST-DIVERSITY-001",
        "NET-CONNECTION-FAILURE-001",
        "NET-RARE-PORT-001",
    }

    filtered = [
        c for c in conditions
        if _rule_id(c) in recon_rule_ids
    ]

    if not filtered:
        return []

    # A rare destination is useful supporting evidence for a scan, but rare
    # destinations alone should not manufacture a reconnaissance incident.
    # Require an actual scan signal, or at least two non-rare reconnaissance
    # signals, before promoting the network behavior to an incident.
    rule_ids = {_rule_id(c) for c in filtered}
    non_rare_rule_ids = rule_ids - {"NET-RARE-DEST-001"}
    if "NET-SCAN-001" not in rule_ids and len(non_rare_rule_ids) < 2:
        return []

    return _correlate_c2_like_network_family(
        device_id,
        filtered,
        rule,
        extra_rationale="Multiple reconnaissance-oriented network signals are present",
    )


def _correlate_c2_like_network_family(
    device_id: str,
    conditions: Sequence[Dict[str, Any]],
    rule: CorrelationRule,
    extra_rationale: str,
) -> List[IncidentCandidate]:
    incidents: List[IncidentCandidate] = []

    for grouping_identity, group in _group_conditions(conditions, rule).items():
        group = _dedupe_conditions(group)

        if len({_rule_id(c) for c in group}) < rule.minimum_conditions:
            continue

        if not _within_window(group, rule.window_seconds):
            continue

        score, bonus, rationale = _calculate_incident_score(rule, group)
        rationale.append(extra_rationale)

        destinations = sorted(
            {
                d
                for d in (_destination_identity(c) for c in group)
                if d
            }
        )

        timestamps = [
            ts for ts in (_condition_time(c) for c in group) if ts is not None
        ]
        now = datetime.now(timezone.utc)

        incidents.append(
            IncidentCandidate(
                incident_key=_stable_incident_key(
                    device_id, rule.rule_id, grouping_identity
                ),
                correlation_rule_id=rule.rule_id,
                device_id=device_id,
                title=rule.title,
                category=rule.category,
                description=rule.description,
                severity=_severity_max(
                    [rule.severity]
                    + [c.get("severity", "LOW") for c in group]
                ),
                confidence=_confidence_from_conditions(group),
                attack_stage=rule.attack_stage,
                mitre_id=rule.mitre_id,
                state="NEW",
                risk_score=score,
                base_risk=round(score - bonus, 2),
                correlation_bonus=bonus,
                first_seen=_iso(min(timestamps)) if timestamps else _iso(now),
                last_seen=_iso(max(timestamps)) if timestamps else _iso(now),
                condition_count=len(group),
                condition_keys=sorted(_condition_key(c) for c in group),
                evidence=[_evidence(c) for c in group if _evidence(c)],
                rationale=rationale,
                source_types=sorted(
                    {s for s in (_source_type(c) for c in group) if s}
                ),
                users=sorted(
                    {u for u in (_user_identity(c) for c in group) if u}
                ),
                processes=sorted(
                    {
                        _process_identity(c)
                        for c in group
                        if _process_identity(c)
                    }
                ),
                destinations=destinations,
                occurrence_count=max(
                    [int(c.get("occurrence_count") or 1) for c in group]
                    or [1]
                ),
            )
        )

    return incidents


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def correlate(
    device_id: str,
    conditions: Sequence[Dict[str, Any]],
    *,
    now: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Correlate active risk conditions into incident candidates.

    Parameters
    ----------
    device_id:
        Stable device identifier.

    conditions:
        Sequence of condition dictionaries. The dictionaries may come directly
        from the risk_conditions API/database representation.

    now:
        Optional clock override for deterministic tests. Currently reserved for
        future lifecycle logic; timestamps supplied by conditions remain the
        authoritative observation times.

    Returns
    -------
    list[dict]
        Incident candidate dictionaries, sorted by descending risk.
    """
    del now  # Reserved for lifecycle-aware correlation in the next revision.

    normalized_device_id = _text(device_id)
    if not normalized_device_id:
        raise ValueError("device_id is required")

    clean_conditions = [
        dict(c)
        for c in conditions
        if isinstance(c, dict)
    ]

    incidents: List[IncidentCandidate] = []

    incidents.extend(
        _correlate_execution(
            normalized_device_id,
            clean_conditions,
            RULES_BY_ID["CORR-EXEC-001"],
        )
    )

    incidents.extend(
        _correlate_c2(
            normalized_device_id,
            clean_conditions,
            RULES_BY_ID["CORR-C2-001"],
        )
    )

    incidents.extend(
        _correlate_exfiltration(
            normalized_device_id,
            clean_conditions,
            RULES_BY_ID["CORR-EXFIL-001"],
        )
    )

    incidents.extend(
        _correlate_recon(
            normalized_device_id,
            clean_conditions,
            RULES_BY_ID["CORR-RECON-001"],
        )
    )

    # A condition can participate in multiple hypotheses in this v0.2 engine,
    # because one observation can legitimately support more than one story.
    # The incident layer must decide later whether overlapping incidents should
    # merge. We intentionally do not silently destroy evidence here.

    incidents.sort(
        key=lambda i: (
            -i.risk_score,
            -SEVERITY_RANK.get(i.severity, 0),
            i.correlation_rule_id,
            i.incident_key,
        )
    )

    return [incident.to_dict() for incident in incidents]


def correlate_conditions(
    device_id: str,
    conditions: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Compatibility alias for callers that prefer an explicit name."""
    return correlate(device_id, conditions)


def get_correlation_rules() -> List[Dict[str, Any]]:
    """Return the correlation catalogue for API/UI introspection."""
    return [asdict(rule) for rule in CORRELATION_RULES]


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _self_test() -> None:
    device_id = "TEST-DEVICE"

    synthetic_conditions = [
        {
            "condition_key": "PROC-CMD-001|behaviour|process:powershell.exe:pid:99999",
            "device_id": device_id,
            "source_type": "processes",
            "rule_id": "PROC-CMD-001",
            "title": "Encoded PowerShell command",
            "category": "behaviour",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "state": "ACTIVE",
            "risk_contribution": 25.0,
            "effective_risk": 21.25,
            "first_seen": "2026-09-10T16:28:32.256066+05:30",
            "last_seen": "2026-09-10T16:32:12.290022+05:30",
            "occurrence_count": 2,
            "evidence": {
                "process_name": "powershell.exe",
                "pid": 99999,
                "exe": r"C:\Users\User\AppData\Local\Temp\payload.exe",
                "cmdline": "powershell.exe -enc SQBtAHAAbwByAHQAYQBuAHQ=",
                "username": "User",
            },
        },
        {
            "condition_key": "PROC-SCRIPT-001|behaviour|process:powershell.exe:pid:99999",
            "device_id": device_id,
            "source_type": "processes",
            "rule_id": "PROC-SCRIPT-001",
            "title": "Scripting interpreter with suspicious arguments",
            "category": "behaviour",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "state": "ACTIVE",
            "risk_contribution": 18.0,
            "effective_risk": 15.3,
            "first_seen": "2026-09-10T16:28:32.268381+05:30",
            "last_seen": "2026-09-10T16:32:12.304111+05:30",
            "occurrence_count": 2,
            "evidence": {
                "process_name": "powershell.exe",
                "pid": 99999,
                "exe": r"C:\Users\User\AppData\Local\Temp\payload.exe",
                "cmdline": "powershell.exe -enc SQBtAHAAbwByAHQAYQBuAHQ=",
                "username": "User",
            },
        },
        {
            "condition_key": "PROC-PATH-001|behaviour|process:powershell.exe:pid:99999",
            "device_id": device_id,
            "source_type": "processes",
            "rule_id": "PROC-PATH-001",
            "title": "Process executing from suspicious location",
            "category": "behaviour",
            "severity": "MEDIUM",
            "confidence": "LOW",
            "state": "ACTIVE",
            "risk_contribution": 15.0,
            "effective_risk": 9.75,
            "first_seen": "2026-09-10T16:28:32.240883+05:30",
            "last_seen": "2026-09-10T16:32:12.272316+05:30",
            "occurrence_count": 2,
            "evidence": {
                "process_name": "powershell.exe",
                "pid": 99999,
                "exe": r"C:\Users\User\AppData\Local\Temp\payload.exe",
                "cmdline": "powershell.exe -enc SQBtAHAAbwByAHQAYQBuAHQ=",
                "username": "User",
            },
        },
    ]

    incidents = correlate(device_id, synthetic_conditions)

    assert incidents, "Expected an execution incident"
    assert incidents[0]["correlation_rule_id"] == "CORR-EXEC-001"
    assert incidents[0]["condition_count"] == 3
    assert incidents[0]["severity"] == "HIGH"
    assert incidents[0]["confidence"] == "MEDIUM"
    assert incidents[0]["risk_score"] <= 100.0
    assert incidents[0]["risk_score"] < 46.3, (
        "Correlation must not simply sum the three condition risks"
    )

    # A single suspicious port must not become a C2 incident.
    single_port = [
        {
            "condition_key": "NET-PORT-001|network|destination:1.2.3.4:4444",
            "device_id": device_id,
            "source_type": "network",
            "rule_id": "NET-PORT-001",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "state": "ACTIVE",
            "risk_contribution": 12.0,
            "effective_risk": 10.2,
            "last_seen": "2026-09-10T16:32:12+05:30",
            "evidence": {
                "remote_ip": "1.2.3.4",
                "remote_port": 4444,
            },
        }
    ]

    c2_incidents = correlate(device_id, single_port)
    assert not any(
        i["correlation_rule_id"] == "CORR-C2-001"
        for i in c2_incidents
    ), "One suspicious port must not create a C2 incident"

    print("=" * 72)
    print("ABACUS CORRELATION ENGINE")
    print(f"Version: {CORRELATION_ENGINE_VERSION}")
    print("=" * 72)
    print(f"[PASS] Execution correlation: {incidents[0]['title']}")
    print(f"[PASS] Conditions correlated: {incidents[0]['condition_count']}")
    print(f"[PASS] Incident severity: {incidents[0]['severity']}")
    print(f"[PASS] Incident confidence: {incidents[0]['confidence']}")
    print(f"[PASS] Incident risk: {incidents[0]['risk_score']}")
    print("[PASS] Single suspicious port does not become C2")
    print("=" * 72)


if __name__ == "__main__":
    _self_test()
