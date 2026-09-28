"""Bound collector library for JOCKY v0.1.

Each top-level function maps to exactly one capability. Calls are only
dispatched when the invoking mission declares that capability (enforced by
the interpreter). ``SAMPLE`` marks this stage's synthetic harness data;
Block 4 replaces it with the live ctypes/mission-critical harvesters while
keeping the same row schemas (the "seamed" interface).
"""

from __future__ import annotations

from typing import Any

from jocky.dsl.types import DOMAIN_REGISTRY

SAMPLE = True  # synthetic harness rows until Block 4 harvest is wired

# fn name -> capability it consumes
BUILTIN_CAPABILITIES: dict[str, str] = {
    "collect_processes": "process:list",
    "analyze_network_connections": "network:analyze",
    "list_services": "service:list",
    "list_drivers": "driver:list",
    "list_autostarts": "persistence:list",
    "read_events": "event:read",
    "scan_lotl": "lotl:scan",
    "sign_evidence": "evidence:sign",
    "dispatch": "collection:dispatch",
}

BOOLEAN_ASSIST = {
    "collect_processes": "toolhelp32 snapshot (CreateToolhelp32Snapshot)",
    "analyze_network_connections": "GetExtendedTcpTable / UDP table + PID correlation",
    "list_services": "sc.exe query state= all",
    "list_drivers": "drvload / setupapi driver-store inventory",
    "list_autostarts": "winreg Run/RunOnce + Startup folders",
    "read_events": "pdh/EventLog Application+System channels",
    "scan_lotl": "local file scan for Living-off-the-Land binaries",
    "sign_evidence": "Ed25519 record signature (agent key)",
    "dispatch": "fan-out mission to endorsed endpoints",
}


def _rows(dtype: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = set(DOMAIN_REGISTRY[dtype]["fields"])
    return [dict((k, r[k]) for k in fields if k in r) for r in rows]


def collect_processes() -> list[dict[str, Any]]:
    return _rows("Process", [
        {"pid": 4, "ppid": 0, "name": "System", "exe": "ntoskrnl.exe",
         "username": "SYSTEM", "created": "2026-01-01T00:00:00Z", "threads": 45},
        {"pid": 452, "ppid": 4, "name": "svchost.exe", "exe": r"C:\Windows\System32\svchost.exe",
         "username": "SYSTEM", "created": "2026-01-01T00:00:05Z", "threads": 21},
        {"pid": 812, "ppid": 4, "name": "winlogon.exe", "exe": r"C:\Windows\System32\winlogon.exe",
         "username": "SYSTEM", "created": "2026-01-01T00:00:07Z", "threads": 6},
        {"pid": 1204, "ppid": 812, "name": "VBoxService.exe", "exe": r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxService.exe",
         "username": "SYSTEM", "created": "2026-01-01T00:00:08Z", "threads": 9},
        {"pid": 1488, "ppid": 452, "name": "dwm.exe", "exe": r"C:\Windows\System32\dwm.exe",
         "username": "DWM-1", "created": "2026-01-01T00:00:12Z", "threads": 12},
        {"pid": 1620, "ppid": 1204, "name": "VBoxTray.exe", "exe": r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxTray.exe",
         "username": "Loq", "created": "2026-01-01T00:00:13Z", "threads": 5},
    ])


def analyze_network_connections() -> list[dict[str, Any]]:
    return _rows("NetworkConnection", [
        {"pid": 452, "process_name": "svchost.exe", "state": "ESTABLISHED",
         "local_addr": "10.0.2.15", "local_port": 50042,
         "remote_addr": "151.101.2.132", "remote_port": 443,
         "remote_hostname": "cdn.example-cdn.net", "direction": "outbound"},
        {"pid": 4, "process_name": "System", "state": "LISTEN",
         "local_addr": "0.0.0.0", "local_port": 445,
         "remote_addr": "0.0.0.0", "remote_port": 0,
         "remote_hostname": "", "direction": "inbound"},
        {"pid": 812, "process_name": "winlogon.exe", "state": "CLOSE_WAIT",
         "local_addr": "10.0.2.15", "local_port": 5041,
         "remote_addr": "8.8.8.8", "remote_port": 53,
         "remote_hostname": "dns.google", "direction": "outbound"},
    ])


def list_services() -> list[dict[str, Any]]:
    return _rows("Service", [
        {"name": "wuauserv", "display": "Windows Update", "state": "RUNNING",
         "start_type": "AUTO_START", "path": r"C:\Windows\system32\svchost.exe -k netsvcs", "pid": 452},
        {"name": "LanmanServer", "display": "Server", "state": "RUNNING",
         "start_type": "AUTO_START", "path": r"C:\Windows\system32\svchost.exe -k netsvcs", "pid": 452},
        {"name": "Spooler", "display": "Print Spooler", "state": "STOPPED",
         "start_type": "AUTO_START", "path": r"C:\Windows\System32\spoolsv.exe", "pid": -1},
    ])


def list_drivers() -> list[dict[str, Any]]:
    return _rows("Driver", [
        {"name": "VBoxGuest", "path": r"C:\Windows\System32\drivers\VBoxGuest.sys",
         "signed": True, "signer": "Oracle Corporation", "state": "RUNNING", "known_vulns": False},
        {"name": "Null", "path": r"C:\Windows\System32\drivers\Null.sys",
         "signed": True, "signer": "Microsoft Windows", "state": "RUNNING", "known_vulns": False},
    ])


def list_autostarts() -> list[dict[str, Any]]:
    return _rows("Autostart", [
        {"name": "VBoxTray", "command": r'"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxTray.exe"',
         "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "enabled": True, "user": "Loq"},
        {"name": "OneDriveSetup", "command": r"C:\Windows\SysWOW64\OneDriveSetup.exe",
         "location": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "enabled": True, "user": "SYSTEM"},
    ])


def read_events() -> list[dict[str, Any]]:
    return _rows("Event", [
        {"channel": "Application", "event_id": 1001, "level": 4,
         "provider": "Windows Error Reporting", "message": "crash bucket", "observed_at": "2026-09-29T02:11:00Z"},
        {"channel": "System", "event_id": 7045, "level": 4,
         "provider": "Service Control Manager", "message": "A service was installed", "observed_at": "2026-09-29T03:40:00Z"},
    ])


def scan_lotl() -> list[dict[str, Any]]:
    return _rows("LotlVector", [
        {"category": "dual-use", "vector": "cmd.exe", "path": r"C:\Windows\System32\cmd.exe",
         "exploitable": True, "detail": "present and unconstrained"},
        {"category": "remote", "vector": "bitsadmin", "path": r"C:\Windows\System32\bitsadmin.exe",
         "exploitable": True, "detail": "present and unconstrained"},
        {"category": "signed-abuse", "vector": "rundll32.exe", "path": r"C:\Windows\System32\rundll32.exe",
         "exploitable": True, "detail": "present and unconstrained"},
    ])


def sign_evidence(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """evidence:sign — wraps records (used after real signing in Block 3)."""
    return _rows("Evidence", [
        {"finding_type": "observed", "source": "collectors.synthetic",
         "payload": {"rows": rows}, "observed_at": "2026-09-29T04:00:00Z",
         "chain_hash": "", "signed_by": ""}
    ])


def dispatch(endpoint: str, mission: str) -> list[dict[str, Any]]:
    return _rows("SystemInfo", [
        {"hostname": endpoint, "platform": "windows", "os_version": "10.0",
         "collector_version": "0.1.0", "privileges": "none"}
    ])


BOUND_BUILTINS: frozenset[str] = frozenset(BUILTIN_CAPABILITIES)

__all__ = [
    "SAMPLE",
    "BUILTIN_CAPABILITIES",
    "BOOLEAN_ASSIST",
    "BOUND_BUILTINS",
    "collect_processes",
    "analyze_network_connections",
    "list_services",
    "list_drivers",
    "list_autostarts",
    "read_events",
    "scan_lotl",
    "sign_evidence",
    "dispatch",
]