"""Bound collector library for JOCKY v0.1.

Each top-level function maps to exactly one capability.  Calls are only
dispatched when the invoking mission declares that capability (enforced by
the interpreter).  With ``config.SAMPLE_DATA`` set the library returns
deterministic synthetic rows (tests); otherwise it delegates to the live
Windows harvesters (``jocky.runtime.harvesters``) so the demo shows real
process/network/service/driver data under the caller's own token.
"""

from __future__ import annotations

from typing import Any

from jocky.config import SAMPLE_DATA
from jocky.dsl.types import DOMAIN_REGISTRY

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
    "probe_registry": "registry:query",
    "probe_service": "service:probe",
    "probe_identity": "identity:probe",
}

BOOLEAN_ASSIST = {
    "collect_processes": "toolhelp32 snapshot (CreateToolhelp32Snapshot)",
    "analyze_network_connections": "GetExtendedTcpTable / UDP table + PID correlation",
    "list_services": "SERVICE_WIN32 enumeration via SCM (QueryServiceConfig)",
    "list_drivers": "SERVICE_DRIVER enumeration + WinVerifyTrust/Authenticode signature state",
    "list_autostarts": "winreg Run/RunOnce + Startup folders",
    "read_events": "wevtutil Application+System channels (unelevated)",
    "scan_lotl": "local file scan for Living-off-the-Land binaries",
    "sign_evidence": "Ed25519 record signature (agent key)",
    "dispatch": "fan-out mission to endorsed endpoints",
    "probe_registry": "winreg OpenKey/EnumValue read of a named hive key",
    "probe_service": "SCM sc qc read of a named service config",
    "probe_identity": "whoami /user + effective-privilege probe",
}


def _rows(dtype: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = set(DOMAIN_REGISTRY[dtype]["fields"])
    return [dict((k, r[k]) for k in fields if k in r) for r in rows]


if SAMPLE_DATA:
    from jocky.runtime import _sample as S

    def collect_processes() -> list[dict[str, Any]]:
        return _rows("Process", S.SAMPLE_PROCESSES)

    def analyze_network_connections() -> list[dict[str, Any]]:
        return _rows("NetworkConnection", S.SAMPLE_NETWORK)

    def list_services() -> list[dict[str, Any]]:
        return _rows("Service", S.SAMPLE_SERVICES)

    def list_drivers() -> list[dict[str, Any]]:
        return _rows("Driver", S.SAMPLE_DRIVERS)

    def list_autostarts() -> list[dict[str, Any]]:
        return _rows("Autostart", S.SAMPLE_AUTOSTARTS)

    def read_events() -> list[dict[str, Any]]:
        return _rows("Event", S.SAMPLE_EVENTS)

    def scan_lotl() -> list[dict[str, Any]]:
        return _rows("LotlVector", S.SAMPLE_LOTL)

    def sign_evidence(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

    def probe_registry(key_path: str) -> list[dict[str, Any]]:
        return _rows("RegistryValue", S.SAMPLE_REGISTRY)

    def probe_service(service_name: str) -> list[dict[str, Any]]:
        return _rows("ServiceConfig", S.SAMPLE_SERVICECONFIG)

    def probe_identity() -> list[dict[str, Any]]:
        return _rows("Identity", S.SAMPLE_IDENTITY)
else:
    from jocky.runtime import harvesters as H

    def collect_processes() -> list[dict[str, Any]]:
        return _rows("Process", H.proc_rows())

    def analyze_network_connections() -> list[dict[str, Any]]:
        return _rows("NetworkConnection", H.connection_rows())

    def list_services() -> list[dict[str, Any]]:
        return _rows("Service", H.service_rows())

    def list_drivers() -> list[dict[str, Any]]:
        return _rows("Driver", H.driver_rows())

    def list_autostarts() -> list[dict[str, Any]]:
        return _rows("Autostart", H.autostart_rows())

    def read_events() -> list[dict[str, Any]]:
        return _rows("Event", H.event_rows())

    def scan_lotl() -> list[dict[str, Any]]:
        return _rows("LotlVector", H.lotl_rows())

    def sign_evidence(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return _rows("Evidence", [
            {"finding_type": "observed", "source": "collectors.live",
             "payload": {"rows": rows}, "observed_at": "2026-09-29T04:00:00Z",
             "chain_hash": "", "signed_by": ""}
        ])

    def dispatch(endpoint: str, mission: str) -> list[dict[str, Any]]:
        return _rows("SystemInfo", H.system_info(endpoint))

    def probe_registry(key_path: str) -> list[dict[str, Any]]:
        return _rows("RegistryValue", H.registry_probe(key_path))

    def probe_service(service_name: str) -> list[dict[str, Any]]:
        return _rows("ServiceConfig", H.service_probe(service_name))

    def probe_identity() -> list[dict[str, Any]]:
        return _rows("Identity", H.identity_probe())


BOUND_BUILTINS: frozenset[str] = frozenset(BUILTIN_CAPABILITIES)

__all__ = [
    "SAMPLE_DATA",
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