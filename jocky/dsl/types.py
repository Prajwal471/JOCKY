"""Type system for JOCKY v0.1.

Primitives, shapes (collections), and the opaque forensic domain types
defined in the language spec. Type expressions parse to instances of
``TypeRef``; the checker annotates AST nodes with them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional as PyOptional


@dataclass(frozen=True)
class TypeRef:
    name: str
    params: tuple["TypeRef", ...] = ()

    def __str__(self) -> str:
        if not self.params:
            return self.name
        inner = ", ".join(str(p) for p in self.params)
        return f"{self.name}<{inner}>"

    def to_jir(self) -> dict:
        return {"name": self.name, "params": [p.to_jir() for p in self.params]}


PRIMITIVES = ("int", "float", "bool", "string", "bytes", "timestamp", "duration", "none")
SHAPES = ("list", "set", "map", "table", "optional")

# Opaque forensic domain types: values created only by capability-gated
# collectors; normal code can project fields but never construct them.
DOMAIN_TYPES = (
    "Process",
    "NetworkConnection",
    "Service",
    "Driver",
    "Autostart",
    "Event",
    "Finding",
    "Evidence",
    "SystemInfo",
    "LotlVector",
)


def t(name: str, *params: "TypeRef | str") -> TypeRef:
    return TypeRef(name, tuple(p if isinstance(p, TypeRef) else TypeRef(p) for p in params))


INT = t("int")
FLOAT = t("float")
BOOL = t("bool")
STRING = t("string")
BYTES = t("bytes")
TIMESTAMP = t("timestamp")
DURATION = t("duration")
NONE = t("none")

PROCESS = t("Process")
NETWORK = t("NetworkConnection")
SERVICE = t("Service")
DRIVER = t("Driver")
AUTOSTART = t("Autostart")
EVENT = t("Event")
FINDING = t("Finding")
EVIDENCE = t("Evidence")
SYSTEM_INFO = t("SystemInfo")
LOTL = t("LotlVector")

DOMAIN_REGISTRY: dict[str, dict] = {
    "Process": {
        "fields": {
            "pid": INT, "ppid": INT, "name": STRING, "exe": STRING,
            "username": STRING, "created": TIMESTAMP, "threads": INT,
        },
    },
    "NetworkConnection": {
        "fields": {
            "pid": INT, "process_name": STRING, "state": STRING,
            "local_addr": STRING, "local_port": INT,
            "remote_addr": STRING, "remote_port": INT,
            "remote_hostname": STRING, "direction": STRING,
        },
    },
    "Service": {
        "fields": {
            "name": STRING, "display": STRING, "state": STRING,
            "start_type": STRING, "path": STRING, "pid": INT,
        },
    },
    "Driver": {
        "fields": {
            "name": STRING, "path": STRING, "signed": BOOL,
            "signer": STRING, "state": STRING, "known_vulns": BOOL,
        },
    },
    "Autostart": {
        "fields": {
            "name": STRING, "command": STRING, "location": STRING,
            "enabled": BOOL, "user": STRING,
        },
    },
    "Event": {
        "fields": {
            "channel": STRING, "event_id": INT, "level": INT,
            "provider": STRING, "message": STRING, "observed_at": TIMESTAMP,
        },
    },
    "Finding": {
        "fields": {
            "rule": STRING, "severity": STRING, "endpoint": STRING,
            "detail": STRING, "observed_at": TIMESTAMP,
        },
    },
    "Evidence": {
        "fields": {
            "finding_type": STRING, "source": STRING, "payload": t("map", STRING, STRING),
            "observed_at": TIMESTAMP, "chain_hash": STRING, "signed_by": STRING,
        },
    },
    "SystemInfo": {
        "fields": {
            "hostname": STRING, "platform": STRING, "os_version": STRING,
            "collector_version": STRING, "privileges": STRING,
        },
    },
    "LotlVector": {
        "fields": {
            "category": STRING, "vector": STRING, "path": STRING,
            "exploitable": BOOL, "detail": STRING,
        },
    },
}

# Capability consumed by each unit of analysis.
CAPABILITIES = frozenset({
    "process:list",   # enumerate running processes
    "process:detail",     # module metadata for a process
    "network:list",       # socket / connection table
    "network:analyze",    # PID<->socket correlation + anomaly scoring
    "service:list",       # service manager enumeration
    "driver:list",        # driver inventory + signature state
    "persistence:list",   # autostart / Run keys
    "event:read",         # event log channels (non-Security by default)
    "lotl:scan",          # local LOTL + privilege-escalation vector scan
    "evidence:sign",      # produce signed evidence records
    "collection:dispatch",  # fan-out to multiple endpoints
})

# Capabilities that are *never* granted at compile policy time:
NEVER_GRANT = frozenset({
    "edr:disable", "defender:disable", "amsi:bypass", "etw:patch",
    "inject:cross_process", "privilege:escalation", "mitm:network",
    "kernel:write",
})