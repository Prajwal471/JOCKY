"""Coverage/matrix for the contested-space detection evaluation (Block 5).

Each collector capability maps to a clause describing the *mechanism* used to
observe it, whether that mechanism is live under the least-privilege token, and
which protected block of the contested-space model it addresses.  The matrix is
seeded into ``coverage_clauses`` by the dispatch path so the same table backs
the docs and the evaluator:
"""

from __future__ import annotations

from typing import Any

from jocky.dsl.types import CAPABILITIES
from jocky.server.db import CoverageClause

_SEED_NOTES = {
    "process:list": "toolhelp32 snapshot; per-process owner via process token",
    "network:analyze": "GetExtendedTcpTable/UDP + PID correlation (unelevated)",
    "service:list": "SCM EnumServicesStatusExW + QueryServiceConfigW",
    "driver:list": "SCM driver enum + Authenticode signature state (PowerShell batch)",
    "persistence:list": "winreg Run/RunOnce + Startup folder scan",
    "event:read": "wevtutil Application+System channels, namespace-agnostic XML",
    "lotl:scan": "local file scan for Living-off-the-Land dual-use binaries",
    "evidence:sign": "per-record Ed25519 signature over canonical hash chain",
    "registry:query": "winreg OpenKey/EnumValue read of a named hive key",
    "service:probe": "SCM sc qc read of a named service config",
    "identity:probe": "whoami /user + effective-privilege probe",
}

COVERAGE_SEED: list[dict[str, Any]] = [
    {
        "clause_id": cap,
        "title": cap.replace(":", " ").title(),
        "status": "LIVE",
        "mechanism": _SEED_NOTES.get(cap, ""),
        "protected_block": "",
        "notes": "live under least-privilege token; provenance privileges=none",
    }
    for cap in sorted(CAPABILITIES)
    if cap in _SEED_NOTES
]


def seed_coverage(session) -> int:
    """Idempotently upsert the coverage matrix; returns row count."""
    for row in COVERAGE_SEED:
        existing = (
            session.query(CoverageClause)
            .filter_by(clause_id=row["clause_id"])
            .first()
        )
        if existing is None:
            session.add(CoverageClause(**row))
        else:
            for key, value in row.items():
                setattr(existing, key, value)
    session.flush()
    return len(COVERAGE_SEED)


__all__ = ["COVERAGE_SEED", "seed_coverage"]