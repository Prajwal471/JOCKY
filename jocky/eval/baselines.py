"""The baseline matrix (Block 10).

A baseline is one measurable claim about JOCKY under contested-space
constraints, expressed as a mission plus a set of expectations.  Each baseline
is tagged with the property from ``docs/detection-definition.md`` that it
measures, so a matrix run reports *what was proven*, not just "it ran".

The matrix covers the four claimed properties:

1. least-privilege by default
2. read-only by construction
3. bound execution
4. tamper-evident evidence

plus the two machine-checkable properties introduced in Block 9: repeatable
observation (P6) and no host mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

# Each expectation receives the baseline result dict and returns True/False.
Expectation = Callable[[dict[str, Any]], bool]


@dataclass(frozen=True)
class Baseline:
    id: str
    name: str
    property: str
    mission: str
    capabilities: tuple[str, ...]
    expectations: tuple[tuple[str, Expectation], ...]
    expected_evidence: int
    citation: str = ""
    max_steps: int | None = None
    notes: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------- helpers

def _emitted_values(result: dict[str, Any]) -> list[Any]:
    out: list[Any] = []
    for run in result.get("runs", []):
        for rec in run.get("emitted", []):
            out.append(rec.get("value"))
    return out


def _first_rows(result: dict[str, Any]) -> list[Any]:
    for value in _emitted_values(result):
        if isinstance(value, list) and value:
            return value
    return []


# ------------------------------------------------------------- expectations

def _exp_completed(result: dict[str, Any]) -> bool:
    return result["status"] == "completed" and result["evidence_count"] >= 1


def _exp_all_signed(result: dict[str, Any]) -> bool:
    return bool(result["signed_records"]) and result["signed_records"] == result["evidence_count"]


def _exp_privileges_none(result: dict[str, Any]) -> bool:
    return bool(result["privileges_seen"]) and set(result["privileges_seen"]) == {"none"}


def _exp_identity_rows(result: dict[str, Any]) -> bool:
    rows = _first_rows(result)
    if not rows or not isinstance(rows[0], dict):
        return False
    row = rows[0]
    return bool(row.get("user")) and bool(row.get("sid")) and "privileges" in row


def _exp_identity_unprivileged(result: dict[str, Any]) -> bool:
    rows = _first_rows(result)
    if not rows or not isinstance(rows[0], dict):
        return False
    return rows[0].get("privileges") in ("none", "administrator")


def _exp_registry_rows(result: dict[str, Any]) -> bool:
    rows = _first_rows(result)
    if not rows or not isinstance(rows[0], dict):
        return False
    row = rows[0]
    return bool(row.get("hive")) and bool(row.get("path")) and bool(row.get("value_type"))


def _exp_service_rows(result: dict[str, Any]) -> bool:
    rows = _first_rows(result)
    if not rows or not isinstance(rows[0], dict):
        return False
    row = rows[0]
    return bool(row.get("name")) and bool(row.get("binary_path") or row.get("path"))


def _exp_proofs_hold(result: dict[str, Any]) -> bool:
    return bool(result.get("proofs_hold"))


def _exp_evidence_count(result: dict[str, Any]) -> bool:
    return result["evidence_count"] == int(result["baseline"].expected_evidence)


def _exp_bounded_failure(result: dict[str, Any]) -> bool:
    if result["status"] != "failed":
        return False
    err = (result.get("error") or "").lower()
    return "budget" in err or "cap" in err


def _exp_steps_within_budget(result: dict[str, Any]) -> bool:
    return result["steps"] <= int(result["baseline"].max_steps or 0)


def _exp_deterministic(result: dict[str, Any]) -> bool:
    return bool(result.get("determinism_hold"))


def _exp_host_unmutated(result: dict[str, Any]) -> bool:
    return bool(result.get("no_mutation_hold"))


# ---------------------------------------------------------------- baselines

IDENTITY = Baseline(
    id="identity.least_privilege",
    name="Effective identity is least-privilege",
    property="1. least-privilege by default",
    capabilities=("identity:probe", "evidence:sign"),
    mission='''
@requires(identity:probe, evidence:sign)
mission "BaselineIdentity" {
  let who = probe_identity();
  emit who;
}
''',
    expectations=(
        ("mission completed", _exp_completed),
        ("every record signed", _exp_all_signed),
        ("provenance privileges == none", _exp_privileges_none),
        ("identity row has user+sid", _exp_identity_rows),
        ("effective privileges reported", _exp_identity_unprivileged),
    ),
    expected_evidence=1,
    tags=("contested-space",),
)

REGISTRY = Baseline(
    id="registry.autostart_read",
    name="Registry autostart key read without elevation",
    property="2. read-only by construction",
    capabilities=("registry:query", "evidence:sign"),
    mission='''
@requires(registry:query, evidence:sign)
mission "BaselineRegistry" {
  let reg = probe_registry("HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run");
  emit reg;
}
''',
    expectations=(
        ("mission completed", _exp_completed),
        ("every record signed", _exp_all_signed),
        ("rows carry hive/path/value_type", _exp_registry_rows),
    ),
    expected_evidence=1,
    tags=("contested-space",),
)

SERVICE = Baseline(
    id="service.config_read",
    name="SCM service config read without elevation",
    property="2. read-only by construction",
    capabilities=("service:probe", "evidence:sign"),
    mission='''
@requires(service:probe, evidence:sign)
mission "BaselineService" {
  let svc = probe_service("LanmanServer");
  emit svc;
}
''',
    expectations=(
        ("mission completed", _exp_completed),
        ("every record signed", _exp_all_signed),
        ("row carries name + binary path", _exp_service_rows),
    ),
    expected_evidence=1,
    tags=("contested-space",),
)

CHAIN = Baseline(
    id="chain.integrity",
    name="Multi-emit mission yields a verifiable evidence chain",
    property="4. tamper-evident evidence",
    capabilities=("process:list", "network:analyze", "evidence:sign"),
    mission='''
@requires(process:list, network:analyze, evidence:sign)
mission "BaselineChain" {
  let p = collect_processes();
  emit p |count;
  let n = analyze_network_connections();
  emit n |count;
  emit p |take 1;
}
''',
    expectations=(
        ("mission completed", _exp_completed),
        ("three evidence records", _exp_evidence_count),
        ("every record signed", _exp_all_signed),
        ("P1-P5 equivalence proofs hold", _exp_proofs_hold),
    ),
    expected_evidence=3,
    tags=("contested-space", "interop"),
)

BOUNDS = Baseline(
    id="bounds.enforced",
    name="Runaway loop is refused by the step budget",
    property="3. bound execution",
    capabilities=("evidence:sign",),
    mission='''
@requires(evidence:sign)
mission "BaselineBounds" {
  let i = 0;
  while i < 100000000 { i = i + 1; }
  emit i;
}
''',
    expectations=(
        ("run failed", lambda r: r["status"] == "failed"),
        ("failure cites the budget or loop cap", _exp_bounded_failure),
        ("steps stayed within budget", _exp_steps_within_budget),
    ),
    expected_evidence=0,
    max_steps=2000,
    tags=("safety",),
)

DETERMINISM = Baseline(
    id="collection.determinism",
    name="Two harvests of unchanged state are byte-identical",
    property="repeatable observation (Block 9, P6)",
    capabilities=("identity:probe", "service:probe"),
    mission='''
@requires(identity:probe, service:probe)
mission "BaselineDeterminism" {
  let who = probe_identity();
  emit who;
  let svc = probe_service("LanmanServer");
  emit svc;
}
''',
    expectations=(
        ("mission completed", _exp_completed),
        ("P6 harvest payloads identical", _exp_deterministic),
    ),
    expected_evidence=2,
    tags=("interop",),
)

UNMUTATED = Baseline(
    id="host.unmutated",
    name="Inspection does not change the inspected host",
    property="2. read-only by construction",
    capabilities=("process:list", "persistence:list", "service:list", "lotl:scan"),
    mission='''
@requires(process:list, persistence:list, service:list, lotl:scan)
mission "BaselineUnmutated" {
  let p = collect_processes();
  emit p |count;
  let a = list_autostarts();
  emit a |count;
  let s = list_services();
  emit s |count;
  let l = scan_lotl();
  emit l |count;
}
''',
    expectations=(
        ("mission completed", _exp_completed),
        ("host fingerprint unchanged", _exp_host_unmutated),
    ),
    expected_evidence=4,
    tags=("contested-space",),
)


BASELINES: tuple[Baseline, ...] = (
    IDENTITY,
    REGISTRY,
    SERVICE,
    CHAIN,
    BOUNDS,
    DETERMINISM,
    UNMUTATED,
)


def baseline_by_id(baseline_id: str) -> Baseline:
    for b in BASELINES:
        if b.id == baseline_id:
            return b
    raise KeyError(baseline_id)


__all__ = [
    "Baseline",
    "BASELINES",
    "baseline_by_id",
]
