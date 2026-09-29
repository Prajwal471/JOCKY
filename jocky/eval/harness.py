"""Evaluation harness: clean env + baseline matrix (Block 10).

Runs every baseline in :mod:`jocky.eval.baselines` against an isolated
environment and reports, per baseline, which expectations held.  The harness is
deliberately *not* a micro-benchmark: what is measured are the four claimed
properties from ``docs/detection-definition.md`` plus the two machine-checkable
properties from Block 9. Wall-clock timings are collected for operator
convenience and written to the local report only — they are never persisted
(see ``EvalBaselineRun`` in ``jocky/server/db.py``).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from jocky.dsl.jir import JIR_VERSION
from jocky.eval.baselines import BASELINES, Baseline
from jocky.eval.citation import (
    CitationResult,
    cite_connections,
    cite_processes,
    cite_services,
)
from jocky.runtime.evidence import harvest_payload
from jocky.server import db, dispatch
from jocky.server.coverage import COVERAGE_SEED

_REPO_ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------- environment

def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=_REPO_ROOT,
            capture_output=True,
            timeout=10,
        )
        return out.stdout.decode("utf-8", "replace").strip()
    except Exception:
        return "unknown"


def provenance() -> dict[str, Any]:
    """Environment facts a measured result must be read against."""
    from jocky.config import MAX_RECURSION_DEPTH, WHILE_ITERATION_CAP
    from jocky.runtime import harvesters

    info = harvesters.system_info("")[0]
    return {
        "jir_version": JIR_VERSION,
        "commit": _git_commit(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "host": info.get("hostname", ""),
        "os_version": info.get("os_version", ""),
        "privileges": info.get("privileges", ""),
        "recursion_cap": MAX_RECURSION_DEPTH,
        "while_iteration_cap": WHILE_ITERATION_CAP,
        "measured_at": datetime.now(timezone.utc).isoformat(),
    }


@contextmanager
def clean_env(
    database_url: str | None = None,
    *,
    keys_dir: Path | None = None,
    drop: bool | None = None,
) -> Iterator[Session]:
    """Yield a session bound to an isolated database and key directory.

    The harness must not be able to contaminate the demo/production database,
    nor reuse the persisted agent key, so both are overridden for the duration
    of the run and restored afterwards.

    ``drop`` controls schema teardown. It defaults to ``True`` only for an
    ephemeral SQLite database; a durable database (Postgres) is **never**
    dropped, because the baseline rows are the evidence this harness exists to
    produce.
    """
    import jocky.config as cfg

    url = database_url or os.environ.get("JOCKY_EVAL_DATABASE_URL") or "sqlite://"
    raw_keys = os.environ.get("JOCKY_EVAL_KEYS_DIR")
    key_dir = Path(keys_dir or raw_keys or (_REPO_ROOT / "jocky" / "keys"))
    # Only an *in-memory* SQLite database is disposable. A file-backed SQLite
    # URL and any server database are durable and must survive teardown.
    base = url.split("?", 1)[0]
    ephemeral = base in ("sqlite://", "sqlite:///:memory:")
    do_drop = ephemeral if drop is None else drop

    if base.startswith("sqlite"):
        if ephemeral:
            engine = create_engine(
                url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        else:
            engine = create_engine(url)
    else:
        engine = create_engine(url)
    db.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    old_keys_dir = cfg.KEYS_DIR
    old_signer = dispatch._agent_signer
    cfg.KEYS_DIR = Path(key_dir)
    dispatch._agent_signer = None
    try:
        yield session
    finally:
        dispatch._agent_signer = old_signer
        cfg.KEYS_DIR = old_keys_dir
        session.close()
        if do_drop:
            db.Base.metadata.drop_all(engine)
        engine.dispose()


# -------------------------------------------------------------- P6 / dirt

def _probe_payloads() -> dict[str, Any]:
    """Harvest the probe signals once, stripped of evidence-injected fields."""
    from jocky.runtime import harvesters

    out: dict[str, Any] = {}
    try:
        out["identity"] = [
            harvest_payload({"rows": [r]}) for r in harvesters.identity_probe()
        ]
    except Exception:
        out["identity"] = []
    try:
        out["service"] = [
            harvest_payload({"rows": [r]})
            for r in harvesters.service_probe("LanmanServer")
        ]
    except Exception:
        out["service"] = []
    return out


def _host_fingerprint() -> dict[str, Any]:
    """Read-only state fingerprint used to detect host mutation."""
    from jocky.runtime import harvesters

    fp: dict[str, Any] = {}
    for key, fn in (
        ("autostarts", harvesters.autostart_rows),
        ("lotl", harvesters.lotl_rows),
    ):
        try:
            rows = fn("") if key == "autostarts" else fn()
        except Exception:
            rows = []
        fp[key] = sorted(
            str(sorted(r.items(), key=lambda kv: kv[0], reverse=True))
            for r in rows
        )
    try:
        fp["services"] = sorted(
            str(sorted((r.get("name", ""), r.get("state", ""), r.get("binary_path", "")), reverse=True))
            for r in harvesters.service_rows()
        )
    except Exception:
        fp["services"] = []
    return fp


# ------------------------------------------------------------- run baseline

def _check_expectations(baseline: Baseline, result: dict[str, Any]) -> list[dict[str, Any]]:
    checked = []
    for label, fn in baseline.expectations:
        try:
            ok = bool(fn(result))
        except Exception as exc:  # a broken expectation is a FAIL, not a crash
            ok = False
            result.setdefault("errors", []).append(f"{label}: {exc}")
        checked.append({"expectation": label, "holds": ok})
    return checked


def _jocky_object_count(capability: str) -> int | None:
    """Row count from JOCKY's *own* API for the cited capability.

    Deliberately a direct harvest rather than the mission's emitted value: a
    mission may emit a projection (``|count`` collapses rows to an int), and
    comparing a projection against a native tool count would report a delta
    that says nothing about agreement.
    """
    from jocky.runtime import harvesters

    try:
        if capability == "process:list":
            return len(harvesters.proc_rows())
        if capability == "network:analyze":
            return len(harvesters.connection_rows())
        if capability == "service:list":
            return len(harvesters.service_rows())
    except Exception:
        return None
    return None


def _capability_citation(
    capabilities: tuple[str, ...],
    result: dict[str, Any],
) -> list[CitationResult]:
    """Run the independent-citation path for each cited capability.

    Contained: a citation failure degrades that one row to UNAVAILABLE and must
    never abort the matrix.
    """
    citations: list[CitationResult] = []
    for cap, cite in (
        ("process:list", cite_processes),
        ("network:analyze", cite_connections),
        ("service:list", cite_services),
    ):
        if cap not in capabilities:
            continue
        try:
            citations.append(cite(_jocky_object_count(cap)))
        except Exception as exc:  # noqa: BLE001 - citation is advisory
            citations.append(
                CitationResult(cap, "n/a", None, None, "UNAVAILABLE",
                               f"{type(exc).__name__}: {exc}")
            )
    return citations


def run_baseline(
    session: Session,
    baseline: Baseline,
    mode: str,
) -> dict[str, Any]:
    """Run one baseline and return its full result dict (no persistence)."""
    before_fp = _host_fingerprint() if baseline.id == "host.unmutated" else None

    fingerprint = None
    determinism_hold = True
    if baseline.id == "collection.determinism":
        fingerprint = _probe_payloads()
        determinism_hold = fingerprint == _probe_payloads()

    max_steps = baseline.max_steps
    result: dict[str, Any] = {
        "baseline": baseline,
        "mode": mode,
        "status": "ERROR",
        "error": "",
        "evidence_count": 0,
        "signed_records": 0,
        "privileges_seen": set(),
        "steps": 0,
        "proofs_hold": False,
        "determinism_hold": determinism_hold,
        "bounds_hold": False,
        "no_mutation_hold": False,
        "row_counts": {},
        "runs": [],
        "mission_digest": "",
        "mission_id": None,
    }

    try:
        kwargs: dict[str, Any] = {}
        if max_steps is not None:
            kwargs["maximum_steps"] = max_steps
        report = dispatch.run_and_persist(
            session, source=baseline.mission, author="eval-harness", **kwargs
        )
        result["status"] = "completed"
        result["runs"] = report["runs"]
        result["evidence_count"] = report["evidence_count"]
        result["mission_digest"] = report["mission_digest"]
        result["mission_id"] = report["mission_id"]
        result["steps"] = sum(int(r["steps"]) for r in report["runs"])
    except RuntimeError as exc:
        result["status"] = "failed"
        result["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - harness must not die on a baseline
        result["status"] = "ERROR"
        result["error"] = f"{type(exc).__name__}: {exc}"

    mine = _mission_records(session, result)
    result["signed_records"] = len([r for r in mine if r.signature])
    result["evidence_count"] = len(mine)
    result["privileges_seen"] = {r.privileges for r in mine}

    if result["status"] == "completed" and result["mission_digest"]:
        from jocky.eval.equivalence import prove_mission_all_hold

        mid = _mission_id(session, result)
        mission = session.get(db.Mission, mid) if mid is not None else None
        if mission is not None:
            all_hold, proofs = prove_mission_all_hold(
                session, mission, dispatch.agent_signer().public_key_hex
            )
            result["proofs_hold"] = all_hold
            result["proofs"] = proofs

    result["row_counts"] = _row_counts(mine)
    result["bounds_hold"] = (
        result["status"] == "failed" and "budget" in (result["error"] or "").lower()
    ) or (baseline.id == "bounds.enforced" and result["status"] == "failed")
    result["no_mutation_hold"] = (
        before_fp == _host_fingerprint() if before_fp is not None else True
    )
    result["citation"] = [c.to_dict() for c in _capability_citation(baseline.capabilities, result)]
    result["expectations"] = _check_expectations(baseline, result)

    passed = sum(1 for e in result["expectations"] if e["holds"])
    result["expectations_passed"] = passed
    result["expectations_total"] = len(result["expectations"])
    all_expectations_hold = passed == result["expectations_total"]
    # A baseline only PASSes if the mission also reached the status its
    # expectations assume: `bounds.enforced` is *meant* to fail safely, so it
    # is the one baseline that expects status == "failed". Every other
    # baseline must have completed, otherwise a mission that never ran could
    # pass a trivial expectation.
    expected_status = "failed" if baseline.id == "bounds.enforced" else "completed"
    result["verdict"] = (
        "ERROR"
        if result["status"] == "ERROR"
        else "PASS"
        if (all_expectations_hold and result["status"] == expected_status)
        else "FAIL"
    )
    return result


def _mission_id(session: Session, result: dict[str, Any]) -> int | None:
    """The id of the mission a result came from.

    ``run_and_persist`` reports the id it created, and that is the only
    unambiguous answer: the same source dispatched twice into a durable database
    produces two missions with the same ``jir_sha256``, so a digest lookup with
    ``.first()`` can return the *older* one -- a different mission, signed by a
    different key, with different evidence. The digest lookup is kept only as a
    fallback for a hand-built result dict.
    """
    direct = result.get("mission_id")
    if direct is not None:
        return int(direct)
    m = (
        session.query(db.Mission)
        .filter_by(jir_sha256=result["mission_digest"])
        .order_by(db.Mission.id)
        .first()
    )
    return m.id if m else None


def _mission_records(session: Session, result: dict[str, Any]) -> list[db.EvidenceRecord]:
    mid = _mission_id(session, result)
    if mid is None:
        return []
    return (
        session.query(db.EvidenceRecord)
        .filter_by(mission_id=mid)
        .order_by(db.EvidenceRecord.chain_index)
        .all()
    )


def _row_counts(records: list[db.EvidenceRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in records:
        rows = (r.payload or {}).get("rows")
        if isinstance(rows, list):
            n = len(rows)
        elif isinstance(rows, dict):
            n = 1
        else:
            n = 0 if rows is None else 1
        counts[r.capability] = max(counts.get(r.capability, 0), n)
    return counts


# ------------------------------------------------------------------- matrix

def run_matrix(
    session: Session,
    mode: str,
    *,
    baselines: tuple[Baseline, ...] = BASELINES,
) -> dict[str, Any]:
    """Run every baseline, persist the rows, and summarise the matrix."""
    from jocky.server.metrics import interop_metrics

    results = [run_baseline(session, b, mode) for b in baselines]
    interop = interop_metrics(session, dispatch.agent_signer().public_key_hex)
    prov = provenance()
    coverage = _coverage_report(results)

    rows = []
    for res in results:
        row = _persist(session, res, prov)
        rows.append(row)
    promoted = _promote_coverage(session, results)

    verdict = "PASS"
    if any(r["verdict"] == "ERROR" for r in results):
        verdict = "ERROR"
    elif any(r["verdict"] == "FAIL" for r in results):
        verdict = "FAIL"

    return {
        "mode": mode,
        "verdict": verdict,
        "provenance": prov,
        "interop": interop,
        "coverage": coverage,
        "promoted_coverage": promoted,
        "results": [_report_row(r) for r in results],
        "rows_persisted": len(rows),
    }


def _report_row(res: dict[str, Any]) -> dict[str, Any]:
    b: Baseline = res["baseline"]
    return {
        "baseline_id": b.id,
        "name": b.name,
        "property": b.property,
        "capabilities": list(b.capabilities),
        "verdict": res["verdict"],
        "status": res["status"],
        "error": res["error"],
        "evidence_count": res["evidence_count"],
        "expectations_passed": res["expectations_passed"],
        "expectations_total": res["expectations_total"],
        "expectations": res["expectations"],
        "proofs_hold": res["proofs_hold"],
        "determinism_hold": res["determinism_hold"],
        "no_mutation_hold": res["no_mutation_hold"],
        "citation": res["citation"],
        "mission_digest": res["mission_digest"],
    }


def _coverage_report(results: list[dict[str, Any]]) -> dict[str, Any]:
    measured: set[str] = set()
    for res in results:
        if res["verdict"] == "PASS":
            measured.update(res["baseline"].capabilities)
    seeded = {c["clause_id"] for c in COVERAGE_SEED}
    return {
        "seeded_capabilities": sorted(seeded),
        "measured_capabilities": sorted(measured),
        "uncovered_capabilities": sorted(seeded - measured),
    }


def _promote_coverage(session: Session, results: list[dict[str, Any]]) -> list[str]:
    """LIVE -> MEASURED for every capability a PASSing baseline exercised."""
    measured: set[str] = set()
    for res in results:
        if res["verdict"] == "PASS":
            measured.update(res["baseline"].capabilities)
    promoted = []
    for clause in session.query(db.CoverageClause).all():
        if clause.clause_id in measured and clause.status == "LIVE":
            clause.status = "MEASURED"
            promoted.append(clause.clause_id)
    return promoted


def _persist(session: Session, res: dict[str, Any], prov: dict[str, Any]):
    b: Baseline = res["baseline"]
    row = db.EvalBaselineRun(
        baseline_id=b.id,
        name=b.name,
        mode=res["mode"],
        status=res["verdict"],
        property=b.property,
        capabilities=list(b.capabilities),
        expectations_total=res["expectations_total"],
        expectations_passed=res["expectations_passed"],
        evidence_count=res["evidence_count"],
        steps=res["steps"],
        proofs_hold=bool(res["proofs_hold"]),
        determinism_hold=bool(res["determinism_hold"]),
        bounds_hold=bool(res["bounds_hold"]),
        no_mutation_hold=bool(res["no_mutation_hold"]),
        citation=res["citation"],
        provenance=prov,
        detail={"error": res["error"], "expectations": res["expectations"]},
    )
    session.add(row)
    session.flush()
    return row


# ---------------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="JOCKY evaluation harness (Block 10)")
    ap.add_argument("--mode", choices=("sample", "live"), default="live")
    ap.add_argument("--out", help="write the JSON report to this path")
    ap.add_argument("--db", help="database URL (default: JOCKY_EVAL_DATABASE_URL or sqlite)")
    args = ap.parse_args(argv)

    if args.mode == "sample":
        os.environ.setdefault("JOCKY_SAMPLE_DATA", "1")

    started = time.perf_counter()
    with clean_env(args.db) as session:
        report = run_matrix(session, args.mode)
        session.commit()
    report["wall_clock_s"] = round(time.perf_counter() - started, 3)
    report["note"] = "wall_clock_s is operator convenience only; not persisted"

    text = json.dumps(report, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)

    print(
        f"matrix {report['mode']}: {report['verdict']} "
        f"({sum(1 for r in report['results'] if r['verdict'] == 'PASS')}"
        f"/{len(report['results'])} baselines passed, "
        f"{len(report['coverage']['uncovered_capabilities'])} capabilities uncovered)",
        file=sys.stderr,
    )
    return 0 if report["verdict"] == "PASS" else 1


__all__ = [
    "clean_env",
    "provenance",
    "run_baseline",
    "run_matrix",
    "main",
]


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
