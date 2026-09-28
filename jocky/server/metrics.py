"""Interop metrics (Block 9).

This module computes interop-level invariants over persisted state (Postgres
or SQLite) so that the chain, JIR identity, coverage matrix, and Ed25519
signatures can be machine-checked as a single trust surface. These checks
are read-only and do not mutate data.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from jocky.dsl.jir import JIR_VERSION, digest
from jocky.dsl.parser import parse
from jocky.runtime.evidence import verify_record
from jocky.server import db
from jocky.server.coverage import COVERAGE_SEED


def _ok(status: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"status": status, "details": details}


def interop_metrics(session: Session, agent_pubkey_hex: str | None = None) -> dict[str, Any]:
    """Return a machine-checkable interop metrics bundle."""

    missions = session.query(db.Mission).all()
    artifacts = session.query(db.Artifact).all()
    decisions = session.query(db.CapabilityDecision).all()
    evidence = session.query(db.EvidenceRecord).all()
    endpoints = session.query(db.Endpoint).all()
    clauses = session.query(db.CoverageClause).all()

    ep_by_id = {e.id: e for e in endpoints}
    m_by_id = {m.id: m for m in missions}
    a_by_mid = {a.mission_id: a for a in artifacts}
    e_by_mid: dict[int, list[db.EvidenceRecord]] = {}
    for r in evidence:
        e_by_mid.setdefault(r.mission_id, []).append(r)
    for lst in e_by_mid.values():
        lst.sort(key=lambda x: (x.chain_index, x.id))

    link_ok = True
    link_issues: list[str] = []
    for a in artifacts:
        if a.mission_id not in m_by_id:
            link_ok = False
            link_issues.append(f"artifact {a.id} orphan mission {a.mission_id}")
    for d in decisions:
        if d.mission_id not in m_by_id:
            link_ok = False
            link_issues.append(f"decision {d.id} orphan mission {d.mission_id}")
    for r in evidence:
        if r.mission_id not in m_by_id or r.endpoint_id not in ep_by_id:
            link_ok = False
            link_issues.append(
                f"evidence {r.id} orphan m={r.mission_id} ep={r.endpoint_id}"
            )

    declared_caps_set = set()
    for m in missions:
        declared_caps_set.update(m.jir.get("program", {}).get("declared_capabilities", []))
    seeded_caps = {c["clause_id"] for c in COVERAGE_SEED}
    coverage_missing = sorted(declared_caps_set - seeded_caps)

    decision_by_mid: dict[int, set[str]] = {}
    for d in decisions:
        decision_by_mid.setdefault(d.mission_id, set()).add(d.capability)
    decisions_missing: list[str] = []
    for m in missions:
        dcaps = decision_by_mid.get(m.id, set())
        mcap = set(m.jir.get("program", {}).get("declared_capabilities", []))
        decisions_missing.extend(sorted(mcap - dcaps))

    continuity_ok = True
    continuity_issues: list[str] = []
    for m in missions:
        lst = e_by_mid.get(m.id, [])
        for i, r in enumerate(lst):
            if i == 0:
                if r.prev_hash != "":
                    continuity_ok = False
                    continuity_issues.append(
                        f"mission {m.id} record {r.id} non-empty head prev"
                    )
                continue
            prev_rec = lst[i - 1]
            if r.prev_hash != prev_rec.chain_hash:
                continuity_ok = False
                continuity_issues.append(
                    f"mission {m.id} record {r.id} chain break {r.prev_hash[:8]}!={prev_rec.chain_hash[:8]}"
                )

    jir_ok = True
    jir_issues: list[str] = []
    for m in missions:
        if m.jir.get("version") != JIR_VERSION:
            jir_ok = False
            jir_issues.append(f"mission {m.id} jir_version {m.jir.get('version')!r}!= {JIR_VERSION}")
        try:
            d = digest(parse(m.source_text))
        except Exception as exc:  # pragma: no cover
            d = ""
            jir_ok = False
            jir_issues.append(f"mission {m.id} parse/digest failed: {exc}")
        if d != m.jir_sha256:
            jir_ok = False
            jir_issues.append(f"mission {m.id} digest!=jir_sha256")
        a = a_by_mid.get(m.id)
        if a is not None and d != a.jir_hash:
            jir_ok = False
            jir_issues.append(f"mission {m.id} digest!=artifact.jir_hash")

    ver_ok = True
    verified = 0
    if agent_pubkey_hex:
        for r in evidence:
            rec = {
                "finding_type": r.finding_type,
                "source": r.source,
                "privileges": r.privileges,
                "payload": r.payload,
                "payload_sha256": r.payload_sha256,
                "chain_index": r.chain_index,
                "prev_hash": r.prev_hash,
                "chain_hash": r.chain_hash,
                "capability": r.capability,
                "signature": r.signature,
                "signed_by": agent_pubkey_hex,
            }
            try:
                if verify_record(rec, agent_pubkey_hex):
                    verified += 1
                else:
                    ver_ok = False
            except Exception:
                ver_ok = False
    total_e = len(evidence)

    return {
        "missions": len(missions),
        "artifacts": len(artifacts),
        "decisions": len(decisions),
        "evidence": total_e,
        "endpoints": len(endpoints),
        "coverage_clauses": len(clauses),
        "linkage_integrity": _ok("ok" if link_ok else "fail", {"issues": link_issues}),
        "coverage": _ok("ok" if not coverage_missing else "fail", {"missing_seeded_caps": coverage_missing}),
        "decisions_complete": _ok("ok" if not decisions_missing else "fail", {"missing": decisions_missing}),
        "chain_continuity": _ok("ok" if continuity_ok else "fail", {"issues": continuity_issues}),
        "jir_stability": _ok("ok" if jir_ok else "fail", {"issues": jir_issues}),
        "signature_verifiability": _ok(
            "ok" if (agent_pubkey_hex and ver_ok and total_e == verified) else ("warn" if not agent_pubkey_hex else "fail"),
            {
                "total": total_e,
                "verified": verified,
                "pubkey_provided": bool(agent_pubkey_hex),
            },
        ),
    }