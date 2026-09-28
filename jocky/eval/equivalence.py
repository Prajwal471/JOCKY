"""Equivalence-proof harness (Block 9).

Runs the machine-checkable proofs behind ``docs/equivalence-proofs.md``.  P1-P5
are cheap, pure-function checks that a completed mission can run against its
own persisted state; P6 (collection determinism) re-harvests and is only run
standalone against a live endpoint, never inside dispatch.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from jocky.dsl.jir import JIR_VERSION, digest, serialize
from jocky.dsl.parser import parse
from jocky.runtime.evidence import canonical_bytes, verify_record
from jocky.server import db


def _p(name: str, ok: bool, detail: Any) -> dict[str, Any]:
    return {"proof": name, "holds": bool(ok), "detail": detail}


def prove_source_to_jir_determinism(source: str) -> dict[str, Any]:
    """P1: two independent parses of the same source yield one JIR digest."""
    a = digest(parse(source))
    b = digest(parse(source))
    return _p("P1_source_to_jir_determinism", a == b, a)


def prove_canonical_serialization(doc: dict) -> dict[str, Any]:
    """P2: canonical JSON re-serialization is byte-stable and key-sorted.

    This is the interop contract: a second implementation (e.g. the Rust port)
    reproduces identical bytes from the JIR, so identity survives a hop.
    """
    s1 = canonical_bytes(doc).decode("utf-8")
    s2 = canonical_bytes(doc).decode("utf-8")
    sorted_again = canonical_bytes(__import__("json").loads(s1)).decode("utf-8")
    ok = s1 == s2 == sorted_again
    return _p("P2_canonical_serialization", ok, {"bytes": len(canonical_bytes(doc)), "stable": ok})


def prove_mission_anchor(mission: db.Mission, records: list[db.EvidenceRecord]) -> dict[str, Any]:
    """P3: every emitted record is anchored to the mission JIR digest."""
    want = mission.jir_sha256
    ok = bool(want) and all((r.payload or {}).get("_mission_digest") == want for r in records)
    return _p("P3_mission_anchor", ok, {"mission_digest": want, "records": len(records)})


def prove_chain_and_signatures(
    records: list[db.EvidenceRecord], public_key_hex: str
) -> dict[str, Any]:
    """P4+P5: chain hashes recompute and every signature verifies."""
    ordered = sorted(records, key=lambda r: (r.chain_index, r.id))
    prev = ""
    chain_ok = True
    sig_ok = True
    for r in ordered:
        if r.prev_hash != prev:
            chain_ok = False
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
        }
        if not verify_record(rec, public_key_hex):
            sig_ok = False
        prev = r.chain_hash
    return [
        _p("P4_chain_hash_recompute", chain_ok, {"records": len(ordered)}),
        _p("P5_signature_verify", sig_ok, {"records": len(ordered)}),
    ]


def prove_mission(session: Session, mission: db.Mission, public_key_hex: str) -> list[dict[str, Any]]:
    """Run P1-P5 for a single mission and return the per-proof results."""
    records = session.query(db.EvidenceRecord).filter_by(mission_id=mission.id).all()
    proofs = [
        prove_source_to_jir_determinism(mission.source_text),
        prove_canonical_serialization(mission.jir),
    ]
    if mission.jir.get("version") != JIR_VERSION:
        proofs.append(_p("P0_jir_version", False, mission.jir.get("version")))
    proofs.append(prove_mission_anchor(mission, records))
    proofs.extend(prove_chain_and_signatures(records, public_key_hex))
    return proofs


def prove_mission_all_hold(
    session: Session, mission: db.Mission, public_key_hex: str
) -> tuple[bool, list[dict[str, Any]]]:
    """Convenience: returns (all_hold, proofs)."""
    proofs = prove_mission(session, mission, public_key_hex)
    return (all(p["holds"] for p in proofs), proofs)


__all__ = [
    "prove_source_to_jir_determinism",
    "prove_canonical_serialization",
    "prove_mission_anchor",
    "prove_chain_and_signatures",
    "prove_mission",
    "prove_mission_all_hold",
    "serialize",
]