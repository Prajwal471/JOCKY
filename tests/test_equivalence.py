"""Equivalence-proof harness tests (Block 9, P1-P5)."""

from __future__ import annotations

from jocky.dsl.jir import jir_document
from jocky.dsl.parser import parse
from jocky.eval.equivalence import (
    prove_canonical_serialization,
    prove_mission_all_hold,
    prove_source_to_jir_determinism,
)
from jocky.runtime.evidence import Ed25519Signer, sign_evidence_record, verify_record
from jocky.server import dispatch

SRC = '''
@requires(process:list)
mission "EquivMission" {
  let rows = collect_processes();
  emit rows;
}
'''


def test_p1_source_to_jir_determinism():
    p = prove_source_to_jir_determinism(SRC)
    assert p["holds"] is True


def test_p1_changes_with_capability_set():
    other = SRC.replace("process:list", "network:analyze")
    assert (
        prove_source_to_jir_determinism(SRC)["detail"]
        != prove_source_to_jir_determinism(other)["detail"]
    )


def test_p2_canonical_serialization():
    p = prove_canonical_serialization(jir_document(parse(SRC)))
    assert p["holds"] is True


def test_p5_verify_record_roundtrip(tmp_path):
    signer = Ed25519Signer(tmp_path / "signer.pem")
    rec = sign_evidence_record(
        finding_type="observation",
        source="test",
        payload={"rows": [1, 2, 3]},
        privileges="none",
        capability="process:list",
        chain_index=0,
        prev_hash="",
        mission_digest="a" * 64,
        signer=signer,
    )
    pub = signer.public_key_hex
    stored = {k: rec[k] for k in (
        "finding_type", "source", "privileges", "payload", "payload_sha256",
        "chain_index", "prev_hash", "chain_hash", "capability", "signature",
    )}
    assert verify_record(stored, pub) is True

    tampered = dict(stored)
    tampered["payload"] = {"rows": [1, 2, 99]}
    assert verify_record(tampered, pub) is False

    stranger = Ed25519Signer(tmp_path / "stranger.pem").public_key_hex
    assert stranger != pub
    assert verify_record(stored, stranger) is False


def test_p1_to_p5_hold_for_dispatched_mission(session):
    report = dispatch.run_and_persist(session, source=SRC)
    mission = session.query(dispatch.db.Mission).filter_by(
        jir_sha256=report["mission_digest"]
    ).one()
    all_hold, proofs = prove_mission_all_hold(
        session, mission, dispatch.agent_signer().public_key_hex
    )
    assert all_hold is True
    names = {p["proof"] for p in proofs}
    assert "P1_source_to_jir_determinism" in names
    assert "P4_chain_hash_recompute" in names
    assert "P5_signature_verify" in names


def test_tampered_evidence_breaks_p5(session):
    from jocky.server import db

    dispatch.run_and_persist(session, source=SRC)
    rec = session.query(db.EvidenceRecord).first()
    rec.payload = {"rows": ["tampered"]}
    session.flush()
    mission = session.query(db.Mission).first()
    all_hold, _ = prove_mission_all_hold(
        session, mission, dispatch.agent_signer().public_key_hex
    )
    assert all_hold is False
