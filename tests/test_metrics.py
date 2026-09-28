"""Interop metrics tests (Block 9)."""

from __future__ import annotations

from jocky.server import db, dispatch
from jocky.server.metrics import interop_metrics

SRC = '''
@requires(process:list, registry:query)
mission "InteropMission" {
  let rows = collect_processes();
  emit rows;
  let reg = probe_registry("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
  emit reg;
}
'''


def test_metrics_all_ok_after_dispatch(session):
    dispatch.run_and_persist(session, source=SRC)
    pub = dispatch.agent_signer().public_key_hex
    m = interop_metrics(session, pub)
    assert m["linkage_integrity"]["status"] == "ok"
    assert m["chain_continuity"]["status"] == "ok"
    assert m["jir_stability"]["status"] == "ok"
    assert m["decisions_complete"]["status"] == "ok"
    assert m["coverage"]["status"] == "ok"
    assert m["signature_verifiability"]["status"] == "ok"
    assert m["signature_verifiability"]["details"]["verified"] == m["evidence"]
    assert m["evidence"] == 2
    assert m["missions"] == 1


def test_metrics_warn_without_pubkey(session):
    dispatch.run_and_persist(session, source=SRC)
    m = interop_metrics(session, None)
    assert m["signature_verifiability"]["status"] == "warn"
    assert m["signature_verifiability"]["details"]["pubkey_provided"] is False


def test_metrics_detect_chain_break(session):
    dispatch.run_and_persist(session, source=SRC)
    recs = session.query(db.EvidenceRecord).order_by(db.EvidenceRecord.chain_index).all()
    recs[1].prev_hash = "0" * 64
    session.flush()
    m = interop_metrics(session, dispatch.agent_signer().public_key_hex)
    assert m["chain_continuity"]["status"] == "fail"
    assert m["chain_continuity"]["details"]["issues"]


def test_metrics_detect_jir_drift(session):
    dispatch.run_and_persist(session, source=SRC)
    mission = session.query(db.Mission).first()
    mission.jir_sha256 = "f" * 64
    session.flush()
    m = interop_metrics(session, dispatch.agent_signer().public_key_hex)
    assert m["jir_stability"]["status"] == "fail"


def test_metrics_empty_session_ok(session):
    m = interop_metrics(session, None)
    assert m["missions"] == 0
    assert m["linkage_integrity"]["status"] == "ok"
    assert m["chain_continuity"]["status"] == "ok"
