"""Dispatch + evidence persistence tests (Block 4b) against in-memory SQLite."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from jocky.server import db, dispatch

MISSION = '''
@requires(process:list, network:analyze)
mission "Recon" {
  let p = collect_processes();
  emit p |count;
  emit p |sort_by("pid") |take 2;
}

@requires(service:list)
experiment "Services" {
  let s = list_services();
  emit s |count;
}
'''


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    db.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    s = Session()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


def test_run_and_persist_evidence_chain(session):
    report = dispatch.run_and_persist(session, source=MISSION, author="tester")
    assert report["evidence_count"] == 3  # two emits + one emit
    tails = report["chain_hashes"]
    assert len(tails) == 3
    assert len(set(tails)) == 3

    rows = session.query(db.EvidenceRecord).order_by(db.EvidenceRecord.chain_index).all()
    assert [r.chain_index for r in rows] == [0, 1, 2]
    assert rows[1].prev_hash == rows[0].chain_hash
    assert rows[2].prev_hash == rows[1].chain_hash
    for r in rows:
        assert len(r.chain_hash) == 64
        assert len(r.signature) == 128
        assert r.privileges == "none"
        assert r.payload["_mission_digest"]

    mission = session.query(db.Mission).one()
    assert mission.jir_sha256 == report["mission_digest"]
    assert mission.jir["program"]["name"] == "Recon"
    assert mission.status == "completed"

    artifact = session.query(db.Artifact).one()
    assert artifact.jir_hash == report["mission_digest"]
    assert len(artifact.sha256) == 64
    assert artifact.equivalence_proven is False

    decisions = {
        d.capability: d.decision
        for d in session.query(db.CapabilityDecision).all()
    }
    assert decisions == {"process:list": "ALLOW", "network:analyze": "ALLOW", "service:list": "ALLOW"}

    clauses = session.query(db.CoverageClause).all()
    assert len(clauses) == 11
    assert all(c.status == "LIVE" for c in clauses)


def test_failed_mission_marks_status(session):
    with pytest.raises(RuntimeError):
        dispatch.run_and_persist(session, source='mission "Bad" { unknown_builtin(); }')
    assert session.query(db.Mission).one().status == "failed"


def test_capabilities_carried_into_evidence(session):
    report = dispatch.run_and_persist(session, source=MISSION)
    rows = session.query(db.EvidenceRecord).all()
    caps = {r.capability for r in rows}
    assert "process:list" in caps
    assert "service:list" in caps


def test_mission_card_issued_when_requester_key_given(session, tmp_path):
    from jocky.runtime.evidence import Ed25519Signer
    from jocky.runtime.identity import mission_card_from_dict

    key = Ed25519Signer(key_path=tmp_path / "req.pem")
    report = dispatch.run_and_persist(session, source=MISSION, card=key, purpose="lab")
    card = mission_card_from_dict(report["mission_card"])
    assert card.verify()
    assert card.mission_digest == report["mission_digest"]
    assert "process:list" in card.capabilities


def test_run_and_persist_rejects_bad_mission(session):
    with pytest.raises(RuntimeError, match="not declared"):
        dispatch.run_and_persist(
            session, source='mission "Bad" { let s = list_services(); emit s; }'
        )


def test_query_evidence_filters(session):
    dispatch.run_and_persist(session, source=MISSION)
    cap = dispatch.query_evidence(session, capability="process:list")
    assert len(cap) == 2
    service = dispatch.query_evidence(session, capability="service:list")
    assert len(service) == 1
    assert dispatch.query_evidence(session, source="collectors::process")[0]["source"].endswith("::process")


def test_mission_and_agent_listing(session):
    dispatch.run_and_persist(session, source=MISSION)
    missions = dispatch.list_missions(session)
    assert missions[0]["author"] == "demo-operator"
    agents = dispatch.list_agents(session)
    assert agents[0]["agent_id"]
    assert len(agents[0]["identity_public_key"]) == 64