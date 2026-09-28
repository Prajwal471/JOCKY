"""Block 0 smoke tests: ORM round-trip against in-memory SQLite.

The Postgres schema is enforced by the Alembic migration; these tests keep
the model layer executable anywhere and prove chain-hash bookkeeping works.
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from jocky.server import db


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    db.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    s = Session()
    try:
        yield s
    finally:
        s.close()


def test_endpoint_roundtrip(session):
    ep = db.Endpoint(agent_id="ep-1", hostname="box01", platform="windows")
    session.add(ep)
    session.commit()
    got = session.query(db.Endpoint).filter_by(agent_id="ep-1").one()
    assert got.platform == "windows"
    assert got.hostname == "box01"


def test_evidence_chain_fields(session):
    ep = db.Endpoint(agent_id="ep-2", hostname="box02", platform="linux")
    session.add(ep)
    session.commit()

    e1 = db.EvidenceRecord(
        endpoint_id=ep.id,
        finding_type="process",
        source="procfs",
        privileges="none",
        payload={"pid": 1, "name": "init"},
        payload_sha256="a" * 64,
        observed_at=datetime.now(timezone.utc),
        chain_index=0,
        prev_hash="",
        chain_hash="b" * 64,
        capability="process:list",
    )
    e2 = db.EvidenceRecord(
        endpoint_id=ep.id,
        finding_type="process",
        source="procfs",
        privileges="none",
        payload={"pid": 2, "name": "kthreadd"},
        payload_sha256="c" * 64,
        observed_at=datetime.now(timezone.utc),
        chain_index=1,
        prev_hash=e1.chain_hash,
        chain_hash="d" * 64,
        capability="process:list",
    )
    session.add_all([e1, e2])
    session.commit()

    rows = session.query(db.EvidenceRecord).order_by(db.EvidenceRecord.chain_index).all()
    assert [r.chain_index for r in rows] == [0, 1]
    assert rows[1].prev_hash == rows[0].chain_hash


def test_mission_and_artifact(session):
    m = db.Mission(name="demo", source_text="mission demo", jir={"kind": "JIR"}, jir_sha256="z" * 64)
    session.add(m)
    session.commit()
    session.add(
        db.Artifact(
            mission_id=m.id,
            variant_index=0,
            jir_hash="e" * 64,
            sha256="f" * 64,
            llvm_ir_hash="g" * 64,
            passes=["O0"],
            equivalence_proven=True,
        )
    )
    session.commit()
    art = session.query(db.Artifact).one()
    assert art.mission.name == "demo"
    assert art.equivalence_proven


def test_capability_decision_deny(session):
    m = db.Mission(name="rogue", source_text="", jir={"kind": "JIR"}, jir_sha256="h" * 64)
    session.add(m)
    session.commit()
    session.add(
        db.CapabilityDecision(
            mission_id=m.id,
            capability="edr:disable",
            decision="DENY",
            reason="capability not declared in @requires",
            jir_hash="i" * 64,
        )
    )
    session.commit()
    d = session.query(db.CapabilityDecision).one()
    assert d.decision == "DENY"
    assert "not declared" in d.reason