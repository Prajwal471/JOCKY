"""FastAPI surface tests for the JOCKY dispatch server (Block 4b)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from jocky.server import db
from jocky.server.api import app, get_session

MISSION = '''
@requires(process:list)
mission "ApiProbe" {
  let p = collect_processes();
  emit p |count;
}
'''


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    db.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)

    def override():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_session] = override
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_create_mission_and_evidence(client):
    r = client.post("/missions", json={"source": MISSION, "author": "api-user", "purpose": "lab"})
    assert r.status_code == 200
    body = r.json()
    assert body["evidence_count"] == 1
    assert len(body["chain_hashes"]) == 1
    assert body["endpoint"]["platform"] in ("windows", "linux", "win32", "darwin")

    ev = client.get("/evidence").json()
    assert len(ev) == 1
    assert ev[0]["capability"] == "process:list"
    assert ev[0]["signature"]

    missions = client.get("/missions").json()
    assert missions[0]["name"] == "ApiProbe"
    assert missions[0]["author"] == "api-user"

    agents = client.get("/agents").json()
    assert len(agents) == 1


def test_create_mission_rejects_escalation(client):
    r = client.post("/missions", json={"source": 'mission "X" { let s = list_services(); emit s; }'})
    assert r.status_code == 400
    assert "not declared" in r.json()["detail"]


def test_mission_evidence_endpoint(client):
    r = client.post("/missions", json={"source": MISSION})
    assert r.status_code == 200
    evidence = client.get("/evidence").json()
    target_id = client.get("/missions").json()[0]["id"]
    me = client.get(f"/missions/{target_id}/evidence").json()
    assert me["mission_id"] == target_id
    assert me["evidence_count"] == 1
    assert me["evidence"][0]["chain_hash"] == evidence[0]["chain_hash"]
    assert client.get("/missions/99999/evidence").status_code == 404


def test_sse_stream_emits_records(client):
    r = client.post("/missions", json={"source": MISSION})
    assert r.status_code == 200
    target_id = client.get("/missions").json()[0]["id"]
    with client.stream("GET", f"/missions/{target_id}/stream") as resp:
        assert resp.status_code == 200
        chunks = list(resp.iter_text())
    joined = "".join(chunks)
    assert "event: evidence" in joined
    assert "event: done" in joined
    assert '"chain_hash"' in joined