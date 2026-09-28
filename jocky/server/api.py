"""JOCKY dispatch server (FastAPI) — Block 4b.

POST /missions ingests a mission, runs it under the capability interpreter,
signs and persists its evidence chain; the read endpoints expose missions,
evidence and agent identity for the demo dashboards.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from jocky.server import db, dispatch, metrics

app = FastAPI(title="JOCKY Dispatch Server", version="0.1.0")


def get_session() -> Session:
    session = db.SessionLocal()
    try:
        yield session
    finally:
        session.close()


class MissionIn(BaseModel):
    source: str = Field(..., min_length=1, description="JOCKY mission source text")
    author: str = "demo-operator"
    purpose: str = "defense demonstration"
    name: Optional[str] = None


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "jocky-dispatch", "version": "0.1.0"}


@app.post("/missions", response_class=JSONResponse)
def create_mission(body: MissionIn, session: Session = Depends(get_session)) -> dict[str, Any]:
    try:
        return dispatch.run_and_persist(
            session,
            source=body.source,
            author=body.author,
            purpose=body.purpose,
            name=body.name,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/missions")
def missions(limit: int = 50, session: Session = Depends(get_session)) -> list[dict[str, Any]]:
    return dispatch.list_missions(session, limit=min(limit, 200))


def _mission_or_404(session: Session, mission_id: int) -> db.Mission:
    mission = session.get(db.Mission, mission_id)
    if mission is None:
        raise HTTPException(status_code=404, detail="mission not found")
    return mission


@app.get("/missions/{mission_id}/evidence")
def mission_evidence(
    mission_id: int,
    limit: int = 1000,
    offset: int = 0,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    _mission_or_404(session, mission_id)
    rows = (
        session.query(db.EvidenceRecord)
        .filter(db.EvidenceRecord.mission_id == mission_id)
        .order_by(db.EvidenceRecord.chain_index.asc())
        .limit(min(limit, 5000))
        .offset(max(offset, 0))
        .all()
    )
    return {
        "mission_id": mission_id,
        "evidence_count": len(rows),
        "evidence": [dispatch.record_json(r) for r in rows],
    }


@app.get("/missions/{mission_id}/stream")
def mission_stream(mission_id: int, session: Session = Depends(get_session)) -> StreamingResponse:
    """Live SSE stream: yields each signed evidence record as it lands."""
    _mission_or_404(session, mission_id)

    def event_source():
        last_index = -1
        poll = 0
        while True:
            rec = (
                session.query(db.EvidenceRecord)
                .filter(
                    db.EvidenceRecord.mission_id == mission_id,
                    db.EvidenceRecord.chain_index > last_index,
                )
                .order_by(db.EvidenceRecord.chain_index.asc())
                .first()
            )
            if rec is not None:
                last_index = rec.chain_index
                yield "event: evidence\n"
                yield f"data: {json.dumps(dispatch.record_json(rec))}\n\n"
                poll = 0
            else:
                mission = session.get(db.Mission, mission_id)
                if mission is not None and mission.status in ("completed", "failed"):
                    yield 'event: done\ndata: {"status": "%s"}\n\n' % mission.status
                    return
                poll += 1
                if poll > 300:
                    yield 'event: done\ndata: {"status": "timeout"}\n\n'
                    return
                time.sleep(0.05)

    return StreamingResponse(event_source(), media_type="text/event-stream")


@app.get("/evidence")
def evidence(
    finding_type: Optional[str] = None,
    source: Optional[str] = None,
    capability: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    return dispatch.query_evidence(
        session,
        finding_type=finding_type,
        source=source,
        capability=capability,
        limit=min(limit, 500),
        offset=offset,
    )


@app.get("/agents")
def agents(session: Session = Depends(get_session)) -> list[dict[str, Any]]:
    return dispatch.list_agents(session)


@app.get("/metrics/interop")
def interop(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Block 9: machine-checkable interop invariants over persisted state."""
    return metrics.interop_metrics(session, dispatch.agent_signer().public_key_hex)


@app.get("/missions/{mission_id}/proofs")
def mission_proofs(mission_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    """Block 9: the P1-P5 equivalence proofs for one mission."""
    from jocky.eval.equivalence import prove_mission_all_hold

    mission = _mission_or_404(session, mission_id)
    all_hold, proofs = prove_mission_all_hold(
        session, mission, dispatch.agent_signer().public_key_hex
    )
    return {"mission_id": mission_id, "all_hold": all_hold, "proofs": proofs}