"""JOCKY dispatch server (FastAPI) — Block 4b.

POST /missions ingests a mission, runs it under the capability interpreter,
signs and persists its evidence chain; the read endpoints expose missions,
evidence and agent identity for the demo dashboards.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from jocky.server import db, dispatch

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