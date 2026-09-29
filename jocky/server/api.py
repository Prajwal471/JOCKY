"""JOCKY dispatch server (FastAPI) — Block 4b.

POST /missions ingests a mission, runs it under the capability interpreter,
signs and persists its evidence chain; the read endpoints expose missions,
evidence and agent identity for the demo dashboards.

Block 11 adds the active-measure endpoints and serves the demo dashboard from
``static/``. The dashboard is a single static page with no build step and no
external assets, so it works on an air-gapped host.

Block 13 protects the two routes that can cause work -- ``POST /missions`` and
``POST /measures/run`` -- with the bearer token in :mod:`jocky.server.auth`.
The read routes stay open for the dashboard. A mission's ``author`` is derived
from the presented token, never from the request body, so attribution cannot be
spoofed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from jocky.server import db, dispatch, metrics
from jocky.server.auth import require_token

app = FastAPI(title="JOCKY Dispatch Server", version="0.1.0")

STATIC_DIR = Path(__file__).resolve().parent / "static"

#: How long a measure subprocess may run before it is killed.
MEASURE_TIMEOUT_S = 180


def get_session() -> Session:
    session = db.SessionLocal()
    try:
        yield session
    finally:
        session.close()


class MissionIn(BaseModel):
    source: str = Field(..., min_length=1, description="JOCKY mission source text")
    author: Optional[str] = Field(
        default=None,
        description=(
            "Deprecated and ignored: `author` is now derived from the API token "
            "so a caller cannot attribute a mission to someone else."
        ),
    )
    purpose: str = "defense demonstration"
    name: Optional[str] = None


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "jocky-dispatch", "version": "0.1.0"}


@app.post("/missions", response_class=JSONResponse)
def create_mission(
    body: MissionIn,
    principal: dict[str, Any] = Depends(require_token),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    try:
        return dispatch.run_and_persist(
            session,
            source=body.source,
            author=principal["operator"],
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


# ------------------------------------------------------- Block 11: measures

class MeasureRunIn(BaseModel):
    measure_ids: Optional[list[str]] = Field(
        default=None,
        description="measure ids to run; omit to run all of them",
    )


@app.get("/measures")
def measures() -> dict[str, Any]:
    """The active-measure catalog. Reports no results — it runs nothing."""
    from jocky.eval import measures as measures_mod

    return {
        "measures": measures_mod.catalog(),
        "note": (
            "Each measure drives a case that must fail and reports PASS only "
            "when the failure was observed; POST /measures/run executes them."
        ),
    }


@app.post("/measures/run", response_class=JSONResponse)
def run_measures(
    body: MeasureRunIn | None = None,
    principal: dict[str, Any] = Depends(require_token),
) -> dict[str, Any]:
    """Run the active measures in a subprocess and return their report.

    ``principal`` is unused beyond being the gate: declaring the dependency is
    what makes the route refuse an unauthenticated caller. There is nothing to
    attribute here, since a measure run is not a mission.

    Deliberately a subprocess: the measures need an isolated database and a
    throwaway agent key, and ``clean_env`` obtains that by overriding
    process-global state. The dispatch server serves requests on a thread pool,
    so doing it in-process would let a measure run swap the live server's
    signing key underneath an in-flight mission.
    """
    argv = [sys.executable, "-m", "jocky.eval.measures"]
    if body is not None and body.measure_ids:
        argv += ["--ids", *body.measure_ids]
    env = dict(os.environ)
    # Keep the subprocess off the server's database and key directory.
    env.pop("JOCKY_EVAL_DATABASE_URL", None)
    env.pop("JOCKY_EVAL_KEYS_DIR", None)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=MEASURE_TIMEOUT_S,
            env=env,
            cwd=str(Path(__file__).resolve().parents[2]),
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504, detail=f"measures exceeded {MEASURE_TIMEOUT_S}s"
        )
    if proc.returncode not in (0, 1) or not proc.stdout:
        raise HTTPException(
            status_code=500,
            detail=f"measure runner failed: {proc.stderr.decode('utf-8', 'replace')[-500:]}",
        )
    try:
        return json.loads(proc.stdout.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="measure runner produced no report")


@app.get("/coverage")
def coverage(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Capability coverage plus the property->measure map for the dashboard."""
    from jocky.eval import measures as measures_mod
    from jocky.server.coverage import seed_coverage

    if session.query(db.CoverageClause).count() == 0:
        seed_coverage(session)
        session.commit()

    clauses = [
        {
            "capability": c.clause_id,
            "title": c.title,
            "status": c.status,
            "mechanism": c.mechanism,
            "notes": c.notes,
        }
        for c in session.query(db.CoverageClause).order_by(db.CoverageClause.clause_id).all()
    ]
    counts: dict[str, int] = {}
    for c in clauses:
        counts[c["status"]] = counts.get(c["status"], 0) + 1

    properties: dict[str, list[str]] = {}
    for m in measures_mod.MEASURES:
        properties.setdefault(m.property, []).append(m.id)

    return {
        "clauses": clauses,
        "counts": counts,
        "properties": [
            {"property": name, "measures": ids}
            for name, ids in sorted(properties.items())
        ],
    }


@app.get("/")
def index() -> RedirectResponse:
    return RedirectResponse("/ui/")


@app.get("/ui")
def ui_redirect() -> RedirectResponse:
    return RedirectResponse("/ui/")


if STATIC_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=str(STATIC_DIR), html=True), name="ui")