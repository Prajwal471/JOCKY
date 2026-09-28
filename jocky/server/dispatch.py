"""Dispatch + persistence layer (Block 4b).

Executes parsed missions under the capability interpreter, converts every
``emit`` into a signed, hash-chained evidence record and persists both the
mission object and its evidence chain.  Used directly by the FastAPI surface
and by the demo scripts, so the API and the CLI share the same trust path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from jocky.dsl.jir import digest, jir_document
from jocky.dsl.parser import parse
from jocky.runtime.evidence import Ed25519Signer, sign_evidence_record
from jocky.runtime.interpreter import run_mission
from jocky.server import db

_agent_signer: Ed25519Signer | None = None


def agent_signer() -> Ed25519Signer:
    global _agent_signer
    if _agent_signer is None:
        _agent_signer = Ed25519Signer()
    return _agent_signer


def ensure_endpoint(session: Session, hostname: str | None = None) -> db.Endpoint:
    from jocky.runtime import harvesters

    info = harvesters.system_info(hostname or "")[0]
    agent_id = info["hostname"]
    ep = session.query(db.Endpoint).filter_by(agent_id=agent_id).first()
    if ep is None:
        ep = db.Endpoint(
            agent_id=agent_id,
            hostname=agent_id,
            platform=info["platform"],
            os_version=info["os_version"],
            collector_version=info["collector_version"],
        )
        session.add(ep)
        session.flush()
    return ep


def save_mission(session: Session, source: str, author: str, name: str | None = None) -> db.Mission:
    prog = parse(source)
    doc = jir_document(prog)
    mission = db.Mission(
        name=name or prog.name,
        source_text=source,
        jir=doc,
        jir_sha256=digest(prog),
        author=author,
        status="dispatched",
    )
    session.add(mission)
    session.flush()
    return mission


def _record_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        rows = payload.get("rows")
        if isinstance(rows, list):
            return rows
        if rows is not None and not isinstance(rows, dict):
            return [{"result": rows}]
        return [payload]
    return [{"result": payload}]


def chain_evidence(
    session: Session,
    *,
    emitted: list[dict[str, Any]],
    mission_digest: str,
    endpoint_id: int,
    mission_id: int,
    capability_label: str,
    source_label: str,
    start_index: int,
    tail: str = "",
) -> tuple[list[db.EvidenceRecord], int]:
    """Turn a mission run's emissions into signed, chained evidence rows."""
    records: list[db.EvidenceRecord] = []
    idx = start_index
    prev_hash = tail
    signer = agent_signer()
    for emitted_item in emitted:
        value = emitted_item.get("value")
        payload: dict[str, Any] = {"rows": _record_rows(value)}
        signed = sign_evidence_record(
            finding_type="observation",
            source=source_label,
            payload=payload,
            privileges="none",
            capability=capability_label,
            chain_index=idx,
            prev_hash=prev_hash,
            mission_digest=mission_digest,
            signer=signer,
        )
        rec = db.EvidenceRecord(
            endpoint_id=endpoint_id,
            mission_id=mission_id,
            finding_type=signed["finding_type"],
            source=signed["source"],
            privileges=signed["privileges"],
            payload=signed["payload"],
            payload_sha256=signed["payload_sha256"],
            observed_at=datetime.now(timezone.utc),
            chain_index=signed["chain_index"],
            prev_hash=signed["prev_hash"],
            chain_hash=signed["chain_hash"],
            capability=signed["capability"],
            signature=signed["signature"],
        )
        session.add(rec)
        records.append(rec)
        prev_hash = signed["chain_hash"]
        idx += 1
    return records, idx


def run_and_persist(
    session: Session,
    *,
    source: str,
    author: str = "demo-operator",
    purpose: str = "",
    name: str | None = None,
    card: Any = None,
) -> dict[str, Any]:
    """Parse, dispatch, sign and persist a mission; return its full report."""
    from jocky.runtime.identity import issue_mission_card

    endpoint = ensure_endpoint(session)
    mission = save_mission(session, source, author, name)
    prog = parse(source)
    mission_digest = digest(prog)
    declared = mission.jir["program"]["declared_capabilities"]

    issued_card = card
    if card is not None:
        issued_card = issue_mission_card(
            signer=card,
            mission_digest=mission_digest,
            capabilities=declared,
            purpose=purpose,
        )

    runs: list[dict[str, Any]] = []
    evidence_rows: list[db.EvidenceRecord] = []
    index = 0
    for unit in prog.units:
        run = run_mission(prog, unit, mission_card=issued_card)
        if run.error:
            session.rollback()
            raise RuntimeError(f"mission {unit.name!r} failed: {run.error}")
        cap = (list(unit.requires) or ["evidence:sign"])[0]
        recs, index = chain_evidence(
                session,
                emitted=run.emitted,
                mission_digest=mission_digest,
                endpoint_id=endpoint.id,
                mission_id=mission.id,
                capability_label=cap,
                source_label=f"jockey::collectors::{cap.split(':')[0]}",
                start_index=index,
                tail=evidence_rows[-1].chain_hash if evidence_rows else "",
            )
        session.flush()
        evidence_rows.extend(recs)
        runs.append({
            "unit": unit.name,
            "kind": unit.kind,
            "emitted": run.emitted,
            "steps": run.steps,
            "result": run.result,
            "evidence_count": len(recs),
        })

    card_payload = None
    if issued_card is not None:
        from jocky.runtime.identity import mission_card_to_dict

        card_payload = mission_card_to_dict(issued_card)
    session.commit()
    return {
        "name": mission.name,
        "mission_digest": mission_digest,
        "runs": runs,
        "evidence_count": len(evidence_rows),
        "chain_hashes": [r.chain_hash for r in evidence_rows],
        "mission_card": card_payload,
        "endpoint": {"agent_id": endpoint.agent_id, "platform": endpoint.platform},
    }


def query_evidence(
    session: Session,
    *,
    finding_type: str | None = None,
    source: str | None = None,
    capability: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    q = session.query(db.EvidenceRecord)
    if finding_type:
        q = q.filter(db.EvidenceRecord.finding_type == finding_type)
    if source:
        q = q.filter(db.EvidenceRecord.source.ilike(f"%{source}%"))
    if capability:
        q = q.filter(db.EvidenceRecord.capability == capability)
    rows = q.order_by(db.EvidenceRecord.chain_index.asc()).limit(limit).offset(max(offset, 0)).all()
    return [{
        "id": r.id,
        "finding_type": r.finding_type,
        "source": r.source,
        "capability": r.capability,
        "chain_index": r.chain_index,
        "prev_hash": r.prev_hash,
        "chain_hash": r.chain_hash,
        "payload_sha256": r.payload_sha256,
        "signature": r.signature,
        "observed_at": r.observed_at.isoformat() if r.observed_at else "",
        "payload": r.payload,
    } for r in rows]


def list_missions(session: Session, limit: int = 50) -> list[dict[str, Any]]:
    rows = session.query(db.Mission).order_by(db.Mission.created_at.desc()).limit(limit).all()
    return [{
        "id": m.id,
        "name": m.name,
        "author": m.author,
        "status": m.status,
        "jir_sha256": m.jir_sha256,
        "capabilities": m.jir["program"]["declared_capabilities"],
        "created_at": m.created_at.isoformat() if m.created_at else "",
    } for m in rows]


def list_agents(session: Session) -> list[dict[str, Any]]:
    rows = session.query(db.Endpoint).all()
    pub = agent_signer().public_key_hex
    return [{
        "agent_id": e.agent_id,
        "hostname": e.hostname,
        "platform": e.platform,
        "os_version": e.os_version,
        "collector_version": e.collector_version,
        "identity_public_key": pub,
        "privileges": "none",
    } for e in rows]