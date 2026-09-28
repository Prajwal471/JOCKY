"""Dispatch + persistence layer (Block 4b).

Executes parsed missions under the capability interpreter, converts every
``emit`` into a signed, hash-chained evidence record and persists both the
mission object and its evidence chain.  Used directly by the FastAPI surface
and by the demo scripts, so the API and the CLI share the same trust path.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy.orm import Session

from jocky.config import LLVM_PASSES
from jocky.dsl.jir import digest, jir_document
from jocky.dsl.parser import parse
from jocky.runtime.evidence import Ed25519Signer, sign_evidence_record
from jocky.runtime.interpreter import run_mission
from jocky.server import db
from jocky.server.coverage import seed_coverage

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
        status="queued",
    )
    session.add(mission)
    session.flush()
    return mission


def record_artifact(
    session: Session,
    *,
    mission: db.Mission,
    jir_hash: str,
    variant_index: int = 0,
) -> db.Artifact:
    """Capture the compiled artifact for a mission (jir hash + source digest)."""
    artifact = db.Artifact(
        mission_id=mission.id,
        variant_index=variant_index,
        jir_hash=jir_hash,
        sha256=hashlib.sha256(mission.source_text.encode("utf-8")).hexdigest(),
        llvm_ir_hash="",
        passes=LLVM_PASSES,
        equivalence_proven=False,
    )
    session.add(artifact)
    session.flush()
    return artifact


def record_capability_decisions(
    session: Session,
    *,
    mission: db.Mission,
    jir_hash: str,
) -> list[db.CapabilityDecision]:
    """Persist the ALLOW/DENY decision for every capability in the mission.

    ``parse()`` already gates unknown + never-grant capabilities at compile
    time (checker.validate_capabilities), so reaching this point means every
    declared requirement is allowed by the registry.
    """
    decisions: list[db.CapabilityDecision] = []
    declared = mission.jir["program"]["declared_capabilities"]
    for cap in declared:
        decision = db.CapabilityDecision(
            mission_id=mission.id,
            capability=cap,
            decision="ALLOW",
            reason="declared in capability registry; compile-time validate() gate passed",
            jir_hash=jir_hash,
        )
        session.add(decision)
        decisions.append(decision)
    session.flush()
    return decisions


def _record_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        rows = payload.get("rows")
        if isinstance(rows, list):
            return rows
        if rows is not None and not isinstance(rows, dict):
            return [{"result": rows}]
        return [payload]
    return [{"result": payload}]


def sign_record(
    *,
    emitted_value: Any,
    mission_digest: str,
    endpoint_id: int,
    mission_id: int,
    capability_label: str,
    source_label: str,
    chain_index: int,
    prev_hash: str,
) -> tuple[db.EvidenceRecord, int]:
    """Sign + build one evidence record; returns (record, next chain index)."""
    payload: dict[str, Any] = {"rows": _record_rows(emitted_value)}
    signed = sign_evidence_record(
        finding_type="observation",
        source=source_label,
        payload=payload,
        privileges="none",
        capability=capability_label,
        chain_index=chain_index,
        prev_hash=prev_hash,
        mission_digest=mission_digest,
        signer=agent_signer(),
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
    return rec, chain_index + 1


def _mark_equivalence(session: Session, mission: db.Mission) -> bool:
    """Run P1-P5 for this mission and set ``Artifact.equivalence_proven`` (Block 9)."""
    from jocky.eval.equivalence import prove_mission_all_hold

    artifacts = session.query(db.Artifact).filter_by(mission_id=mission.id).all()
    if not artifacts:
        return False
    all_hold, _proofs = prove_mission_all_hold(
        session, mission, agent_signer().public_key_hex
    )
    for artifact in artifacts:
        artifact.equivalence_proven = all_hold
    return all_hold


def run_and_persist(
    session: Session,
    *,
    source: str,
    author: str = "demo-operator",
    purpose: str = "",
    name: str | None = None,
    card: Any = None,
    stream: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Parse, dispatch, sign and persist a mission; return its full report.

    When ``stream`` is provided, every ``emit`` is signed and persisted as the
    interpreter loop runs (live chain tail) and the callback is invoked with
    the fresh record dict so the caller can forward it to an SSE client.
    """
    from jocky.runtime.identity import issue_mission_card

    endpoint = ensure_endpoint(session)
    mission = save_mission(session, source, author, name)
    prog = parse(source)
    mission_digest = digest(prog)
    seed_coverage(session)
    record_artifact(session, mission=mission, jir_hash=mission_digest)
    record_capability_decisions(session, mission=mission, jir_hash=mission_digest)
    mission.status = "dispatched"
    session.flush()
    session.commit()

    issued_card = card
    if card is not None:
        issued_card = issue_mission_card(
            signer=card,
            mission_digest=mission_digest,
            capabilities=mission.jir["program"]["declared_capabilities"],
            purpose=purpose,
        )

    runs: list[dict[str, Any]] = []
    evidence_rows: list[db.EvidenceRecord] = []
    current_cap: str = "evidence:sign"
    index = 0

    def _live_emit(record: dict[str, Any]) -> None:
        nonlocal index, current_cap
        tail = evidence_rows[-1].chain_hash if evidence_rows else ""
        rec, index = sign_record(
            emitted_value=record.get("value"),
            mission_digest=mission_digest,
            endpoint_id=endpoint.id,
            mission_id=mission.id,
            capability_label=current_cap,
            source_label=f"jockey::collectors::{current_cap.split(':')[0]}",
            chain_index=index,
            prev_hash=tail,
        )
        session.add(rec)
        session.flush()
        session.commit()
        evidence_rows.append(rec)
        if stream is not None:
            stream(record_json(rec))

    for unit in prog.units:
        current_cap = (list(unit.requires) or ["evidence:sign"])[0]
        run = run_mission(prog, unit, mission_card=issued_card, on_emit=_live_emit)
        if run.error:
            mission.status = "failed"
            session.commit()
            raise RuntimeError(f"mission {unit.name!r} failed: {run.error}")
        session.flush()
        runs.append({
            "unit": unit.name,
            "kind": unit.kind,
            "emitted": run.emitted,
            "steps": run.steps,
            "result": run.result,
            "evidence_count": len(evidence_rows),
        })

    mission.status = "completed"
    card_payload = None
    if issued_card is not None:
        from jocky.runtime.identity import mission_card_to_dict

        card_payload = mission_card_to_dict(issued_card)
    session.flush()
    _mark_equivalence(session, mission)
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


def record_json(r: db.EvidenceRecord) -> dict[str, Any]:
    """Serialize an evidence record for API/stream consumption."""
    return {
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
    return [record_json(r) for r in rows]


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