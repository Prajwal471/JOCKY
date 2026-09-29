"""Active measures (Block 11): counterfactual demonstrations of the four
claimed properties in ``docs/detection-definition.md``.

A *baseline* (Block 10) shows that a mission works. A *measure* here shows that
something which **must not** work does not: each one drives a mission, a
capability request, or a persisted record into the failure it is supposed to hit
and reports PASS only once that failure has been observed.

Two rules keep a measure worth something:

1. **A refusal is not a pass on its own.** Every measure also carries a
   *positive control* — a near-identical case that is supposed to succeed. A
   measure that refuses everything, or that trips over an unrelated bug, fails.
2. **A measure never touches durable state.** Measures run inside the harness
   :func:`jocky.eval.harness.clean_env` (isolated database, throwaway agent
   key), so demonstrating that JOCKY cannot be escalated cannot also corrupt the
   demo database or overwrite the real agent key.

A PASS is a statement about *this build, on this host, in this mode* — see each
measure's ``does_not_prove`` field, which the API serves alongside the verdict.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.orm import Session

from jocky.dsl.jir import digest
from jocky.dsl.parser import JockySyntaxError, parse
from jocky.runtime.evidence import Ed25519Signer, sha256_bytes, verify_record
from jocky.runtime.identity import issue_mission_card
from jocky.runtime.interpreter import run_mission
from jocky.server import db, dispatch

Observation = tuple[str, bool]
MeasureRun = Callable[[Session], dict[str, Any]]


@dataclass(frozen=True)
class Measure:
    """One claim about JOCKY, plus the failure that would falsify it."""

    id: str
    name: str
    property: str
    claim: str
    expects: str
    does_not_prove: str
    run: MeasureRun


def _verdict(
    measure: Measure,
    detail: str,
    observations: list[Observation],
    notes: str = "",
) -> dict[str, Any]:
    return {
        "measure_id": measure.id,
        "name": measure.name,
        "property": measure.property,
        "claim": measure.claim,
        "does_not_prove": measure.does_not_prove,
        "verdict": "PASS" if all(ok for _, ok in observations) else "FAIL",
        "detail": detail,
        "observations": [
            {"observation": label, "holds": bool(ok)} for label, ok in observations
        ],
        "notes": notes,
    }


def _chain_hash(record: dict[str, Any]) -> str:
    """Recompute a record's chain hash from its persisted fields."""
    payload = record.get("payload") or {}
    return sha256_bytes(
        {
            "index": record["chain_index"],
            "prev": record["prev_hash"],
            "payload_sha256": record["payload_sha256"],
            "mission": payload.get("_mission_digest", ""),
        }
    )


# ------------------------------------------------- 1. no-escalation

_UNDECLARED_CALL = '''
@requires(evidence:sign)
mission "MeasureNoEscalation" {
  let p = collect_processes();
  emit p |count;
}
'''

_DECLARED_CALL = '''
@requires(process:list, evidence:sign)
mission "MeasureNoEscalationControl" {
  let p = collect_processes();
  emit p |count;
}
'''


def _no_escalation(session: Session) -> dict[str, Any]:
    """A collector the mission never declared must not be callable."""
    refused = ""
    try:
        dispatch.run_and_persist(session, source=_UNDECLARED_CALL, author="measure")
    except (RuntimeError, JockySyntaxError) as exc:
        refused = str(exc)

    # Positive control: the identical body, correctly declared, must succeed.
    # If the control fails too then this measure has proven nothing except that
    # JOCKY cannot run a mission at all.
    control_evidence = 0
    control_error = ""
    try:
        report = dispatch.run_and_persist(
            session, source=_DECLARED_CALL, author="measure"
        )
        control_evidence = int(report["evidence_count"])
    except (RuntimeError, JockySyntaxError) as exc:
        control_error = str(exc)

    missions = session.query(db.Mission).filter_by(name="MeasureNoEscalation").all()
    leaked = sum(
        session.query(db.EvidenceRecord).filter_by(mission_id=m.id).count()
        for m in missions
    )

    return _verdict(
        MEASURE_NO_ESCALATION,
        refused or "NOT REFUSED - the undeclared call was allowed",
        [
            ("undeclared capability refused", bool(refused)),
            (
                "refusal names the undeclared capability",
                "process:list" in refused,
            ),
            ("refused mission produced no evidence", leaked == 0),
            (
                "control mission with the capability declared completes",
                not control_error,
            ),
            ("control mission produced signed evidence", control_evidence >= 1),
        ],
        notes=control_error,
    )


MEASURE_NO_ESCALATION = Measure(
    id="no-escalation",
    name="Undeclared capability is refused",
    property="1. least-privilege by default",
    claim=(
        "A mission can only use capabilities it declared in @requires; calling "
        "an undeclared collector is refused rather than silently granted."
    ),
    expects=(
        "The call is refused, the refusal names the missing capability, no "
        "evidence is produced, and the same call succeeds once declared."
    ),
    does_not_prove=(
        "That the OS would refuse a privileged call. JOCKY refuses because the "
        "mission did not ask for it, not because the token is weak."
    ),
    run=_no_escalation,
)


# ------------------------------------------------- 2. never-grant / read-only

def _capability_refusal(capability: str) -> str:
    """Try to declare one capability; return the refusal text ('' if accepted)."""
    source = f'''
@requires({capability})
mission "MeasureRegistryProbe" {{
  let x = 1;
  emit x;
}}
'''
    try:
        parse(source)
    except JockySyntaxError as exc:
        return str(exc)
    return ""


def _never_grant(session: Session) -> dict[str, Any]:
    """The registry holds no write capability, and says so on request."""
    offensive = _capability_refusal("edr:disable")
    write_like = _capability_refusal("file:write")
    read_like = _capability_refusal("process:list")

    return _verdict(
        MEASURE_NEVER_GRANT,
        offensive or "NOT REFUSED - a never-grant capability was accepted",
        [
            ("never-grant capability rejected", bool(offensive)),
            (
                "rejection cites the never-grant set",
                "never-grant" in offensive,
            ),
            (
                "a write-shaped capability absent from the registry is rejected",
                "unknown capability" in write_like,
            ),
            (
                "a read-only capability is accepted (registry is not just empty)",
                read_like == "",
            ),
        ],
        notes=f"file:write -> {write_like or 'ACCEPTED'}",
    )


MEASURE_NEVER_GRANT = Measure(
    id="never-grant",
    name="The capability registry holds no write capability",
    property="2. read-only by construction",
    claim=(
        "Read-only is structural, not a denylist convention: the capability "
        "registry contains no write capability, so there is nothing to grant."
    ),
    expects=(
        "A never-grant name is refused as never-grant, a write-shaped name is "
        "refused as unknown to the registry, and a genuine read capability is "
        "still accepted."
    ),
    does_not_prove=(
        "That every read-only collector is free of side effects. The no-mutation "
        "baseline (host.unmutated) covers that separately."
    ),
    run=_never_grant,
)


# ------------------------------------------------- 3. bounded execution

_RUNAWAY = '''
@requires(evidence:sign)
mission "MeasureRunaway" {
  let i = 0;
  while i < 100000000 { i = i + 1; }
  emit i;
}
'''

_FINITE = '''
@requires(evidence:sign)
mission "MeasureFiniteLoop" {
  let i = 0;
  while i < 5 { i = i + 1; }
  emit i;
}
'''

_RECURSIVE = '''
mission "MeasureRecursion" {
  fn down(n: int) {
    return down(n - 1);
  }
  let _ = down(1000);
}
'''


def _bounded(session: Session) -> dict[str, Any]:
    """The budget must be the thing that stops a runaway mission."""
    cap = 2000
    runaway_prog = parse(_RUNAWAY)
    runaway = run_mission(runaway_prog, runaway_prog.units[0], maximum_steps=cap)
    runaway_error = runaway.error or ""

    # Positive control: the same loop shape, bounded by its own condition and
    # given a generous budget, must finish. Otherwise "refused" would just mean
    # "JOCKY refuses loops".
    finite_prog = parse(_FINITE)
    finite = run_mission(finite_prog, finite_prog.units[0], maximum_steps=cap)
    finite_error = finite.error or ""

    # The step count must be at or just past the cap: proof the cap is the
    # binding constraint rather than a coincidental early exit.
    ran_to_cap = runaway.steps > cap

    recursive_prog = parse(_RECURSIVE)
    recursive = run_mission(recursive_prog, recursive_prog.units[0], recursion_cap=4)
    recursion_error = recursive.error or ""

    return _verdict(
        MEASURE_BOUNDED,
        runaway_error or "NOT STOPPED - the runaway mission completed",
        [
            ("runaway mission failed", bool(runaway_error)),
            ("failure cites the step budget", "budget" in runaway_error.lower()),
            (
                "mission was stopped by the cap, not by finishing early",
                ran_to_cap,
            ),
            ("control loop completes within a generous budget", not finite_error),
            ("recursion depth is capped", "recursion depth" in recursion_error),
        ],
        notes=(
            f"steps={runaway.steps} cap={cap}; "
            f"finite steps={finite.steps}; {recursion_error}"
        ),
    )


MEASURE_BOUNDED = Measure(
    id="bounds.enforced",
    name="Runaway execution is stopped by its budget",
    property="3. bound execution",
    claim=(
        "Loops, dispatch and recursion are bounded: no mission can run "
        "unbounded, whatever it asks for."
    ),
    expects=(
        "An infinite loop is aborted exactly at the step budget, a recursion "
        "deeper than the cap is refused, and a finite loop still completes."
    ),
    does_not_prove=(
        "That the budget is a meaningful time limit on this host. Wall-clock is "
        "deliberately not measured here."
    ),
    run=_bounded,
)


# ------------------------------------------------- 4. tamper-evident evidence

_CHAIN_MISSION = '''
@requires(process:list, network:analyze, evidence:sign)
mission "MeasureTamper" {
  let p = collect_processes();
  emit p |count;
  let n = analyze_network_connections();
  emit n |count;
  emit p |take 1;
}
'''


def _tamper_evidence(session: Session) -> dict[str, Any]:
    """Escalate a forgery one layer at a time; each layer must be caught.

    A payload-only edit is caught by the payload digest. Recomputing the digest
    hides that, but then the chain hash no longer matches. Rewriting the chain
    hash hides that too, but the successor's ``prev_hash`` no longer points at
    it. Repairing the successor's anchor hides that, and only the signature is
    left -- which needs the agent key. Demonstrating the ladder is the honest
    version of "tamper-evident": four independent layers, each catching exactly
    the forger the previous layer could not.
    """
    report = dispatch.run_and_persist(
        session, source=_CHAIN_MISSION, author="measure"
    )
    public_key = dispatch.agent_signer().public_key_hex
    # Resolve the mission by the id ``run_and_persist`` reported, not by JIR
    # digest: on a durable database the same source may already be present from
    # an earlier run, and a digest lookup would hand back that older mission --
    # whose records were signed with a different key, so a *legitimate* record
    # would fail verification and the measure would report a false FAIL.
    mission = session.get(db.Mission, report["mission_id"])
    if mission is None:
        raise RuntimeError("measure mission was not persisted")

    records = (
        session.query(db.EvidenceRecord)
        .filter_by(mission_id=mission.id)
        .order_by(db.EvidenceRecord.chain_index)
        .all()
    )
    if len(records) < 2:
        raise RuntimeError(f"expected a multi-record chain, got {len(records)}")

    target, successor = records[0], records[1]
    original = dispatch.record_json(target)
    original_successor_prev = successor.prev_hash
    verified_before = verify_record(original, public_key)

    def _commit() -> dict[str, Any]:
        session.commit()
        session.refresh(target)
        return dispatch.record_json(target)

    forged = dict(original["payload"])
    forged["measure_tamper"] = "flipped"

    # layer 1 - edit the payload only
    target.payload = forged
    at = _commit()
    layer1 = {
        "payload_digest_broken": sha256_bytes(at["payload"]) != at["payload_sha256"],
        "rejected": not verify_record(at, public_key),
    }

    # layer 2 - also repair the digest (requires no key)
    target.payload_sha256 = sha256_bytes(forged)
    at = _commit()
    layer2 = {
        "chain_hash_broken": _chain_hash(at) != at["chain_hash"],
        "rejected": not verify_record(at, public_key),
    }

    # layer 3 - also repair the chain hash (requires no key)
    target.chain_hash = _chain_hash(at)
    at = _commit()
    layer3 = {
        "successor_link_broken": successor.prev_hash != at["chain_hash"],
        "rejected": not verify_record(at, public_key),
    }

    # layer 4 - also repair the successor's anchor (requires no key)
    successor.prev_hash = at["chain_hash"]
    session.commit()
    session.refresh(target)
    at = dispatch.record_json(target)
    layer4 = {"rejected": not verify_record(at, public_key)}

    # restore
    target.payload = original["payload"]
    target.payload_sha256 = original["payload_sha256"]
    target.chain_hash = original["chain_hash"]
    successor.prev_hash = original_successor_prev
    session.commit()
    session.refresh(target)
    session.refresh(successor)
    verified_after = verify_record(dispatch.record_json(target), public_key)

    return _verdict(
        MEASURE_TAMPER,
        "payload -> +digest -> +chain_hash -> +successor anchor; rejected at "
        "every layer",
        [
            ("record verifies before tampering", verified_before),
            ("layer 1 (payload edit) breaks the payload digest", layer1["payload_digest_broken"]),
            ("layer 1 rejected by verify_record", layer1["rejected"]),
            ("layer 2 (digest repaired) breaks the chain hash", layer2["chain_hash_broken"]),
            ("layer 2 rejected by verify_record", layer2["rejected"]),
            ("layer 3 (chain hash repaired) breaks the successor link", layer3["successor_link_broken"]),
            ("layer 3 rejected by verify_record", layer3["rejected"]),
            ("layer 4 (successor anchor repaired) rejected by the signature", layer4["rejected"]),
            ("record verifies again once restored", verified_after),
        ],
        notes=f"records={len(records)} tampered chain_index={at['chain_index']}",
    )


MEASURE_TAMPER = Measure(
    id="tamper-evident",
    name="A modified evidence record fails verification",
    property="4. tamper-evident evidence",
    claim=(
        "Evidence is tamper-evident: a one-field edit is rejected, and each "
        "repair an editor attempts is caught by a different, independent layer."
    ),
    expects=(
        "Payload digest, chain hash, successor anchor and Ed25519 signature each "
        "catch a strictly more capable forger, and the record verifies again "
        "once restored."
    ),
    does_not_prove=(
        "That history cannot be rewritten. Anyone holding the agent key can "
        "re-sign a whole chain; this raises the cost of an edit, it does not "
        "prevent a key holder from forging."
    ),
    run=_tamper_evidence,
)


# ------------------------------------------------- 5. JIR pinning

_CARDED = '''
@requires(process:list, evidence:sign)
mission "MeasureCarded" {
  let p = collect_processes();
  emit p |count;
}
'''

_DRIFTED = '''
@requires(process:list, evidence:sign)
mission "MeasureDrifted" {
  let p = collect_processes();
  emit p |count;
  emit p |take 1;
}
'''


def _jir_pinned(session: Session) -> dict[str, Any]:
    """A card authorises one exact program; a modified program is refused."""
    drifted_prog = parse(_DRIFTED)
    with tempfile.TemporaryDirectory(prefix="jocky-measure-requester-") as tmp:
        # A requester key distinct from the agent key: pinning must come from
        # the card's digest, not from key coincidence.
        requester = Ed25519Signer(key_path=Path(tmp) / "requester_ed25519.pem")
        card = issue_mission_card(
            signer=requester,
            mission_digest="f" * 64,  # pinned to some other program entirely
            capabilities=["process:list", "evidence:sign"],
            purpose="active measure: JIR pinning",
        )
        drift = run_mission(
            drifted_prog, drifted_prog.units[0], mission_card=card
        )
        drift_error = drift.error or ""

        # Positive control: a card pinned to *this* program's digest runs.
        pinned_prog = parse(_CARDED)
        pinned_card = issue_mission_card(
            signer=requester,
            mission_digest=digest(pinned_prog),
            capabilities=["process:list", "evidence:sign"],
            purpose="active measure: JIR pinning",
        )
        control = run_mission(
            pinned_prog, pinned_prog.units[0], mission_card=pinned_card
        )
        control_error = control.error or ""

    return _verdict(
        MEASURE_JIR_PINNED,
        drift_error or "NOT REFUSED - a drifted program ran under a stale card",
        [
            ("drifted program refused", bool(drift_error)),
            ("refusal cites JIR drift", "JIR drift" in drift_error),
            (
                "control program runs under a correctly pinned card",
                not control_error,
            ),
            ("control emitted its evidence", len(control.emitted) >= 1),
        ],
        notes=control_error,
    )


MEASURE_JIR_PINNED = Measure(
    id="jir-pinned",
    name="A mission card authorises one exact program",
    property="4. tamper-evident evidence",
    claim=(
        "Evidence is anchored: a signed mission card pins one JIR digest, and a "
        "program that drifts from it cannot run under that card."
    ),
    expects=(
        "A program modified after the card was issued is refused for JIR drift, "
        "while the program the card names still runs and emits evidence."
    ),
    does_not_prove=(
        "That the card's capabilities match what the host would allow. The card "
        "bounds the mission against its issuer, not against Windows."
    ),
    run=_jir_pinned,
)


MEASURES: tuple[Measure, ...] = (
    MEASURE_NO_ESCALATION,
    MEASURE_NEVER_GRANT,
    MEASURE_BOUNDED,
    MEASURE_TAMPER,
    MEASURE_JIR_PINNED,
)


def measure_by_id(measure_id: str) -> Measure:
    for m in MEASURES:
        if m.id == measure_id:
            return m
    raise KeyError(measure_id)


def catalog() -> list[dict[str, Any]]:
    """The measure catalog, without running anything."""
    return [
        {
            "id": m.id,
            "name": m.name,
            "property": m.property,
            "claim": m.claim,
            "expects": m.expects,
            "does_not_prove": m.does_not_prove,
        }
        for m in MEASURES
    ]


def run_measure(session: Session, measure: Measure) -> dict[str, Any]:
    """Run one measure; a broken measure is an ERROR, never a PASS."""
    try:
        result = measure.run(session)
    except Exception as exc:  # noqa: BLE001 - one bad measure must not stop the rest
        result = _verdict(
            measure,
            f"{type(exc).__name__}: {exc}",
            [("measure completed without error", False)],
        )
        result["verdict"] = "ERROR"
    result["mode"] = "sample" if _sample_mode() else "live"
    return result


def run_measures(
    session: Session,
    measure_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Run the selected measures (all of them by default) in one session."""
    if measure_ids:
        try:
            selected = tuple(measure_by_id(mid) for mid in measure_ids)
        except KeyError as exc:
            raise ValueError(f"unknown measure: {exc.args[0]}") from exc
    else:
        selected = MEASURES

    results = [run_measure(session, m) for m in selected]
    verdict = "PASS"
    if any(r["verdict"] == "ERROR" for r in results):
        verdict = "ERROR"
    elif any(r["verdict"] == "FAIL" for r in results):
        verdict = "FAIL"
    return {
        "verdict": verdict,
        "mode": results[0]["mode"] if results else _sample_mode(),
        "measures_run": len(results),
        "measures": results,
    }


def _sample_mode() -> bool:
    from jocky import config

    return bool(config.SAMPLE_DATA)


# ---------------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    """Run the measures and print a JSON report.

    The dashboard invokes this as a *subprocess* rather than in-process:
    :func:`jocky.eval.harness.clean_env` overrides process-global state (the
    agent key directory and the cached signer), and the dispatch server runs
    its endpoints on a thread pool. A subprocess is the only way to prove the
    measures cannot disturb a live server.
    """
    import argparse
    import json
    import sys

    ap = argparse.ArgumentParser(description="JOCKY active measures (Block 11)")
    ap.add_argument("--ids", nargs="*", help="measure ids to run (default: all)")
    ap.add_argument("--out", help="write the JSON report to this path")
    args = ap.parse_args(argv)

    from jocky.eval.harness import clean_env

    with clean_env() as session:
        report = run_measures(session, args.ids or None)
        session.commit()

    text = json.dumps(report, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)

    print(
        f"active measures {report['mode']}: {report['verdict']} "
        f"({sum(1 for m in report['measures'] if m['verdict'] == 'PASS')}"
        f"/{len(report['measures'])} measures passed)",
        file=sys.stderr,
    )
    return 0 if report["verdict"] == "PASS" else 1


__all__ = [
    "Measure",
    "MEASURES",
    "measure_by_id",
    "catalog",
    "run_measure",
    "run_measures",
    "main",
]


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
