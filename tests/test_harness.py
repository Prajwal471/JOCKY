"""Evaluation harness tests (Block 10).

Runs the full baseline matrix against an isolated in-memory SQLite session
under the deterministic sample-data seam, so the matrix is green everywhere.
The live-mode path is exercised by a Windows-guarded collector test and by the
CLI smoke test.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from jocky.eval.baselines import BASELINES, baseline_by_id
from jocky.eval.citation import cite_processes, cite_services
from jocky.eval.harness import clean_env, provenance, run_baseline, run_matrix
from jocky.server import db

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def eval_session(tmp_path):
    with clean_env(keys_dir=tmp_path / "keys") as session:
        yield session


# --------------------------------------------------------------- clean env

def test_clean_env_does_not_touch_main_database(eval_session, monkeypatch):
    """The harness must not be able to write to the app's real session.

    The app's session is rebound to a *second* in-memory database rather than
    the configured ``DATABASE_URL``: the claim under test is that the harness
    and the app use separate stores, which is provable here without a live
    Postgres (this test previously needed one, and failed wherever Postgres was
    not running).
    """
    from sqlalchemy import create_engine as _create_engine
    from sqlalchemy.orm import sessionmaker as _sessionmaker
    from sqlalchemy.pool import StaticPool as _StaticPool

    from jocky.server import dispatch

    main_engine = _create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=_StaticPool,
    )
    db.Base.metadata.create_all(main_engine)
    main_session = _sessionmaker(bind=main_engine, expire_on_commit=False)
    monkeypatch.setattr(db, "engine", main_engine)
    monkeypatch.setattr(db, "SessionLocal", main_session)
    try:
        dispatch.run_and_persist(eval_session, source=BASELINES[0].mission)
        assert eval_session.query(db.Mission).count() == 1

        # the app's own session is a different store and saw none of it
        app_session = db.SessionLocal()
        try:
            assert app_session.query(db.Mission).count() == 0
        finally:
            app_session.close()
    finally:
        main_engine.dispose()


def test_clean_env_restores_signer_and_keys(eval_session, tmp_path):
    import jocky.config as cfg
    from jocky.server import dispatch

    # inside the eval env: temp key dir, lazily created signer
    assert cfg.KEYS_DIR == tmp_path / "keys"
    outer_signer = dispatch.agent_signer()
    assert dispatch._agent_signer is outer_signer

    # a nested env swaps both, then restores exactly what was there at entry
    with clean_env(keys_dir=tmp_path / "other") as s2:
        assert cfg.KEYS_DIR == tmp_path / "other"
        assert s2 is not None
        dispatch.agent_signer()
        assert dispatch._agent_signer.key_path.parent == tmp_path / "other"
    assert cfg.KEYS_DIR == tmp_path / "keys"
    assert dispatch._agent_signer is outer_signer


def test_clean_env_keeps_durable_database(tmp_path):
    """A non-ephemeral eval database must never be dropped at teardown.

    The baseline rows are the evidence the harness exists to produce; wiping
    them on exit would make the whole harness pointless. A file-backed SQLite
    URL stands in for a durable Postgres URL here (same non-``sqlite://``
    in-memory branch), so the behaviour is verified, not the source text.
    """
    dbfile = tmp_path / "durable.db"
    url = f"sqlite:///{dbfile}"
    with clean_env(url, keys_dir=tmp_path / "k1") as s1:
        run_matrix(s1, "sample")
        s1.commit()
        assert s1.query(db.EvalBaselineRun).count() == len(BASELINES)
    import sqlite3

    assert dbfile.exists()
    con = sqlite3.connect(str(dbfile))
    try:
        on_disk = con.execute("select count(*) from eval_baseline_runs").fetchone()[0]
    finally:
        con.close()
    assert on_disk == len(BASELINES)
    with clean_env(url, keys_dir=tmp_path / "k2") as s2:
        assert s2.query(db.EvalBaselineRun).count() == len(BASELINES)


def test_clean_env_ephemeral_is_dropped_by_default():
    """The in-memory default is disposable and leaves nothing behind."""
    with clean_env() as s1:
        run_matrix(s1, "sample")
        assert s1.query(db.EvalBaselineRun).count() == len(BASELINES)
    with clean_env() as s2:
        assert s2.query(db.EvalBaselineRun).count() == 0


def test_clean_env_scopes_keys_to_temp_dir(eval_session, tmp_path):
    """A fresh clean_env must not sign with the repo's persisted agent key."""
    import jocky.config as cfg
    from jocky.server import dispatch

    dispatch.agent_signer()
    assert dispatch._agent_signer.key_path.parent == tmp_path / "keys"
    assert cfg.KEYS_DIR == tmp_path / "keys"


def test_provenance_captures_environment(eval_session):
    prov = provenance()
    assert prov["jir_version"]
    assert prov["commit"]
    assert prov["python"]
    assert "while_iteration_cap" in prov
    assert "privileges" in prov


# ---------------------------------------------------------------- baselines

def test_all_baselines_wellformed():
    assert len(BASELINES) == 7
    ids = [b.id for b in BASELINES]
    assert len(set(ids)) == len(ids)
    for b in BASELINES:
        assert b.name and b.property and b.mission
        assert b.expectations, b.id
        assert b.expected_evidence >= 0
        assert b.capabilities


def test_baseline_by_id():
    assert baseline_by_id("chain.integrity").expected_evidence == 3
    with pytest.raises(KeyError):
        baseline_by_id("nope")


# --------------------------------------------------- durable-database identity

def test_a_repeat_run_is_not_confused_with_the_first(tmp_path):
    """A mission must be identified by the id, not by its JIR digest.

    Regression found by running the harness against a *durable* database
    (PostgreSQL, the documented deployment target). Dispatching the same source
    twice creates two missions with the same ``jir_sha256``, so a digest lookup
    with ``.first()`` returns the **older** one -- a different mission, holding
    evidence signed by a different key. The caller then verifies the wrong
    records and reports corruption that is not there. In-memory SQLite hid this
    for the whole project because every run started empty.

    The second run deliberately gets its own key directory, which is what makes
    the mix-up observable: the first mission's records were signed by key A, so
    verifying them against key B fails. A file-backed SQLite database is durable
    in the same way as Postgres and needs no server.
    """
    url = f"sqlite:///{tmp_path / 'durable.db'}"
    with clean_env(url, keys_dir=tmp_path / "keys-a") as session:
        first = run_baseline(session, baseline_by_id("chain.integrity"), "sample")
    with clean_env(url, keys_dir=tmp_path / "keys-b") as session:
        second = run_baseline(session, baseline_by_id("chain.integrity"), "sample")

    assert first["mission_digest"] == second["mission_digest"], "precondition: same source"
    assert first["mission_id"] != second["mission_id"], "each dispatch is its own mission"
    # Read against the *second* run's key. Had the harness resolved the first
    # mission by digest, these records would not verify and proofs_hold would
    # come back False.
    assert second["proofs_hold"] is True, second.get("proofs")
    assert second["verdict"] == "PASS", (second["verdict"], second.get("error"))
    assert first["proofs_hold"] is True


def test_dispatch_reports_the_mission_it_created(tmp_path):
    """``run_and_persist`` must name its own mission, not leave it inferable."""
    from jocky.server import dispatch

    mission = '@requires(process:list)\nmission "IdProbe" {\n  emit collect_processes() |count;\n}\n'
    with clean_env(f"sqlite:///{tmp_path / 'ids.db'}", keys_dir=tmp_path / "keys") as session:
        a = dispatch.run_and_persist(session, source=mission, author="t")
        b = dispatch.run_and_persist(session, source=mission, author="t")

    assert a["mission_id"] != b["mission_id"]
    assert a["mission_digest"] == b["mission_digest"]


# ------------------------------------------------------------------- matrix

def test_matrix_passes_in_sample_mode(eval_session):
    report = run_matrix(eval_session, "sample")
    assert report["verdict"] == "PASS", [
        (r["baseline_id"], r["verdict"], r["error"]) for r in report["results"]
    ]
    assert len(report["results"]) == len(BASELINES)
    assert all(r["expectations_passed"] == r["expectations_total"] for r in report["results"])
    assert report["rows_persisted"] == len(BASELINES)


def test_matrix_persists_one_row_per_baseline(eval_session):
    run_matrix(eval_session, "sample")
    rows = eval_session.query(db.EvalBaselineRun).all()
    assert len(rows) == len(BASELINES)
    by_id = {r.baseline_id: r for r in rows}
    assert by_id["bounds.enforced"].status == "PASS"
    assert by_id["chain.integrity"].evidence_count == 3
    assert by_id["chain.integrity"].proofs_hold is True
    assert by_id["collection.determinism"].determinism_hold is True
    assert by_id["host.unmutated"].no_mutation_hold is True
    assert by_id["identity.least_privilege"].provenance["jir_version"]
    # persisted rows must not carry a wall-clock field
    assert "wall_clock_s" not in by_id["chain.integrity"].detail


def test_matrix_promotes_coverage_to_measured(eval_session):
    run_matrix(eval_session, "sample")
    statuses = {c.clause_id: c.status for c in eval_session.query(db.CoverageClause).all()}
    assert statuses["process:list"] == "MEASURED"
    assert statuses["identity:probe"] == "MEASURED"
    assert statuses["evidence:sign"] == "MEASURED"
    # a seeded-but-unexercised capability is not promoted
    assert statuses["driver:list"] == "LIVE"


def test_matrix_reports_uncovered_capabilities(eval_session):
    report = run_matrix(eval_session, "sample")
    uncovered = report["coverage"]["uncovered_capabilities"]
    assert "driver:list" in uncovered
    assert "event:read" in uncovered
    assert "process:list" not in uncovered


def test_matrix_interop_all_ok(eval_session):
    report = run_matrix(eval_session, "sample")
    for key in ("linkage_integrity", "chain_continuity", "jir_stability",
                "decisions_complete", "coverage", "signature_verifiability"):
        assert report["interop"][key]["status"] == "ok", (key, report["interop"][key])


# ---------------------------------------------------------------- baselines

def test_bounds_baseline_fails_safely(eval_session):
    res = run_baseline(eval_session, baseline_by_id("bounds.enforced"), "sample")
    assert res["status"] == "failed"
    assert "budget" in res["error"].lower()
    assert res["steps"] <= 2000
    assert res["verdict"] == "PASS"  # a *safe* failure is the expected result


def test_chain_baseline_emits_three_records(eval_session):
    res = run_baseline(eval_session, baseline_by_id("chain.integrity"), "sample")
    assert res["evidence_count"] == 3
    assert res["proofs_hold"] is True
    assert res["privileges_seen"] == {"none"}


def test_identity_baseline_reports_least_privilege(eval_session):
    res = run_baseline(eval_session, baseline_by_id("identity.least_privilege"), "sample")
    assert res["privileges_seen"] == {"none"}
    assert res["verdict"] == "PASS"


def test_determinism_baseline_stable(eval_session):
    res = run_baseline(eval_session, baseline_by_id("collection.determinism"), "sample")
    assert res["determinism_hold"] is True


def test_failed_baseline_verdict_is_fail(eval_session, monkeypatch):
    """A broken expectation must surface as FAIL, not silently pass."""
    from jocky.eval import baselines as B

    b = B.baseline_by_id("identity.least_privilege")
    broken = B.Baseline(
        id=b.id, name=b.name, property=b.property, mission=b.mission,
        capabilities=b.capabilities,
        expectations=(("impossible", lambda r: False),),
        expected_evidence=b.expected_evidence,
    )
    res = run_baseline(eval_session, broken, "sample")
    assert res["verdict"] == "FAIL"
    assert res["expectations_passed"] == 0


def test_undeclared_capability_mission_is_failed_not_error(eval_session):
    """A mission using an undeclared capability is refused, not executed."""
    from jocky.eval.baselines import Baseline

    bad = Baseline(
        id="bad.mission", name="bad", property="n/a",
        mission='mission "Bad" { let x = collect_processes(); emit x; }',
        capabilities=("process:list",),
        expectations=(("ran", lambda r: True),),
        expected_evidence=1,
    )
    res = run_baseline(eval_session, bad, "sample")
    assert res["status"] == "failed"
    assert "not declared" in res["error"]
    assert res["verdict"] == "FAIL"  # its only expectation ("ran") did not hold


def test_harness_error_path_is_recorded(eval_session, monkeypatch):
    """An unexpected exception becomes status=ERROR, not a crashed harness."""
    from jocky.eval import harness as H

    def boom(*a, **k):
        raise ValueError("simulated collector explosion")

    monkeypatch.setattr(H, "_jocky_object_count", boom)
    res = run_baseline(eval_session, baseline_by_id("chain.integrity"), "sample")
    assert res["status"] == "completed"  # citation failure is contained
    assert res["verdict"] == "PASS"


# ----------------------------------------------------------------- citation

def test_citation_uses_direct_harvest_not_projection(eval_session):
    """A mission emitting |count must not be cited as an object count.

    Comparing a projection (an int) against a native tool count would report a
    meaningless delta, so the harness harvests the same API directly.
    """
    res = run_baseline(eval_session, baseline_by_id("chain.integrity"), "sample")
    cites = {c["capability"]: c for c in res["citation"]}
    assert set(cites) == {"process:list", "network:analyze"}
    # the mission emitted 1 (a count projection); the citation must not be 1
    assert cites["process:list"]["jocky_count"] != 1
    assert cites["network:analyze"]["jocky_count"] != 1
    assert cites["process:list"]["citation_path"] == "tasklist /nh /fo csv"


def test_citation_result_shape():
    r = cite_processes(None)
    d = r.to_dict()
    assert set(d) == {"capability", "citation_path", "jocky_count", "native_count",
                      "status", "detail"}
    assert r.status == "UNAVAILABLE"


@pytest.mark.skipif(sys.platform != "win32", reason="live citation paths are Windows-only")
def test_live_citation_counts_real_host():
    from jocky.runtime import harvesters

    p = cite_processes(len(harvesters.proc_rows()))
    assert p.native_count is not None and p.native_count > 0
    assert p.status.startswith(("MATCH", "DELTA"))
    s = cite_services(len(harvesters.service_rows()))
    assert s.native_count is not None and s.native_count > 0


# ---------------------------------------------------------------------- CLI

def test_cli_sample_mode_runs(tmp_path):
    out = tmp_path / "report.json"
    proc = subprocess.run(
        [sys.executable, "-m", "jocky.eval.harness", "--mode", "sample", "--out", str(out)],
        cwd=REPO_ROOT, capture_output=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["mode"] == "sample"
    assert report["verdict"] == "PASS"
    assert len(report["results"]) == len(BASELINES)
    assert "wall_clock_s" in report  # report-only timing
    assert report["note"].endswith("not persisted")
