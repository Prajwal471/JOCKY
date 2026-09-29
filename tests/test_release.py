"""Cut-gate tests (Block 12).

The gates that touch the filesystem run against the real repository files; the
gates that shell out to the evaluation harness are driven with a synthetic
report so a test asserts the *gate logic* (does a broken invariant fail the
cut?) instead of re-running the matrix.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from jocky import release
from jocky.dsl.parser import JockySyntaxError, parse

REPO_ROOT = Path(__file__).resolve().parents[1]


def _measure(measure_id: str = "no-escalation", **overrides) -> dict:
    measure = {
        "measure_id": measure_id,
        "claim": "a claim",
        "does_not_prove": "a limit",
        "detail": "concrete evidence",
        "verdict": "PASS",
        "observations": [{"observation": f"case {i}", "holds": True} for i in range(4)],
    }
    measure.update(overrides)
    return measure


def _measures_report(*measures: dict) -> dict:
    return {
        "verdict": "PASS" if all(m["verdict"] == "PASS" for m in measures) else "FAIL",
        "mode": "sample",
        "measures": list(measures),
    }


def _interop_report(**overrides) -> dict:
    interop = {key: {"status": "ok", "details": {}} for key in release.REQUIRED_INTEROP}
    interop["signature_verifiability"] = {
        "status": "ok",
        "details": {"total": 12, "verified": 12},
    }
    for key, value in overrides.items():
        interop[key] = value
    return {
        "verdict": "PASS",
        "mode": "sample",
        "interop": interop,
        "results": [
            {"baseline_id": f"b{i}", "verdict": "PASS"} for i in range(release.EXPECTED_BASELINES)
        ],
        "rows_persisted": release.EXPECTED_BASELINES,
    }


def _gate(report: release.Report, name: str) -> release.Gate:
    return next(g for g in report.gates if g.name == name)


# ------------------------------------------------------------ shipped files


def test_version_gate_accepts_the_shipped_metadata():
    report = release.Report()
    release.gate_version(report)
    assert _gate(report, "version").ok


def test_version_gate_fails_without_a_changelog_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(release, "CHANGELOG", tmp_path / "CHANGELOG.md")
    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
    report = release.Report()
    release.gate_version(report)
    assert not _gate(report, "version").ok


def test_examples_gate_passes_on_the_shipped_examples():
    report = release.Report()
    release.gate_examples(report)
    assert _gate(report, "examples").ok


def test_examples_gate_fails_on_a_broken_example(monkeypatch, tmp_path):
    (tmp_path / "broken.jky").write_text('mission "A" { while true { } }', encoding="utf-8")
    monkeypatch.setattr(release, "EXAMPLES_DIR", tmp_path)
    report = release.Report()
    release.gate_examples(report)
    assert not _gate(report, "examples").ok


def test_front_end_and_registry_gates_pass():
    report = release.Report()
    release.gate_front_end(report)
    release.gate_capability_registry(report)
    assert _gate(report, "front-end-fails-closed").ok
    assert _gate(report, "capability-registry").ok


def test_registry_gate_fails_on_an_overlapping_set(monkeypatch):
    """A capability that is both grantable and never-grant is a contradiction."""
    monkeypatch.setattr("jocky.dsl.types.NEVER_GRANT", frozenset({"process:list"}))
    report = release.Report()
    release.gate_capability_registry(report)
    gate = _gate(report, "capability-registry")
    assert not gate.ok
    assert "overlap" in gate.detail


def test_front_end_gate_fails_when_a_refusal_is_removed(monkeypatch):
    """If never-grant enforcement were lifted, the cut must refuse.

    ``checker`` binds the sets at import time, so the patch targets the module
    that actually performs the check rather than the one that defines them.
    """
    monkeypatch.setattr("jocky.dsl.checker.NEVER_GRANT", frozenset())
    monkeypatch.setattr("jocky.dsl.checker.CAPABILITIES", frozenset({"edr:disable"}))
    report = release.Report()
    release.gate_front_end(report)
    assert not _gate(report, "front-end-fails-closed").ok


# ------------------------------------------------------------------ measures


def test_measures_gate_requires_a_stated_limit(monkeypatch):
    monkeypatch.setattr(
        release, "_run_json", lambda *a, **k: _measures_report(_measure(does_not_prove="  "))
    )
    report = release.Report()
    release.gate_active_measures(report)
    assert not _gate(report, "active-measures").ok


def test_measures_gate_requires_the_full_catalogue(monkeypatch):
    monkeypatch.setattr(
        release, "_run_json", lambda *a, **k: _measures_report(_measure("only-one"))
    )
    report = release.Report()
    release.gate_active_measures(report)
    assert not _gate(report, "active-measures").ok


def test_measures_gate_fails_on_a_failing_measure(monkeypatch):
    monkeypatch.setattr(
        release,
        "_run_json",
        lambda *a, **k: _measures_report(_measure(verdict="FAIL")),
    )
    report = release.Report()
    release.gate_active_measures(report)
    assert not _gate(report, "active-measures").ok


def test_measures_gate_passes_on_a_well_formed_report(monkeypatch):
    monkeypatch.setattr(
        release,
        "_run_json",
        lambda *a, **k: _measures_report(
            *[_measure(f"m{i}") for i in range(release.EXPECTED_MEASURES)]
        ),
    )
    report = release.Report()
    release.gate_active_measures(report)
    assert _gate(report, "active-measures").ok


# --------------------------------------------------------- matrix / interop


def test_matrix_gate_requires_every_baseline(monkeypatch):
    report = _interop_report()
    report["results"] = report["results"][:3]
    monkeypatch.setattr(release, "_run_json", lambda *a, **k: report)
    out = release.Report()
    release.gate_baseline_matrix(out)
    assert not _gate(out, "baseline-matrix").ok


def test_interop_gate_fails_on_a_broken_invariant(monkeypatch):
    monkeypatch.setattr(
        release,
        "_run_json",
        lambda *a, **k: _interop_report(
            chain_continuity={"status": "broken", "details": {"issues": ["gap at 2"]}}
        ),
    )
    report = release.Report()
    release.gate_interop(report)
    gate = _gate(report, "interop-invariants")
    assert not gate.ok
    assert "chain_continuity" in gate.detail


def test_interop_gate_passes_and_names_its_evidence(monkeypatch):
    monkeypatch.setattr(release, "_run_json", lambda *a, **k: _interop_report())
    report = release.Report()
    release.gate_interop(report)
    assert "12/12" in _gate(report, "interop-invariants").detail


# ------------------------------------------------------------------ tagging


def test_tag_must_match_the_pyproject_version(capsys):
    assert release.main(["--tag", "9.9.9"]) == 2
    assert "does not match" in capsys.readouterr().err


def test_tag_prints_a_command_for_the_current_version(capsys):
    assert release.main(["--tag", "0.1.0"]) == 0
    assert capsys.readouterr().out.strip() == "git tag -a v0.1.0 -m 'JOCKY 0.1.0'"


# -------------------------------------------------- front-end regressions


def test_migrated_sqlite_schema_accepts_an_insert(tmp_path):
    """The demo builds its schema with Alembic, not ``create_all``.

    Regression: the Block 0 and Block 10 migrations defaulted timestamps with
    ``sa.text('now()')``, a PostgreSQL-only function, so every read route worked
    on a SQLite demo but the first insert failed with
    ``sqlite3.OperationalError: unknown function: now()``. The test suite did
    not catch it because it builds tables from ORM metadata, which spells the
    same intent as ``func.now()`` and compiles per dialect.
    """
    from sqlalchemy import create_engine

    from jocky.server import db

    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    env = dict(os.environ, JOCKY_DATABASE_URL=url)
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr[-600:]

    engine = create_engine(url)
    with Session(engine) as session:
        session.add(
            db.Endpoint(
                agent_id="a", hostname="h", platform="windows", os_version="t", collector_version="c"
            )
        )
        session.commit()
    engine.dispose()

def test_take_with_a_name_is_a_syntax_error_not_a_crash():
    """`|take` takes an int literal; a name must not raise ValueError."""
    with pytest.raises(JockySyntaxError):
        parse('mission "A" { emit 1 |take limit; }')


def test_unbounded_while_is_a_syntax_error_not_a_visit_error():
    """The documented refusal must arrive as JockySyntaxError.

    The source here is syntactically valid, so this exercises the builder's
    refusal rather than Lark's parser.
    """
    with pytest.raises(JockySyntaxError) as exc:
        parse('mission "A" { while true { } }')
    assert "bounded" in str(exc.value)


def test_report_render_names_failing_gates():
    report = release.Report()
    report.add("a-gate", True, "ok")
    report.add("b-gate", False, "broke")
    text = report.render()
    assert "[PASS] a-gate" in text and "[FAIL] b-gate" in text
    assert "cut refused" in text
    assert json.loads(json.dumps(report.as_dict()))["verdict"] == "FAIL"
