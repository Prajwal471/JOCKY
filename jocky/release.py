"""Release cut gate (Block 12).

A cut is a claim that the tree in front of a judge reproduces every result the
repository documents. This module is the executable form of that claim: it
re-runs the gates and refuses to report success unless each one holds.

Design rules, in priority order:

1. **Measure, never assert.** No gate writes down a performance number, a
   detection rate or a portability figure. Each gate either re-derives a value
   from the code in this tree or it fails.
2. **Deterministic by default.** Gates run in ``sample`` mode against a
   throwaway SQLite database so a judge needs neither a network nor a
   PostgreSQL instance. ``--live`` opts into live host reads.
3. **Honesty is itself a gate.** ``active-measures`` fails if any measure
   lacks a stated limit, because a measure that cannot say what it does not
   prove is not evidence of anything.

Usage::

    python -m jocky.release --check
    python -m jocky.release --check --live
    python -m jocky.release --check --with-tests --json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.orm import sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
EXAMPLES_DIR = REPO_ROOT / "examples"

#: Interop invariants the matrix records; all of them must hold at cut time.
REQUIRED_INTEROP = (
    "chain_continuity",
    "coverage",
    "decisions_complete",
    "jir_stability",
    "linkage_integrity",
    "signature_verifiability",
)

#: How many baselines the Block 10 matrix is specified to run.
EXPECTED_BASELINES = 7

#: How many active measures the Block 11 catalogue is specified to run.
EXPECTED_MEASURES = 5


@dataclass
class Gate:
    """One gate's outcome, with the evidence that decided it."""

    name: str
    ok: bool
    detail: str

    def render(self) -> str:
        return f"[{'PASS' if self.ok else 'FAIL'}] {self.name}: {self.detail}"


@dataclass
class Report:
    mode: str = "sample"
    gates: list[Gate] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str) -> None:
        self.gates.append(Gate(name, ok, detail))

    @property
    def ok(self) -> bool:
        return all(g.ok for g in self.gates)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": "PASS" if self.ok else "FAIL",
            "mode": self.mode,
            "gates": [{"name": g.name, "ok": g.ok, "detail": g.detail} for g in self.gates],
        }

    def render(self) -> str:
        lines = [f"JOCKY cut check ({self.mode}): {'PASS' if self.ok else 'FAIL'}"]
        lines += [f"  {g.render()}" for g in self.gates]
        lines.append("")
        lines.append(
            "cut is releasable" if self.ok else "cut refused: fix the failing gates above"
        )
        return "\n".join(lines)


# ------------------------------------------------------------------ helpers


def _run_json(module: str, args: list[str], *, live: bool) -> dict[str, Any]:
    """Run an eval CLI in a subprocess and parse its JSON report.

    A subprocess is not incidental: both eval entry points deliberately use
    process-global state, so running them in-process would prove nothing about
    a shipped tree.
    """
    env = dict(os.environ)
    if not live:
        env["JOCKY_SAMPLE_DATA"] = "1"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        proc = subprocess.run(
            [sys.executable, "-m", module, *args, "--out", str(out)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            env=env,
            timeout=900,
        )
        if proc.returncode != 0 or not out.exists():
            tail = (proc.stderr or proc.stdout or "").strip()[-400:]
            raise RuntimeError(f"{module} exited {proc.returncode}: {tail}")
        return json.loads(out.read_text(encoding="utf-8"))


# -------------------------------------------------------------------- gates


def gate_version(report: Report) -> None:
    """The version in pyproject must be real, and the changelog must name it."""
    if not PYPROJECT.exists():
        report.add("version", False, f"missing {PYPROJECT.name}")
        return
    version = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    if not version or version.count(".") < 1:
        report.add("version", False, f"pyproject version {version!r} is not a version")
        return
    if not CHANGELOG.exists():
        report.add("version", False, "CHANGELOG.md is missing")
        return
    if f"## {version}" not in CHANGELOG.read_text(encoding="utf-8"):
        report.add("version", False, f"CHANGELOG.md has no '## {version}' entry")
        return
    report.add("version", True, f"pyproject {version}, changelog entry present")


def gate_examples(report: Report) -> None:
    """Every shipped example must parse, lower to JIR, and pin deterministically."""
    from jocky.dsl.jir import digest, jir_document
    from jocky.dsl.parser import parse

    paths = sorted(EXAMPLES_DIR.glob("*.jky")) if EXAMPLES_DIR.is_dir() else []
    if not paths:
        report.add("examples", False, "no examples/*.jky found")
        return
    for path in paths:
        try:
            prog = parse(path.read_text(encoding="utf-8"))
            doc = jir_document(prog)
            if digest(prog) != digest(parse(path.read_text(encoding="utf-8"))):
                raise ValueError("JIR digest is not stable across parses")
            if not doc["program"]["declared_capabilities"]:
                raise ValueError("no capabilities declared")
        except Exception as exc:  # noqa: BLE001 - any failure fails the gate
            report.add("examples", False, f"{path.name}: {exc}")
            return
    report.add("examples", True, f"{len(paths)} missions parse, JIR and pin deterministically")


def gate_front_end(report: Report) -> None:
    """The refusals the documentation relies on must still refuse."""
    from jocky.dsl.parser import JockySyntaxError, parse

    cases = {
        "never-grant capability": '@requires(edr:disable) mission "A" { emit 1; }',
        "escalation capability": '@requires(privilege:escalation) mission "A" { emit 1; }',
        "unknown capability": '@requires(frobnicate:warp) mission "A" { emit 1; }',
        "unbounded while": 'mission "A" { while true { } }',
        "non-literal take": 'mission "A" { emit 1 |take limit; }',
    }
    accepted = []
    for label, src in cases.items():
        try:
            parse(src)
        except JockySyntaxError:
            continue
        except Exception as exc:  # noqa: BLE001
            report.add("front-end-fails-closed", False, f"{label}: raised {type(exc).__name__}: {exc}")
            return
        accepted.append(label)
    if accepted:
        report.add("front-end-fails-closed", False, f"accepted invalid source: {', '.join(accepted)}")
        return
    report.add("front-end-fails-closed", True, f"{len(cases)} invalid programs refused")


def gate_capability_registry(report: Report) -> None:
    """The grantable and never-grant sets must stay disjoint, and stay enforced."""
    from jocky.dsl.parser import JockySyntaxError, parse
    from jocky.dsl.types import CAPABILITIES, NEVER_GRANT

    overlap = CAPABILITIES & NEVER_GRANT
    if overlap:
        report.add("capability-registry", False, f"overlap: {sorted(overlap)}")
        return
    leaked = []
    for cap in sorted(NEVER_GRANT):
        src = f'@requires({cap}) mission "A" {{ emit 1; }}'
        try:
            parse(src)
        except JockySyntaxError:
            continue
        except Exception:  # noqa: BLE001
            continue
        leaked.append(cap)
    if leaked:
        report.add("capability-registry", False, f"granted never-grant capabilities: {leaked}")
        return
    report.add(
        "capability-registry",
        True,
        f"{len(CAPABILITIES)} grantable, {len(NEVER_GRANT)} never-grant, all refused at compile time",
    )


def gate_active_measures(report: Report) -> None:
    """All measures pass, and each one states its own limits.

    Non-vacuity is *not* re-derived here: a measure whose every case is
    expected to fail would pass a naive reading, so each measure ships a
    positive control and ``tests/test_measures.py`` asserts that breaking the
    implementation flips the verdict. This gate checks the reporting contract
    the measures owe their readers, and defers falsifiability to that suite.
    """
    try:
        data = _run_json("jocky.eval.measures", [], live=report.mode == "live")
    except RuntimeError as exc:
        report.add("active-measures", False, str(exc))
        return
    if data["verdict"] != "PASS":
        failed = [m["measure_id"] for m in data["measures"] if m["verdict"] != "PASS"]
        report.add("active-measures", False, f"verdict {data['verdict']}: {failed}")
        return
    if len(data["measures"]) != EXPECTED_MEASURES:
        report.add(
            "active-measures",
            False,
            f"expected {EXPECTED_MEASURES} measures, ran {len(data['measures'])}",
        )
        return
    observations = 0
    for measure in data["measures"]:
        mid = measure["measure_id"]
        observations += len(measure["observations"])
        if not measure.get("claim", "").strip():
            report.add("active-measures", False, f"{mid} states no claim")
            return
        if not measure.get("does_not_prove", "").strip():
            report.add("active-measures", False, f"{mid} states no limit")
            return
        if not measure.get("detail", "").strip():
            report.add("active-measures", False, f"{mid} reports no evidence detail")
            return
        if len(measure["observations"]) < 4:
            report.add(
                "active-measures",
                False,
                f"{mid} has {len(measure['observations'])} observations; expected at least 4",
            )
            return
    report.add(
        "active-measures",
        True,
        f"{len(data['measures'])} measures PASS over {observations} observations, "
        f"each stating a claim, a limit and its evidence",
    )


def gate_baseline_matrix(report: Report) -> None:
    """Every baseline and every interop invariant must hold."""
    try:
        data = _run_json(
            "jocky.eval.harness", ["--mode", report.mode], live=report.mode == "live"
        )
    except RuntimeError as exc:
        report.add("baseline-matrix", False, str(exc))
        return
    failed = [r["baseline_id"] for r in data["results"] if r["verdict"] != "PASS"]
    if data["verdict"] != "PASS" or failed:
        report.add("baseline-matrix", False, f"verdict {data['verdict']}: {failed}")
        return
    if len(data["results"]) != EXPECTED_BASELINES:
        report.add(
            "baseline-matrix",
            False,
            f"expected {EXPECTED_BASELINES} baselines, ran {len(data['results'])}",
        )
        return
    report.add(
        "baseline-matrix",
        True,
        f"{len(data['results'])}/{EXPECTED_BASELINES} baselines PASS, "
        f"{data['rows_persisted']} rows recorded",
    )


def gate_interop(report: Report) -> None:
    """Chain continuity, signature verifiability and JIR stability must hold.

    Each invariant is reported as ``{"status": ..., "details": ...}``, so the
    gate reads the status and puts the details in its own evidence line: a
    broken invariant must name what broke, not just that it did.
    """
    try:
        data = _run_json(
            "jocky.eval.harness", ["--mode", report.mode], live=report.mode == "live"
        )
    except RuntimeError as exc:
        report.add("interop-invariants", False, str(exc))
        return
    interop = data.get("interop", {})
    broken = [
        f"{k}={interop[k].get('status', 'absent') if isinstance(interop.get(k), dict) else interop.get(k)}"
        for k in REQUIRED_INTEROP
        if not (isinstance(interop.get(k), dict) and interop[k].get("status") == "ok")
    ]
    if broken:
        report.add("interop-invariants", False, f"not satisfied: {broken}")
        return
    sig = interop["signature_verifiability"].get("details", {})
    report.add(
        "interop-invariants",
        True,
        f"all {len(REQUIRED_INTEROP)} ok; signatures "
        f"{sig.get('verified')}/{sig.get('total')} verified",
    )


def gate_auth(report: Report) -> None:
    """Both mutating routes must refuse an unauthenticated caller.

    Checked in-process against the app rather than over HTTP: the point is the
    dependency, not the transport. Two cases matter, and the second is the one
    that is easy to get wrong -- an *unset* ``JOCKY_API_TOKEN`` must still
    refuse, otherwise dropping an environment variable silently reopens the
    endpoint.
    """
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    from jocky.server import db
    from jocky.server.api import app, get_session
    from jocky.server.auth import TOKEN_ENV, TOKEN_HEADER, TOKEN_IDENTITY

    payload = {
        "source": (
            '@requires(process:list)\n'
            'mission "CutGate" {\n'
            "  let p = collect_processes();\n"
            "  emit p |count;\n"
            "}\n"
        )
    }
    original = os.environ.get(TOKEN_ENV)
    # StaticPool keeps one connection alive, so the in-memory schema survives
    # across the requests a TestClient makes on different threads.
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
        with TestClient(app) as client:
            for label, env_value, headers in (
                ("missing token", original, {}),
                ("wrong token", original, {TOKEN_HEADER: "not-the-token"}),
                ("unset server token", None, {TOKEN_HEADER: "anything"}),
            ):
                if env_value is None:
                    os.environ.pop(TOKEN_ENV, None)
                else:
                    os.environ[TOKEN_ENV] = env_value
                for route in ("/missions", "/measures/run"):
                    r = client.post(route, json=payload, headers=headers)
                    if r.status_code != 401:
                        report.add(
                            "auth",
                            False,
                            f"{route} returned {r.status_code} to a {label}, expected 401",
                        )
                        return
            os.environ[TOKEN_ENV] = original or "cut-gate"
            r = client.post("/missions", json=payload, headers={TOKEN_HEADER: os.environ[TOKEN_ENV]})
            if r.status_code != 200:
                report.add("auth", False, f"valid token rejected: {r.status_code} {r.text[:200]}")
                return
            # The author must come from the credential, not the request body.
            listed = client.get("/missions").json()
            if not listed or listed[-1]["author"] != TOKEN_IDENTITY:
                got = listed[-1]["author"] if listed else None
                report.add("auth", False, f"mission author is {got!r}, expected {TOKEN_IDENTITY!r}")
                return
    except Exception as exc:  # noqa: BLE001 - any failure fails the gate
        report.add("auth", False, f"{type(exc).__name__}: {exc}")
        return
    finally:
        app.dependency_overrides.clear()
        if original is None:
            os.environ.pop(TOKEN_ENV, None)
        else:
            os.environ[TOKEN_ENV] = original
        engine.dispose()
    report.add(
        "auth",
        True,
        "POST /missions and POST /measures/run refuse a missing, wrong and unset token, "
        "and accept a valid one",
    )


def gate_git(report: Report, *, allow_dirty: bool) -> None:
    """A cut is made from a committed tree."""
    def git(*args: str) -> tuple[int, str]:
        proc = subprocess.run(
            ["git", *args], cwd=str(REPO_ROOT), capture_output=True, text=True
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()

    code, branch = git("rev-parse", "--abbrev-ref", "HEAD")
    if code != 0:
        report.add("git", False, "not a git repository")
        return
    _, status = git("status", "--porcelain")
    if status and not allow_dirty:
        changed = len(status.splitlines())
        report.add("git", False, f"{changed} uncommitted change(s); commit or pass --allow-dirty")
        return
    report.add(
        "git",
        True,
        f"branch {branch}, working tree {'dirty (allowed)' if status else 'clean'}",
    )


def gate_tests(report: Report) -> None:
    """The test suite, when the operator asks for it."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    tail = (proc.stdout or "").strip().splitlines()
    report.add("tests", proc.returncode == 0, tail[-1] if tail else "pytest produced no output")


# --------------------------------------------------------------------- main


def run_checks(
    *, live: bool = False, with_tests: bool = False, allow_dirty: bool = False
) -> Report:
    report = Report(mode="live" if live else "sample")
    gate_version(report)
    gate_examples(report)
    gate_front_end(report)
    gate_capability_registry(report)
    gate_active_measures(report)
    gate_baseline_matrix(report)
    gate_interop(report)
    gate_auth(report)
    if with_tests:
        gate_tests(report)
    gate_git(report, allow_dirty=allow_dirty)
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m jocky.release",
        description="Run the JOCKY release cut gates.",
    )
    ap.add_argument("--check", action="store_true", help="run the cut gates (default)")
    ap.add_argument(
        "--live", action="store_true", help="read the real host instead of sample data"
    )
    ap.add_argument("--with-tests", action="store_true", help="also run the pytest suite")
    ap.add_argument(
        "--allow-dirty", action="store_true", help="permit uncommitted changes in the tree"
    )
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    ap.add_argument(
        "--tag", metavar="VERSION", help="print the tag command a green cut authorises"
    )
    args = ap.parse_args(argv)

    if args.tag:
        version = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
        if args.tag != version:
            print(
                f"jocky: --tag {args.tag} does not match pyproject version {version}",
                file=sys.stderr,
            )
            return 2
        print(f"git tag -a v{version} -m 'JOCKY {version}'")
        return 0

    report = run_checks(
        live=args.live, with_tests=args.with_tests, allow_dirty=args.allow_dirty
    )
    print(json.dumps(report.as_dict(), indent=2) if args.json else report.render())
    return 0 if report.ok else 1


__all__ = ["Gate", "Report", "run_checks", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
