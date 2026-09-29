"""One-command demo environment (Block 11).

Order matters in this module. ``--sample`` must set ``JOCKY_SAMPLE_DATA``
*before* anything imports :mod:`jocky.runtime.builtins`, because the builtin
implementations bind their sample/live mode at import time. Every other step
depends on the database being reachable and migrated, so the failure modes are
reported with the exact URL and a fix rather than a stack trace.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from sqlalchemy.orm import sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[2]


def _say(msg: str) -> None:
    print(msg, flush=True)


def _fail(msg: str, hint: str = "") -> int:
    print(f"demo: {msg}", file=sys.stderr, flush=True)
    if hint:
        print(f"      {hint}", file=sys.stderr, flush=True)
    return 1


# ----------------------------------------------------------------- database

def _database_url() -> str:
    from jocky.config import DATABASE_URL, DEFAULT_DATABASE_URL

    return DATABASE_URL or DEFAULT_DATABASE_URL


#: Seconds to wait for the database before giving up. Without this an
#: unreachable host hangs the demo indefinitely instead of reporting the URL.
CONNECT_TIMEOUT_S = 5


def check_database(url: str) -> int | None:
    """Return None when reachable, else a process exit code."""
    from sqlalchemy import create_engine

    connect_args = {"connect_timeout": CONNECT_TIMEOUT_S} if "psycopg" in url else {}
    try:
        engine = create_engine(url, connect_args=connect_args)
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        engine.dispose()
    except Exception as exc:  # noqa: BLE001 - any driver error is a setup problem
        hint = ""
        if url.startswith("postgresql"):
            hint = (
                f"is PostgreSQL running and reachable at {_host_of(url)}? "
                "Set JOCKY_DATABASE_URL to point somewhere else, or use "
                "JOCKY_DATABASE_URL=sqlite:///./demo.db for a file-backed demo."
            )
        return _fail(f"cannot reach the database at {redact(url)}: {exc}", hint)
    return None


def _host_of(url: str) -> str:
    tail = url.split("@", 1)[-1]
    return "/" + tail if "/" in tail else tail


def redact(url: str) -> str:
    """Never echo a password back to the terminal."""
    if "@" not in url or ":" not in url.split("@", 1)[0].split("//", 1)[-1]:
        return url
    scheme, rest = url.split("//", 1)
    creds, tail = rest.split("@", 1)
    user = creds.split(":", 1)[0]
    return f"{scheme}//{user}:***@{tail}"


def migrate(url: str) -> int | None:
    env = dict(os.environ)
    env["JOCKY_DATABASE_URL"] = url
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            env=env,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return _fail("alembic upgrade head timed out")
    if proc.returncode != 0:
        return _fail(
            "alembic upgrade head failed: "
            + proc.stderr.decode("utf-8", "replace").strip()[-600:]
        )
    return None


# -------------------------------------------------------------------- seed

def seed(url: str) -> dict[str, Any]:
    """Seed the coverage matrix and make sure the agent key exists.

    Builds its own engine from ``url`` rather than reusing the module-level
    ``db.engine``: that engine is bound to whatever ``DATABASE_URL`` was at
    import time, so reusing it could seed a different database than the one
    just checked and migrated.
    """
    from jocky.server import db
    from jocky.server.coverage import seed_coverage
    from jocky.runtime.evidence import Ed25519Signer

    engine = db.engine_factory(url)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    try:
        clauses = seed_coverage(session)
        session.commit()
        signer = Ed25519Signer()
        return {
            "coverage_clauses": clauses,
            "agent_key": str(signer.key_path),
            "agent_id": signer.public_key_hex[:16],
        }
    finally:
        session.close()
        engine.dispose()


def run_matrix(database_url: str) -> int:
    """Optionally record an evaluation matrix in the eval database."""
    from jocky.eval.harness import main as harness_main

    return harness_main(["--mode", "live", "--db", database_url])


# -------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m jocky.demo",
        description="Bring up the JOCKY demo environment and dashboard.",
    )
    ap.add_argument(
        "--sample",
        action="store_true",
        help="serve deterministic sample data instead of live host reads",
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument(
        "--matrix",
        action="store_true",
        help="also run the Block 10 baseline matrix before serving",
    )
    ap.add_argument(
        "--no-serve",
        action="store_true",
        help="prepare the environment and exit without starting the server",
    )
    args = ap.parse_args(argv)

    # Must happen before jocky.runtime.builtins is imported anywhere.
    if args.sample:
        os.environ["JOCKY_SAMPLE_DATA"] = "1"

    url = _database_url()
    _say(f"demo: database {redact(url)}")
    code = check_database(url)
    if code is not None:
        return code

    _say("demo: migrating to head")
    code = migrate(url)
    if code is not None:
        return code

    info = seed(url)
    _say(f"demo: seeded {info['coverage_clauses']} coverage clauses")
    _say(f"demo: agent key {info['agent_key']}")

    if args.matrix:
        eval_url = (
            os.environ.get("JOCKY_EVAL_DATABASE_URL")
            or url.replace("/jocky", "/jocky_eval")
        )
        _say(f"demo: running the baseline matrix against {redact(eval_url)}")
        if run_matrix(eval_url) != 0:
            _say("demo: matrix did not pass; the dashboard will show it")

    if args.no_serve:
        _say("demo: prepared (--no-serve)")
        return 0

    # Report the *effective* mode, not the flag: the collectors bind their mode
    # from the environment, so a banner driven by the flag alone can disagree
    # with what is actually being collected.
    from jocky import config

    mode = "sample" if config.SAMPLE_DATA else "live"
    _say("")
    _say(f"demo: mode={mode}")
    _say(f"demo: dashboard  http://{args.host}:{args.port}/ui/")
    _say(f"demo: openapi    http://{args.host}:{args.port}/docs")
    _say(f"demo: health     http://{args.host}:{args.port}/health")
    _say("")

    import uvicorn

    uvicorn.run(
        "jocky.server.api:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="warning",
    )
    return 0


__all__ = ["main", "check_database", "migrate", "seed", "redact"]
