# JOCKY

A forensic scripting language and framework for computer & network forensic
analysis, designed so analysis runs without triggering security solutions.

## Stack

- Python 3.13, Lark, Pydantic, FastAPI
- `llvmlite==0.49.0` (LLVM IR generation + native execution)
- PostgreSQL 16 + Alembic (SQLite in-memory for tests only)
- Ed25519 signing (`cryptography`)

## Quick start

```sh
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"

# PostgreSQL (Docker):
docker run -d --name jocky-pg -e POSTGRES_PASSWORD=demo -e POSTGRES_USER=jocky \
  -e POSTGRES_DB=jocky -p 5432:5432 postgres:16-alpine

# schema:
.venv/Scripts/alembic upgrade head

# tests:
.venv/Scripts/pytest

# evaluation matrix (Block 10):
.venv/Scripts/python -m jocky.eval.harness --mode sample --out report.json
```

## Demo

```sh
# one command from clone to dashboard:
.venv/Scripts/python -m jocky.demo
# -> http://127.0.0.1:8000/ui/
```

`python -m jocky.demo` checks the database is reachable (failing with the exact
URL rather than hanging), runs `alembic upgrade head`, seeds the coverage matrix,
makes sure an agent key exists, and serves the dashboard. `--sample` serves
deterministic sample data instead of live host reads, `--matrix` also runs the
Block 10 baseline matrix first, and `--no-serve` prepares everything and exits.

The dashboard is a single static page — no build step, no CDN, nothing fetched
from the network, so it works on an air-gapped host. It shows the active
measures, the capability coverage matrix, live evidence streaming, missions,
and the interop invariants.

### Active measures

`docs/active-measures.md` — the runnable form of the four properties claimed in
`docs/detection-definition.md`. Each measure drives a case that *must* fail and
reports `PASS` only when that failure was observed:

```sh
.venv/Scripts/python -m jocky.eval.measures
.venv/Scripts/python -m jocky.eval.measures --ids tamper-evident
```

Every measure carries a positive control, so a measure that refused everything
cannot pass. They run in an isolated database with a throwaway agent key, and the
API shells out to the CLI so a measure cannot disturb the live server.

## Layout

```
jocky/
  dsl/       lexer, parser, AST, JIR
  compiler/  LLVM codegen + passes
  runtime/   collectors (ctypes Windows, /proc Linux)
  server/    FastAPI, ORM, evidence chain, interop metrics, static dashboard
  eval/      equivalence proofs, baseline matrix, evaluation harness, active measures
  demo/      one-command demo environment
  crypto/    Ed25519 signing
examples/    *.jky missions
lab/         VM provisioning
tests/
```

## Build discipline

- One git commit per build block; test suite stays green.
- Demo must not require elevation. Collectors report `least_privilege` provenance.