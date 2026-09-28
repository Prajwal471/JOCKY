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
```

## Layout

```
jocky/
  dsl/       lexer, parser, AST, JIR
  compiler/  LLVM codegen + passes
  runtime/   collectors (ctypes Windows, /proc Linux)
  server/    FastAPI, ORM, evidence chain
  crypto/    Ed25519 signing
examples/    *.jky missions
lab/         VM provisioning
tests/
```

## Build discipline

- One git commit per build block; test suite stays green.
- Demo must not require elevation. Collectors report `least_privilege` provenance.