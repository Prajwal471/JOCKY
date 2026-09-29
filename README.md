# JOCKY

A forensic scripting language and framework for computer & network forensic
analysis, designed so that analysis is **read-only, least-privilege and
independently defensible**: every observation is signed into a hash chain
anchored to the mission, and every collector cites the same public API a
reviewer would use to check it.

JOCKY does not claim to be undetectable. Least privilege buys defensibility,
not invisibility — see `docs/detection-definition.md` and
`docs/gap-proof.md`.

## Stack

- Python 3.13, Lark, Pydantic, FastAPI
- PostgreSQL 16 + Alembic (SQLite supported for a zero-infrastructure demo)
- Ed25519 signing (`cryptography`)

`llvmlite==0.49.0` is declared as a dependency but is not yet imported: the
compiler and code-generation layer is unbuilt. See
`docs/implementation-status.md`.

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

### Authentication

The two routes that cause work require a shared token; everything else is open
so the dashboard works without a login.

```sh
export JOCKY_API_TOKEN="$(python -c 'from jocky.server.auth import new_token; print(new_token())')"
.venv/Scripts/python -m jocky.demo
```

`POST /missions` and `POST /measures/run` then want the header
`X-JOCKY-Token: $JOCKY_API_TOKEN`; paste the same value into the dashboard's
**API token** field. If `JOCKY_API_TOKEN` is unset the server **locks** those two
routes rather than opening them, so a missing environment variable cannot
silently expose them. `docs/authentication.md` covers rotation and what this
deliberately is not — there are no accounts, roles or per-caller identity.

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

## Reproduce every claim

```sh
.venv/Scripts/python -m jocky.release --check
```

One command re-derives every result this repository documents: the shipped
examples, the front-end refusals, the capability registry, the five active
measures, the seven-baseline matrix, the interop invariants, and the
authentication refusals. It exits
non-zero and names the failing gate if any of them stops holding. `--live`
reads the real host, `--with-tests` adds the pytest suite, `--json` is for
tools. Details in `docs/cut-flow.md`.

## Status and limits

`docs/implementation-status.md` maps each claim in
`JOCKY_Final_Research_Paper-1.pdf` to what this repository actually implements,
including what is **absent**: no LLVM code generation, no program-transformation
engine, no accounts or roles (authentication is one shared token — see above), no
Linux backend, no provisioned lab, and no
latency, detection-rate, false-positive or portability figures. Those are not
oversights to be discovered during a demo; they are recorded.

## Docs

| Document | Contents |
| --- | --- |
| `docs/implementation-status.md` | claim-to-evidence matrix against the paper |
| `docs/authentication.md` | the API token, fail-closed behaviour, and its limits |
| `docs/demo-runbook.md` | judge-facing runbook, with recovery steps |
| `docs/cut-flow.md` | release cut gates and tagging procedure |
| `docs/detection-definition.md` | what "detection" means here, and the four claimed properties |
| `docs/gap-proof.md` | the contested-space capability-gap argument |
| `docs/equivalence-proofs.md` | proofs P1-P5 and their boundaries |
| `docs/eval-harness.md` | baseline matrix protocol and limitations |
| `docs/active-measures.md` | the five counterfactual measures |

## Layout

```
jocky/
  dsl/       lexer, parser, AST, JIR
  runtime/   collectors (ctypes Windows; non-Windows degrades to empty)
  server/    FastAPI, ORM, evidence chain, interop metrics, static dashboard
  eval/      equivalence proofs, baseline matrix, evaluation harness, active measures
  demo/      one-command demo environment
  crypto/    Ed25519 signing
  release.py cut gates
examples/    *.jky missions (five, all verified by the cut gates)
lab/         not provisioned - the paper's isolated-VM testbed is unbuilt
tests/
```

## Build discipline

- One git commit per build block; test suite stays green.
- Demo must not require elevation. Collectors report `least_privilege` provenance.
- No number ships without the command that produces it, and no performance,
  detection-rate or portability figure ships at all until a lab can measure it.
- `python -m jocky.release --check` must pass before a cut. See `docs/cut-flow.md`.