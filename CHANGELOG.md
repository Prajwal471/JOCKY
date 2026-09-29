# Changelog

All notable changes to JOCKY are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to semantic versioning for the language (`JIR_VERSION`) and the
package.

## Unreleased

### Fixed

- **Block 14** - a mission was re-identified by its JIR digest with `.first()`,
  which is ambiguous once the same source has been dispatched twice into the same
  database. On a durable database (PostgreSQL, the documented deployment target)
  the `tamper-evident` measure therefore read a *previous* run's evidence, signed
  by a different agent key, and reported FAIL on a chain that was intact. The
  whole project had only ever run against in-memory SQLite, where each run starts
  empty, so the bug was invisible. `run_and_persist` now reports the
  `mission_id` it created and the harness and the measure use it. Found by
  actually running the demo against PostgreSQL for the first time since Block 11.
- The pytest suite now clears `JOCKY_EVAL_DATABASE_URL` and
  `JOCKY_EVAL_KEYS_DIR` before collection. An operator who had the eval database
  exported — the normal state after running the harness — had the tests measure
  that database instead of an isolated one, and a failure in
  `test_matrix_interop_all_ok` said nothing about the code.

### Added

- **Block 13** - shared-token authentication on the two mutating dispatch
  routes. `JOCKY_API_TOKEN` is presented as `X-JOCKY-Token` and required by
  `POST /missions` and `POST /measures/run`; read routes stay open so the
  dashboard needs no login. Comparison is `secrets.compare_digest`, a missing
  and a wrong token are indistinguishable, and an **unset** `JOCKY_API_TOKEN`
  locks the routes rather than opening them. Mission `author` is now derived
  from the credential (`api-token-operator`); a body-supplied `author` is
  accepted for compatibility and ignored. The dashboard gained an API token
  field held in `sessionStorage`. `jocky/release.py::gate_auth` fails any cut
  whose mutating routes admit an unauthenticated caller. See
  `docs/authentication.md`.

### Known gaps at Unreleased

Roles, accounts and per-caller identity remain absent: one shared secret, no
login route, no RBAC and no revocation list, so paper §15 and §31 are still only
partly delivered. The full list is in `docs/implementation-status.md`.

## 0.1.0 - 2026-09-29

First tagged cut. The build is organised as twelve blocks, each one commit.

### Language and compiler front end

- **Block 1** - LALR front end: lexer, parser, typed AST, capability policy,
  and JIR identity (`sha256` over a canonical JSON document).
- **Block 2** - capability-honoring function library, bounded interpreter, and
  Ed25519 evidence signing. The never-grant set (`edr:disable`,
  `privilege:escalation`, `kernel:write`, ...) is unrepresentable rather than
  merely discouraged.

### Execution and evidence

- **Block 3** - elliptic-curve mission identity, JIR pinning, and card-gated
  missions.
- **Block 4a** - live `ctypes`/SCM/Authenticode/eventlog harvesters with a
  `JOCKY_SAMPLE_DATA` seam.
- **Block 4b** - dispatch, evidence persistence, and the FastAPI server.
- **Block 5** - contested-space detection definition and the anti-detection
  capability-gap argument (`docs/detection-definition.md`, `docs/gap-proof.md`).
- **Block 6** - validated PostgreSQL 16 chassis with Alembic, artifact,
  capability-decision and coverage capture.

### Claims, proofs and evaluation

- **Block 7** - evidence streams live over SSE as the interpreter emits it.
- **Block 8** - self-assertive read-only probes (`probe_registry`,
  `probe_service`, `probe_identity`) enter the evidence chain as findings.
- **Block 9** - interop metrics and equivalence proofs P1-P5
  (`docs/equivalence-proofs.md`).
- **Block 10** - evaluation harness: clean isolated environment, seven-baseline
  matrix, independent citations, and durable `eval_baseline_runs`
  (`docs/eval-harness.md`).
- **Block 11** - five fail-closed active measures with positive controls, a
  static air-gapped dashboard, and a one-command demo environment
  (`docs/active-measures.md`).

### Wrap-up

- **Block 12** - populated `examples/` with five verified missions; release cut
  gates (`python -m jocky.release --check`); `docs/implementation-status.md`
  (claim-to-evidence matrix against the research paper, including what is *not*
  implemented); `docs/demo-runbook.md`; `docs/cut-flow.md`; and this changelog.

### Fixed

- The front end leaked a raw `ValueError` for `|take <name>` and a raw lark
  `VisitError` for the unbounded-loop refusal; both now surface as
  `JockySyntaxError`, which is what callers and the docs assume.
- Migrations defaulted timestamps with `sa.text('now()')`, a PostgreSQL-only
  function, so a SQLite-backed demo served every read route but failed on the
  first insert with `unknown function: now()`. The default is now standard
  `CURRENT_TIMESTAMP` (revision `b7e4c1a9d3f2`).
- `README.md` advertised LLVM code generation, a `/proc` Linux backend and a
  provisioned `lab/`; none existed. Corrected, and the anti-detection tagline
  now matches the position in `docs/detection-definition.md`.

### Known gaps at 0.1.0

Recorded in full in `docs/implementation-status.md`. In short: no LLVM
code generation (the declared `llvmlite` dependency is unused), no controlled
program-transformation engine, no authentication, no multi-endpoint lab, and no
latency, detection-rate or portability figures.
