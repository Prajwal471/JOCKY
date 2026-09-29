# Changelog

All notable changes to JOCKY are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to semantic versioning for the language (`JIR_VERSION`) and the
package.

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
