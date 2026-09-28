# Evaluation Harness — Clean Env + Baseline Matrix

Block 10 answers one question: **which claims does JOCKY actually hold, when
measured rather than asserted?** The claims are the four properties in
`detection-definition.md`; the measurement is the baseline matrix in
`jocky/eval/baselines.py`, run by `jocky/eval/harness.py`.

The harness is not a benchmark. It measures whether a mission ran, whether its
evidence verifies, and whether the host was left alone. Timing is collected for
operator convenience, written to the local report, and **never persisted**.

## The matrix

| Baseline | Property measured | How it is measured |
| --- | --- | --- |
| `identity.least_privilege` | 1. least-privilege by default | `probe_identity` rows carry user/sid; every record's provenance is `privileges: "none"` |
| `registry.autostart_read` | 2. read-only by construction | hive/path/value_type read from a Run key without elevation |
| `service.config_read` | 2. read-only by construction | SCM config for a named service, read-only |
| `chain.integrity` | 4. tamper-evident evidence | 3 emits; P1–P5 equivalence proofs recomputed from persisted rows |
| `bounds.enforced` | 3. bound execution | a runaway `while` is refused by the step budget; steps stay within the override |
| `collection.determinism` | repeatable observation (P6) | two harvests of unchanged state are byte-identical after stripping `_nonce`/`_mission_digest` |
| `host.unmutated` | 2. read-only by construction | read-only state fingerprint (autostarts, LoTL binaries, service name/state/binary_path) identical before and after |

A baseline **passes** only if its expectations hold *and* the mission reached the
status those expectations assume. `bounds.enforced` is the one baseline whose
correct outcome is a *failure* (`status == "failed"`); every other baseline must
complete. Without that rule a mission that never ran could satisfy a trivial
expectation and be scored PASS.

## Clean env

`clean_env()` guarantees a measurement cannot contaminate the demo database or
impersonate the demo agent:

- its own engine/session — `JOCKY_EVAL_DATABASE_URL`, else in-memory SQLite;
- its own key directory, with the agent signer reset, so evaluation signatures
  are made with a throwaway key;
- `config.KEYS_DIR` and `dispatch._agent_signer` restored on exit;
- **schema teardown only for in-memory SQLite.** A file-backed or server
  database is never dropped — the persisted baseline rows are the evidence this
  harness exists to produce.

`Ed25519Signer` resolves `config.KEYS_DIR` at construction rather than at
import, which is what makes the key override actually take effect.

## Independent-citation column

`jocky/eval/citation.py` re-counts the same object class through the native
citation path named in `gap-proof.md` and reports a status, never a silent pass:

| Capability | Citation path |
| --- | --- |
| `process:list` | `tasklist /nh /fo csv` |
| `network:analyze` | `netstat -ano` |
| `service:list` | `sc query type= service state= all` |

The JOCKY side of the comparison is a **direct harvest**, not the mission's
emitted value: a mission that emits `|count` collapses rows to an integer, and
comparing a projection against a native tool count would report a delta that
says nothing about agreement.

Status is `MATCH`, `DELTA n`, or `UNAVAILABLE` (non-Windows, or the tool
absent). A delta is not a failure — the two reads are not atomic. Observed on
the development host: `service:list` **MATCH** at 316/316; `process:list` a
delta of a few rows (the process table moves between reads); `network:analyze`
a large native excess, because `netstat` reports IPv4 *and* IPv6 sockets while
the collector reads the IPv4 extended table only (`harvesters._tcp_table`
raises `NotImplementedError` for the IPv6 owner-PID layout). That asymmetry is
reported in the row's `detail` rather than smoothed over.

## Persistence

Each baseline writes one `eval_baseline_runs` row (migration `c41a7e2f9b10`):
verdict, expectation tallies, evidence count, steps, the
`proofs_hold`/`determinism_hold`/`bounds_hold`/`no_mutation_hold` booleans, the
citation deltas, the environment provenance, and per-expectation detail.

There is deliberately **no wall-clock column**; `EvalBaselineRun` is a record of
auditable claims, and performance numbers wait for the Phase-2 measurement
phase. `steps` is retained because it evidences bound execution, not speed.

A matrix run also promotes `coverage_clauses.status` from `LIVE` to `MEASURED`
for every capability a passing baseline exercised, and reports the capabilities
no baseline touched. On the development host 9 of 11 seeded capabilities reach
`MEASURED`; `driver:list` and `event:read` remain `LIVE` — present and
mechanism-documented, but not yet exercised by a baseline.

## Usage

```sh
# deterministic, anywhere
python -m jocky.eval.harness --mode sample --out report.json

# live, against the real host and a durable eval database
python -m jocky.eval.harness --mode live --db postgresql+psycopg://jocky:demo@localhost:5432/jocky_eval --out report.json
```

Exit code is 0 only when every baseline passes. `JOCKY_SAMPLE_DATA` and
`JOCKY_EVAL_KEYS_DIR` are honoured; one mode per process is the intended usage
because `jocky.runtime.builtins` binds its sample/live branch at import time.

## Limits

- The measured host is a single unelevated Windows 11 workstation. A clean-VM
  baseline set belongs in `lab/` and is not yet provisioned.
- `bounds.enforced` overrides the step budget to keep the matrix quick, so it
  evidences that a bound is *enforced*, not that the default budget suffices.
- Capability coverage is measured by the harness; the *correctness* of a
  collector's findings is not — the citation column corroborates counts, not
  semantics.
