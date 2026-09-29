# Demo runbook

For a judge, or for anyone reproducing the JOCKY results from a fresh clone.
Every command below has been executed against this tree; the expected output is
quoted. Total time is about five minutes and needs no network.

Before starting, read `docs/implementation-status.md` — in particular the
section on what is *not* claimed — so the demo is not asked to support a claim
the repository does not make.

## 0. Prerequisites

- Python 3.12 or newer (developed on 3.13).
- Windows or Linux. The collectors are **Windows-only**; on Linux they return
  empty results rather than failing, so the interesting output is on Windows.
- No elevation. Nothing here requires administrator rights, and the demo never
  asks for them.
- PostgreSQL is optional. See step 2 for the zero-infrastructure path.

```sh
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"      # POSIX: .venv/bin/pip
```

## 1. Reproduce every documented result (one command)

This is the shortest path to "does what you say it does":

```sh
.venv/Scripts/python -m jocky.release --check
```

```
JOCKY cut check (sample): PASS
  [PASS] version: pyproject 0.1.0, changelog entry present
  [PASS] examples: 5 missions parse, JIR and pin deterministically
  [PASS] front-end-fails-closed: 5 invalid programs refused
  [PASS] capability-registry: 14 grantable, 8 never-grant, all refused at compile time
  [PASS] active-measures: 5 measures PASS over 27 observations, each stating a claim, a limit and its evidence
  [PASS] baseline-matrix: 7/7 baselines PASS, 7 rows recorded
  [PASS] interop-invariants: all 6 ok; signatures 12/12 verified
  [PASS] git: branch master, working tree clean
  cut is releasable
```

It exits non-zero and names the failing gate if any claim stops holding. Add
`--with-tests` to include the pytest suite, `--live` to read the real host
instead of sample data, and `--json` for machine-readable output.

## 2. Bring up the demo

**With PostgreSQL** (the deployment target):

```sh
docker run -d --name jocky-pg -e POSTGRES_PASSWORD=demo -e POSTGRES_USER=jocky \
  -e POSTGRES_DB=jocky -p 5432:5432 postgres:16-alpine
.venv/Scripts/python -m jocky.demo
```

**Without any infrastructure** — a file-backed SQLite database:

```sh
$env:JOCKY_DATABASE_URL="sqlite:///./demo.db"   # POSIX: export JOCKY_DATABASE_URL=...
.venv/Scripts/python -m jocky.demo
```

```
demo: database sqlite:///./demo.db
demo: migrating to head
demo: seeded 11 coverage clauses
demo: agent key ...\jocky\keys\agent_ed25519.pem
demo: mode=live
demo: dashboard  http://127.0.0.1:8000/ui/
```

`--sample` serves deterministic data instead of reading the host. The banner
reports the *effective* mode, not the flag, because the collectors bind their
mode at import time.

## 3. The five things worth showing

### 3.1 The four claimed properties are measured, not asserted

```sh
.venv/Scripts/python -m jocky.eval.measures
```

```
active measures live: PASS (5/5 measures passed)
```

Each measure reports a claim, the concrete evidence for it, **and what it does
not prove**. To see the honesty field rather than the verdict:

```sh
.venv/Scripts/python -m jocky.eval.measures --ids never-grant
```

### 3.2 The baseline matrix

```sh
.venv/Scripts/python -m jocky.eval.harness --mode live
```

`verdict: PASS` across 7 baselines, each with every expectation satisfied, and
`provenance.privileges: "none"` — the run needed no elevation. The report ends
with a `note` stating that `wall_clock_s` is operator convenience only and is
not persisted; that is deliberate, and no performance figure is claimed.

### 3.3 A mission produces a signed, chained evidence record

```sh
$body = @{ source = Get-Content examples/attack_surface.jky -Raw } | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/missions -Method Post -Body $body -ContentType "application/json"
```

Returns `mission_digest`, `mission_card`, `chain_hashes`, `runs`, and
`evidence_count` (6 for this mission). Follow it up:

```sh
Invoke-RestMethod http://127.0.0.1:8000/missions            # id, name, status, jir_sha256
Invoke-RestMethod http://127.0.0.1:8000/missions/1/evidence # the chained records
```

Each record carries `capability`, `chain_index`, `prev_hash`, `chain_hash`,
`payload_sha256` and `signature`. `chain_index` 0 has no `prev_hash`; every
later record links to its predecessor.

### 3.4 The equivalence proofs

```sh
Invoke-RestMethod http://127.0.0.1:8000/missions/1/proofs
```

```
{"mission_id": 1, "all_hold": true, "proofs": [{"proof": "P1_source_to_jir_determinism", "holds": true, ...}]}
```

### 3.5 The dashboard

Open <http://127.0.0.1:8000/ui/>. It is a single static page — no build step, no
CDN, nothing fetched from the network, so it works on an air-gapped host. It
shows the active measures, the coverage matrix, missions, evidence, and the
interop invariants. `/docs` serves the OpenAPI UI and `/health` the liveness
probe.

## 4. Demonstrating a refusal

The strongest thing the language does is refuse. All of these are rejected at
compile time, before any collector runs:

```sh
.venv/Scripts/python -c "from jocky.dsl.parser import parse; parse('@requires(edr:disable) mission \"A\" { emit 1; }')"
# JockySyntaxError: capability 'edr:disable' is in the never-grant set; JOCKY will not perform that action

.venv/Scripts/python -c "from jocky.dsl.parser import parse; parse('mission \"A\" { while true { } }')"
# JockySyntaxError: while true is prohibited: loops must be bounded
```

The never-grant set is `edr:disable`, `amsi:bypass`, `etw:patch`,
`privilege:escalation`, `kernel:write`, `inject:cross_process`, `mitm:network`
and `defender:disable`. None of them is expressible in a mission, and the
`never-grant` measure asserts that refusal every run.

## 5. If something fails

| Symptom | Cause | Fix |
| --- | --- | --- |
| `demo: cannot reach the database` | PostgreSQL is not running | Start the container, or set `JOCKY_DATABASE_URL` to a SQLite file |
| `alembic upgrade head failed` | Stale database from an earlier block | Delete the demo database file and re-run; migrations are additive |
| `active measures ...: ERROR` | A measure could not run | Read the `detail` field; it names the failing step |
| Mission returns 400 | The source was refused | The `detail` names the capability or construct that was rejected |
| Dashboard loads but evidence is empty | No mission has run yet | Do step 3.3 first |
| Collectors return nothing on Linux | Windows-only harvesters | Run on Windows, or use `--sample` |

## 6. What to say, and what not to say

Supported by the gates in this repository:

- every evidence record is signed, chained, and anchored to the mission's JIR
  digest, and tampering at any of four layers is detected;
- a mission cannot use a capability it did not declare, and cannot name a
  never-grant capability at all;
- loops are bounded by construction, not by a watchdog;
- collection needs no elevation, and does not write to the inspected host.

Not supported, and not claimed anywhere in this repository:

- any latency, overhead, detection-rate or false-positive-rate figure;
- any claim of being undetectable — least privilege is defensibility, not
  invisibility;
- portability to Linux — there is no Linux backend yet;
- any transformation, memory-execution or evasion capability.
