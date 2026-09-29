# Implementation status against the research paper

Block 12's final deliverable: an honest account of which paper claims this
repository implements, which it implements without measuring, and which it does
not implement at all.

The anchor is `JOCKY_Final_Research_Paper-1.pdf` (Darshan Ghule, 28 September
2026). Section numbers below refer to that paper.

## How to read this

| State | Meaning |
| --- | --- |
| **Measured** | Implemented, and a runnable gate in this repository produces a value. |
| **Exercised** | Implemented and covered by tests, but no figure is reported. |
| **Absent** | Not implemented. Stated plainly rather than implied. |

**No number appears in this document without the command that produces it.**
Where the paper's metrics (latency, overhead, detection rate, portability) are
not reported, that is a deliberate omission and is recorded as such — the paper
itself requires it: *"The final study must report measured values rather than
invented results."*

Reproduce the whole column with:

```sh
python -m jocky.release --check
```

## Claim-to-evidence matrix

### Language and compiler (§9-§13)

| Paper claim | State | Evidence |
| --- | --- | --- |
| A declarative security DSL | **Exercised** | `jocky/dsl/`; five verified missions in `examples/` |
| Lexer, parser, semantic analysis, fail-closed | **Measured** | `front-end-fails-closed` gate; `tests/test_dsl.py` |
| Capability-based authorization | **Measured** | `no-escalation`, `never-grant` measures; `capability-registry` gate |
| Versioned JIR, platform-independent | **Measured** | `jir_stability` interop invariant; P6 determinism in the matrix |
| JIR pins mission intent | **Measured** | `jir-pinned` measure |
| Capability validator / policy validator | **Measured** | `jocky/dsl/checker.py`; 14 grantable capabilities |
| **Surface syntax matches the paper's §10 grammar** | **Absent** | see *Divergences* below |
| LLVM code generation and passes (§11) | **Absent** | `jocky/compiler/` is an empty package |

### Runtime, evidence and orchestration (§14-§20, §29-§33)

| Paper claim | State | Evidence |
| --- | --- | --- |
| Capability-based security with least privilege | **Measured** | 8 baselines, `provenance.privileges == "none"` |
| Signed mission packages, card gating | **Measured** | `jir-pinned`; Block 3 elliptic-curve identity |
| Evidence hashing and chain of custody | **Measured** | P1-P5; `chain_continuity` = ok |
| Per-record Ed25519 signatures | **Measured** | `signature_verifiability` = 12/12 verified |
| Central management API | **Exercised** | 15 routes in `jocky/server/api.py` |
| Mission signing and dispatch | **Exercised** | `POST /missions`, orchestrator status transitions |
| Telemetry correlation into a unified timeline | **Partial** | mission evidence and SSE stream exist; no cross-endpoint correlation store |
| **Windows collectors** | **Measured** | live `ctypes`/SCM/Authenticode/eventlog harvesters |
| **Ubuntu `/proc` collectors (§13, Table 1)** | **Absent** | `harvesters._win` gates on `win32`; non-Windows degrades to `[]` |
| API authentication on mutating routes (§15, §31) | **Measured** | `X-JOCKY-Token` on `POST /missions` and `POST /measures/run`; fails closed when unset; `auth` gate |
| **Roles, accounts and per-caller identity (§15, §31)** | **Absent** | one shared secret; every authenticated caller is recorded as `api-token-operator`; no login route, no RBAC, no revocation list |
| Endpoint registration and multi-endpoint fan-out (§32) | **Exercised** | `dispatch` capability; single-host in practice |

### Research layers (§20-§28)

| Paper claim | State | Evidence |
| --- | --- | --- |
| Read-only self-assertive probes | **Measured** | Block 8 probes emit into the evidence chain |
| Living-off-the-land observation (§25) | **Exercised** | `lotl:scan` capability, read-only presence probe |
| **Controlled transformation engine (§20, §22)** | **Absent** | a headline contribution; nothing implements it |
| CI/CD research pipeline (§22.1, §34) | **Absent** | no pipeline definition in the repository |
| Memory-execution research (§23) | **Absent** | out of the runtime contract by design |
| Kernel / BYOVD research (§24) | **Partial** | `driver:list` reads driver inventory; no vulnerability catalog |
| Cloud-mediated communication research (§26) | **Absent** | not implemented, not claimed |
| Offensive research boundary (§44) | **Measured** | 8 never-grant capabilities are unrepresentable |

### Experimental method and metrics (§38-§42, §48-§49)

| Paper claim | State | Evidence |
| --- | --- | --- |
| Isolated-VM testbed | **Absent** | `lab/` is not provisioned |
| Baseline vs JOCKY condition comparison | **Partial** | 7 baselines measured on one host, not across a lab |
| Forensic yield | **Measured** | `evidence_count` per baseline |
| Evidence integrity `I` | **Measured** | verified/total per run |
| Portability `P` (§39) | **Absent** | needs a second operating system |
| Overhead / resource `ΔT` (§39) | **Absent** | deliberately not reported |
| Detection rate `DR` (§40) | **Absent** | deliberately not reported |
| False-positive rate `FPR` (§40) | **Absent** | deliberately not reported |
| Detection latency `Ld` (§30) | **Absent** | deliberately not reported |
| Transformation hypotheses H4 (§41) | **Absent** | needs the transformation engine |

Wall-clock is measured for operator convenience, is excluded from every
durable record, and is never presented as a performance result.

## Why those metrics are absent

They are missing for two different reasons, and the difference matters.

**Environment limits.** Portability needs a second operating system and the
hypotheses need the transformation engine. Both are unbuilt, so no figure could
be honest.

**Deliberate scope.** Latency, overhead, detection rate and false-positive rate
are *not* reported even though a rough version could be produced from this
single host, because a single-host, single-configuration number would not
generalise — the paper's own §49 makes exactly this point, and a fabricated
precision figure is worse than an acknowledged gap. The dashboard therefore
shows counts and invariants, not performance.

## Divergences from the paper

**Surface syntax.** The paper's §9-§10 sketches a block-structured form
(`target{} requires{} collect{} analyze{} evidence{} report{}`). The
implemented language is a script form with functions, control flow and pipes:

```
@requires(process:list, network:analyze)
mission "Attack Surface" {
  fn tally() -> int {
    let procs = collect_processes();
    emit procs |count "process records";
    return procs |count;
  }
  emit tally();
}
```

The paper presents its grammar as a simplified sketch; the script form is what
is implemented, tested and pinned. Capability names likewise differ
(`observe.process` in the paper, `process:list` here), and the implemented set
is the narrower, read-only one.

**JIR shape.** The paper's §12 example is an operation list keyed by target
platform. The implemented JIR is a canonical JSON document of units,
functions, statements and declared capabilities, versioned as `0.1.0`, and
carries no target-platform field because only one platform is implemented.

**An unused dependency.** `llvmlite==0.49.0` is declared in `pyproject.toml`
but is not imported anywhere in the codebase. It is the intended dependency of
the unbuilt compiler layer. It should be removed or the layer built before the
next cut; leaving it declared and unused is a known issue of this cut.

## Also corrected at 0.1.0

- The front end leaked a raw `ValueError` for `|take <name>` and a raw lark
  `VisitError` for the unbounded-loop refusal. Both now surface as
  `JockySyntaxError`, which is what callers and the documentation assume.
- `examples/` and `lab/` were advertised in the README layout. `examples/` now
  holds five verified missions; `lab/` is marked unprovisioned instead.
