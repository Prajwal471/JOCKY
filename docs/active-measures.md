# Active Measures — JOCKY

A **baseline** (`docs/eval-harness.md`) shows that a mission works. An **active
measure** shows that something which *must not* work does not. Each measure
drives a case into the failure it is supposed to hit and reports `PASS` only
once that failure has been observed by running it.

These are the runnable form of the four properties claimed in
`docs/detection-definition.md`. Nothing here is asserted from documentation; the
dashboard and the CLI both execute the cases and report what happened.

## Run them

```bash
# all five, JSON on stdout, one line summary on stderr
python -m jocky.eval.measures

# one measure
python -m jocky.eval.measures --ids tamper-evident
```

Or from the dashboard: `POST /measures/run` (`{"measure_ids": [...]}` or `{}`
for all). The endpoint shells out to the CLI on purpose — see
[Isolation](#isolation).

## The two rules

**1. A refusal is not a pass on its own.** Every measure carries a *positive
control*: a near-identical case that is supposed to succeed. If the control
fails, the measure fails. A measure that refused everything, or that tripped
over an unrelated bug, cannot report `PASS`. This is the failure mode Block 10
hit, where a mission that never ran satisfied a trivial expectation.

**2. A measure never touches durable state.** Measures run inside
`jocky.eval.harness.clean_env`: an isolated database and a throwaway Ed25519
key. Demonstrating that JOCKY cannot be escalated cannot also corrupt the demo
database or overwrite the agent key that signed the real chain.

## The measures

### `no-escalation` — property 1, least-privilege by default

A mission declares `evidence:sign` only, then calls `collect_processes()`.

- the call is refused, naming `process:list` as the undeclared capability
- the refused mission persists **zero** evidence records
- **control:** the identical body with `process:list` declared completes and
  produces signed evidence

*Does not prove:* that the OS would refuse a privileged call. JOCKY refuses
because the mission did not ask for it, not because the token is weak.

### `never-grant` — property 2, read-only by construction

Three separate probes, because one denylist entry proves less than a structure:

- `edr:disable` is rejected as being in the never-grant set
- `file:write` is rejected as absent from the capability registry
- `process:list` is still accepted, so the registry is not merely empty

The second probe is the load-bearing one: read-only here is *structural* — there
is no write capability in the registry to grant in the first place, so a
write-shaped request is unknown rather than merely denied.

*Does not prove:* that every read-only collector is free of side effects. The
`host.unmutated` baseline covers that.

### `bounds.enforced` — property 3, bound execution

- an infinite loop is aborted with `step budget exhausted`
- it ran to `steps=2001` against `cap=2000`, proving the **cap** stopped it
  rather than the loop finishing early or the mission erroring for another reason
- recursion deeper than the cap is refused
- **control:** a finite loop with a generous budget completes

*Does not prove:* that the budget is a meaningful time limit on this host.
Wall-clock is deliberately not measured.

### `tamper-evident` — property 4, tamper-evident evidence

A payload is edited, then the forgery is escalated one layer at a time. Each
layer is caught by a *different, independent* check:

| Layer | Forger repairs | Caught by | Needs the key? |
| --- | --- | --- | --- |
| 1 | nothing | payload digest | no |
| 2 | `payload_sha256` | chain hash | no |
| 3 | `chain_hash` | successor's `prev_hash` anchor | no |
| 4 | successor's anchor | Ed25519 signature | **yes** |

The chain hash covers the *stored digest*, not the payload itself, so a
payload-only edit is caught by the digest check alone — repairing the digest is
what forces the next layer. The record verifies again once restored, which is
what proves the measure detected a real tamper rather than a broken harness.

*Does not prove:* that history cannot be rewritten. Anyone holding the agent key
can re-sign a whole chain. This raises the cost of an edit; it does not stop a
key holder from forging.

### `jir-pinned` — property 4, evidence anchored to an authorization

- a program modified *after* its mission card was issued is refused for `JIR drift`
- the requester key is deliberately different from the agent key, so pinning
  comes from the card's digest rather than key coincidence
- **control:** the program the card names still runs and emits evidence

*Does not prove:* that the card's capabilities match what the host would allow.
The card bounds the mission against its issuer, not against Windows.

## Isolation

`clean_env` obtains isolation by overriding process-global state: it swaps
`jocky.config.KEYS_DIR` and clears the cached `dispatch._agent_signer`. The
dispatch server serves requests on a thread pool, so doing this in-process would
let a measure run swap the live server's signing key underneath an in-flight
mission.

`POST /measures/run` therefore runs `python -m jocky.eval.measures` as a
**subprocess** with `JOCKY_EVAL_DATABASE_URL` and `JOCKY_EVAL_KEYS_DIR` stripped
from the environment. `tests/test_measures.py` asserts that a measure run leaves
the caller's `KEYS_DIR`, cached signer, agent key file and database rows exactly
as they were — including that a measure run does not *create* the repository key
if it did not already exist.

## What a PASS is worth

A `PASS` is a statement about **this build, on this host, in this mode**
(`sample` or `live`; `jocky.runtime.builtins` binds the mode at import time).
It is not a claim about Windows, about another operator's token, or about the
absence of a vulnerability. Each measure ships a `does_not_prove` string that the
API and the dashboard display next to the verdict, deliberately.

Results are not persisted. There is no `eval_measure_runs` table: a measure
verdict is a live observation of the current build, and the durable evaluation
record stays `eval_baseline_runs` (Block 10), which records the *baselines* with
their provenance.
