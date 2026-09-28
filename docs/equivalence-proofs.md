# Equivalence Proofs and Interop Metrics

Block 9 delivers the machine-checkable half of the trust argument: proofs that
a JOCKY finding is what it claims to be, and that it survives the hops between
the source, the JIR, the evidence store, and a second implementation.

Every proof below is either **machine-checked** (a function in
`jocky/eval/equivalence.py` with a test in `tests/test_equivalence.py`) or
**argued** (prose only, and labelled as such). The machine-checked set runs
automatically on every completed mission.

## The proof chain

```
source ──P1──▶ JIR digest ──P2──▶ canonical bytes
                  │
                  ├──P3──▶ every evidence record anchored to the digest
                  │
                  └──▶ Artifact.jir_hash
                            │
                            P4 chain_hash recompute
                            P5 Ed25519 signature verify
```

## P1 — Source to JIR determinism *(machine-checked)*

Two independent parses of the same mission source yield one JIR digest, so
mission identity is a function of the text and its declared capabilities, not
of parse order or interpreter state. `test_p1_changes_with_capability_set`
pins the converse: changing the declared capability set changes the digest.
This is what makes capability policy *auditable* — you cannot swap the
capabilities a mission declares without changing what it is.

`prove_source_to_jir_determinism(source)`

## P2 — Canonical serialization is the interop contract *(machine-checked)*

`jir_document` → `serialize` emits JSON with `sort_keys=True`,
`separators=(",", ":")`, `ensure_ascii=False`. The bytes are stable under
re-serialization and round-tripping. A second implementation — the Rust port
named in `jocky/dsl/ast.py` — reproduces identical bytes from the same JIR, so
a mission digest computed in Python can be recomputed and pinned on the other
side. This is the interop surface; the proof is that it is byte-exact.

`prove_canonical_serialization(doc)`

## P3 — Mission anchoring *(machine-checked)*

Every emitted record carries `_mission_digest` inside its signed payload, and
that digest is an input to `chain_hash`. Evidence therefore cannot be
reassigned to a different mission, and a mission's evidence cannot be silently
swapped: the digest enters the hash.

`prove_mission_anchor(mission, records)`

## P4 — Chain hash recompute *(machine-checked)*

`chain_hash = sha256({index, prev, payload_sha256, mission_digest})` is
recomputed from the persisted record and must reproduce bit for bit, and each
record's `prev_hash` must equal its predecessor's `chain_hash` (the head record
anchors on `""`). Insertion, deletion, or reordering of evidence breaks the
chain and is detected by `verify_record` / `interop_metrics`.

`prove_chain_and_signatures(records, pubkey)`

## P5 — Signature authenticity *(machine-checked)*

The Ed25519 signature covers the canonical blob
`{chain_hash, payload_sha256, prev}`. `verify_record` reproduces the payload
digest, the chain hash, and verifies the signature against the agent public
key, failing closed on any mismatch. `tests/test_equivalence.py` includes a
tamper-negative case and a wrong-key case.

## P6 — Collection determinism *(standalone; not in dispatch)*

The strongest claim available about the collectors: two consecutive harvests of
an unchanged host produce byte-identical observation payloads once the
evidence-injected fields (`_nonce`, `_mission_digest`) are stripped, per
`harvest_payload`. This is deliberately not run inside dispatch — it re-reads
the host, which is a measurement, not a collection. Run it against a live
endpoint with `jocky.eval.equivalence`'s P6 helper when establishing a
baseline.

## Interop metrics (`jocky/server/metrics.py`)

`interop_metrics(session, agent_pubkey_hex)` sweeps persisted state and returns
per-invariant status with the offending issues, exposed at
`GET /metrics/interop`:

| Invariant | Meaning | Failure mode caught |
| --- | --- | --- |
| `linkage_integrity` | every artifact/decision/evidence row resolves to a real mission and endpoint | orphaned or dangling foreign rows |
| `coverage` | every declared capability is present in the seeded coverage matrix | a mission exercising an uncovered signal |
| `decisions_complete` | ALLOW decisions cover the mission's declared caps | a capability used without a recorded decision |
| `chain_continuity` | `prev_hash` links across each mission's records | evidence insertion, deletion, or reorder |
| `jir_stability` | `digest(parse(source)) == jir_sha256 == artifact.jir_hash`, uniform JIR version | post-hoc source or JIR tampering |
| `signature_verifiability` | every record passes `verify_record` | forged or mutated evidence |

`GET /missions/{id}/proofs` returns the per-mission P1-P5 result.
A completed mission sets `Artifact.equivalence_proven = True` only when the
whole P1-P5 set holds for it (`dispatch._mark_equivalence`).

## Argued, not machine-checked

- **Portability of P2 to a future Rust implementation.** The canonical byte
  format is fixed and round-trip-proven here; the cross-language implementation
  is not yet in the tree, so the *hop* is argued from the format, not executed.
- **`llvm_ir_hash` / `equivalence_proven` at the compiler boundary.** The
  artifact table records `passes` and a JIR hash; the LLVM pass equivalence
  itself belongs to the compiler blocks and is out of scope for the storage /
  chain / JIR-stability emphasis of this block.
