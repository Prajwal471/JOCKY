# Detection in Contested Space — JOCKY Definition

## Scope

This document fixes what *detection* means for JOCKY's eval deliverables, and
is written for the contested-space evaluation (Block 5). "Contested space"
here means: an analyst operates on a host that is (or is assumed to be)
adversary-controlled, under a strictly least-privilege identity, with no
install-time privileges, no persistence of its own, and no guarantee that the
inspectee's telemetry is trustworthy. The analyst's own observations must
survive that assumption.

## Working definition

> **Detection** is the combination of (a) an **observation** (a fact,
> measurement, or configuration read), and (b) an **attribution rule** that
> maps that observation to a security-relevant state (benign, suspicious,
> malicious) — where both the observation and the rule must be **repeatable**
> and **independently citable**.

Detection therefore has three separable components:

| Component | Contested-space requirement |
| --- | --- |
| Observation | Produced by a read-only capability; source and provenance recorded; no write to the inspected host. |
| Attribution rule | Declared at mission time; tied to the mission's JIR identity; auditable in the evidence chain. |
| Citation | The observation carries a signed hash-chain anchor so later phases can verify it was not tampered with. |

## Anti-detection capability gap

The "anti-detection capability gap" is the difference between the capabilities
a detection solution *claims* to observe and the capabilities it can actually
ground in independently verifiable evidence under contested-space constraints.

JOCKY's position, argued in `gap-proof.md`, is that the winning move in that
gap is **not** stealth — it is **defensible observability**: every capability
is read-only by construction, runs under the caller's own (non-privileged)
token, never mutates the inspected host, and signs every observation into a
hash chain anchored to the mission's JIR digest. There is therefore nothing
for a detection solution to "catch": there is nothing to hide and nothing that
changes the inspected state.

## Claimed properties (what Block 9's contract sheet will reference)

1. **Least-privilege by default.** All collectors report `privileges: "none"`.
2. **Read-only by construction.** The capability registry has no write
   capabilities; the never-grant set is enforced at compile time.
3. **Bound execution.** Loops and dispatch are bounded; no unbounded runtime.
4. **Tamper-evident evidence.** Per-record Ed25519 signature over a canonical
   hash chain anchored to the mission JIR digest.

## Non-goals

- Claiming an adversary cannot observe our tools (false; they can).
- Claiming detections of specific products are ineffective (out of scope, and
  attribution rules are product-neutral here).
- Claiming immunity "from all detections" (recommended wording: *read-only and
  attaining a posture of defensible observability*, not *undetectable*).