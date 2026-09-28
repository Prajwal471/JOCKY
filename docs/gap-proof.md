# Capability-Gap Proof — contested space

This is the *proof* half of Block 5: it argues, per collector capability, that
the observation JOCKY makes is (a) achievable under the least-privilege token,
(b) read-only by construction, and (c) the only *grounded* claim a detection
solution could make about that signal taps the same kernel/Config-space API —
there is no extra "anything to detect" surface JOCKY adds.

## Method

For each capability in `COVERAGE_SEED` (seeded into `coverage_clauses`):

1. **Mechanism** — the exact OS API the collector uses.
2. **Token** — identity under which it runs (`privileges: "none"`).
3. **Dirtiness** — does the observation change the inspected host? (must be no)
4. **Independent citation path** — how a reviewer can reproduce the observation
   without JOCKY (same API surface), so the finding is not tool-dependent.

## Matrix

| Capability | Mechanism | Token | Dirtiness | Independent citation path |
| --- | --- | --- | --- | --- |
| `process:list` | Toolhelp32 snapshot | none | none | `tasklist` / Get-Process |
| `network:analyze` | GetExtendedTcpTable/GetExtendedUdpTable + PID union | none | none | `netstat -ano` |
| `service:list` | SCM EnumServicesStatusExW + QueryServiceConfigW | none | none | `sc query` / `Get-Service` |
| `driver:list` | SCM driver enum + Authenticode signature state | none | none | `driverquery` / `sc query type= driver` |
| `persistence:list` | winreg Run/RunOnce + Startup folders read | none | none | `reg query` / Startup dir listing |
| `event:read` | wevtutil XML on Application+System (unelevated) | none | none | `wevtutil qe` |
| `lotl:scan` | FS existence probe for dual-use binaries | none | none | `Test-Path` on same paths |
| `evidence:sign` | Ed25519 sign of canonical record hash | none | n/a | verify with agent public key |

## The gap argument

A detection solution that wants to defend the *same signal space* must observe
the same APIs JOCKY reads. Those APIs are read-only OS interfaces available to
an unelevated caller; that is — by construction — the entire surface. JOCKY
adds no new writable acts, no persistence, and no mutation. The only
"anti-detection" property JOCKY asserts is therefore **defensible
observability** (every observation is signed, cited via the same public API,
and anchored to the mission JIR digest): an adversary cannot validate any
JOCKY finding is tampered with, and a defender cannot claim JOCKY changed the
host, because the cited observation path is independent and read-only.

## Empirical probes (Block 8 extends this)

- `probe_registry` — reads a specified hive key read-only.
- `probe_service` — queries SCM config for a named service read-only.
- `probe_identity` — reports the effective principal/domain without elevation.

Each probe emits a `finding_type: "probe"` record into the evidence chain,
with the same `privileges: "none"` provenance, so the matrix rows above become
machine-checkable.

## Limits (blocking honesty)

- Least-privilege observation is *not* invisibility; it is *defensibility*.
- The matrix measures capability presence, not adversary sophistication.
- All blocks, including `evidence:sign`, are exercised only at the mission's
  declared capability set.