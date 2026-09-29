# Authentication (Block 13)

JOCKY's dispatch API has two routes that can cause work, and they are the only
two that require a credential:

| Route | Method | Credential |
| --- | --- | --- |
| `/missions` | `POST` | required |
| `/measures/run` | `POST` | required |
| everything else | any | not required |

Read routes stay open on purpose. The dashboard is a static page served by the
same process, and it polls `/health`, `/coverage`, `/measures`,
`/metrics/interop`, `/missions` and `/agents` with no credential. Locking those
would mean shipping a login page instead of a single shared secret, which this
block deliberately does not do.

## The scheme

One shared bearer token, presented in a custom header:

```http
X-JOCKY-Token: <value of JOCKY_API_TOKEN>
```

It is a single static secret. There are no accounts, no sessions, no expiry and
no per-caller identity. `jocky/server/auth.py` is the whole implementation:

```python
TOKEN_ENV = "JOCKY_API_TOKEN"
TOKEN_HEADER = "X-JOCKY-Token"
TOKEN_IDENTITY = "api-token-operator"

def expected_token() -> str: ...   # reads the env var at request time
def new_token() -> str: ...        # secrets.token_urlsafe(32), for operators
def require_token(x_jocky_token: str | None = Header(default=None)) -> dict: ...
```

`require_token` compares with `secrets.compare_digest`, so a caller cannot find
the token by timing the comparison, and it trims surrounding whitespace so a
token pasted with a trailing newline still works.

## Fail closed

Three cases are refused, and the third is the one that matters most:

1. **no header** - 401;
2. **wrong token** - 401, with a body byte-identical to case 1, so a caller
   cannot learn from the response whether the server is configured;
3. **`JOCKY_API_TOKEN` unset on the server** - 401, with a detail naming the
   variable. This is the fail-closed property. A deployment that loses its
   environment variable locks the mutating routes rather than exposing them, and
   the operator is told what to fix.

A missing, wrong, empty or whitespace-only credential is rejected, and so is a
token that is merely a prefix of the real one (which an accidental `startswith`
comparison would have accepted).

Rejections are `401`, not `403`, because the caller has not proved who they are
rather than proved that they may not act. The response carries
`WWW-Authenticate: X-JOCKY-Token`, which is what tells the dashboard where the
token belongs.

## Attribution

`POST /missions` records the mission `author` from the credential:

```json
{"source": "mission \"Demo\" { ... }", "author": "somebody-else"}
```

`author` is accepted for backwards compatibility and **ignored**. The stored
author is always `api-token-operator`, because the author of a mission should be
the identity that dispatched it, not a string the caller chose. `tests/test_auth.py`
asserts that a body-supplied author does not survive; `jocky.release` asserts the
same thing through the gate.

## Running it

```powershell
$env:JOCKY_API_TOKEN = python -c "from jocky.server.auth import new_token; print(new_token())"
python -m jocky.server.api
```

If the variable is not set, the server still starts and the dashboard still
loads, but the two mutating buttons report
`set an API token first` / `unauthenticated - set an API token above`. That is
the intended behaviour, not a broken install.

Using the API directly:

```powershell
$h = @{ "X-JOCKY-Token" = $env:JOCKY_API_TOKEN }
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/missions `
  -Headers $h -ContentType application/json `
  -Body (@{ source = Get-Content examples/attack_surface.jky -Raw } | ConvertTo-Json)
```

## In the dashboard

The API token field sits above the measures. The value is held in
`sessionStorage`, so it dies with the tab and is never written to disk, and it is
sent only to this origin's two POST routes. "Clear" removes it. If
`sessionStorage` is unavailable (private mode in some browsers) the token is held
in memory for the life of the page and the field still works.

## Rotation

There is no rotation protocol. To rotate: set `JOCKY_API_TOKEN` to a new value
and restart the server, which locks out every client holding the old one at
once. To keep a window where both work, run two servers, or accept the outage.
`expected_token()` reads the environment on **every** request rather than at
import, so a restart - or anything else that rewrites the variable - takes
effect without a code change; that also means the variable is read on the request
path, not cached in a module global.

## What this is not

- **Not a login system.** No route issues credentials; the operator sets one by
  hand in the environment.
- **Not multi-user.** Every authenticated caller is `api-token-operator`, so
  evidence attributes missions to the deployment rather than to a person. Paper
  §15 and §31 roles are still absent; see `docs/implementation-status.md`.
- **Not revocable per caller.** There is one secret and one way to change it.
- **Not rate-limited, not audited, not TLS.** Run it on loopback or behind a
  reverse proxy that terminates TLS. The token is a bearer secret: anyone holding
  it can dispatch missions.
- **Not a capability grant.** Passing this gate earns no Jocky capability. A
  mission still has to declare `@requires(...)` for every call it makes, and the
  registry still refuses the never-grant set. Authentication decides *who is
  asking*; capabilities decide *what the code may do*.

## Evidence

- `tests/test_auth.py` - missing/wrong/empty/whitespace/prefix tokens refused;
  unset server token fails closed; missing and wrong tokens indistinguishable;
  author derived from the credential; read routes and dashboard still open.
- `jocky/release.py::gate_auth` - runs on every cut check and fails the cut if
  either mutating route admits an unauthenticated caller, including in the unset
  configuration, or if a valid token is refused.
- `tests/test_api.py`, `tests/test_measures.py` - fixtures configure a token and
  present it, so a future test cannot quietly start exercising an open route.
