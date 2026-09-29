"""API authentication for the dispatch server (Block 13).

A single shared bearer token guards the routes that can *cause* work:
``POST /missions`` and ``POST /measures/run``. The read routes stay open so the
dashboard and the demo runbook keep working without a credential.

Three properties matter more than the mechanism:

**It fails closed.** An unset ``JOCKY_API_TOKEN`` rejects every mutating
request rather than allowing them. A deployment that forgets to configure a
token is locked, not wide open -- the failure mode of "no token means no auth"
is a server that silently reopens the hole the moment an env var is dropped. The
rejection names the missing variable, because the operator needs to know which
one it was; a missing or wrong *caller* token gets a generic body, because
telling those two apart would let a caller probe the configuration.

**The token is the identity.** ``author`` on a mission is derived from the
presented token, not from a field in the request body, so attribution cannot be
spoofed by a caller who found the port open.

**The comparison does not leak.** ``secrets.compare_digest`` is constant-time
in the length of its input, so a caller cannot recover the token by measuring
how long a rejection takes.

This is deliberately *not* role-based access control. There is one credential,
it is not per-operator, and it cannot express paper §31's operator roles. See
``docs/authentication.md``.
"""

from __future__ import annotations

import os
import secrets
from typing import Any

from fastapi import Header, HTTPException, status

#: Environment variable holding the shared token.
TOKEN_ENV = "JOCKY_API_TOKEN"

#: Header the token is presented in.
TOKEN_HEADER = "X-JOCKY-Token"

#: Identity recorded when a caller presents a valid token.
TOKEN_IDENTITY = "api-token-operator"

#: Body of the 401 for a missing or wrong token, deliberately identical in
#: both cases: a caller must not be able to tell "no token sent" from "wrong
#: token sent" and use the difference to probe the configuration.
#:
#: The *unset server* case does name the variable, and that is a deliberate
#: exception. The information it reveals -- that this deployment has no token --
#: is local deployment state that a 401 already implies (an attacker learns
#: nothing they could not see from the status code), and naming the variable is
#: the difference between an operator fixing a missing env var in thirty seconds
#: and filing a bug.
_UNAUTHENTICATED = "unauthenticated: a valid API token is required for this route"

#: 401 rather than 403, because the caller has not proved who they are yet.
#: The challenge names the header to retry with, which is what tells a client
#: (and the dashboard) where the token belongs.
_AUTH_CHALLENGE = {"WWW-Authenticate": TOKEN_HEADER}


def expected_token() -> str:
    """The configured token, or ``""`` when the server has none."""
    return os.environ.get(TOKEN_ENV, "").strip()


def new_token(nbytes: int = 32) -> str:
    """Mint a token. Used by the demo bootstrap and the runbook."""
    return secrets.token_urlsafe(nbytes)


def require_token(
    x_jocky_token: str | None = Header(default=None, alias=TOKEN_HEADER),
) -> dict[str, Any]:
    """FastAPI dependency: reject the request unless the token matches.

    Returns the authenticated principal so the route can attribute work to it.
    """
    configured = expected_token()
    presented = (x_jocky_token or "").strip()

    if not configured:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"unauthenticated: {TOKEN_ENV} is not set on this server",
            headers=_AUTH_CHALLENGE,
        )
    if not presented or not secrets.compare_digest(presented, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_UNAUTHENTICATED,
            headers=_AUTH_CHALLENGE,
        )
    return {"operator": TOKEN_IDENTITY, "authenticated": True}


__all__ = [
    "TOKEN_ENV",
    "TOKEN_HEADER",
    "TOKEN_IDENTITY",
    "expected_token",
    "new_token",
    "require_token",
]
