"""Authentication on the mutating routes (Block 13).

The property under test is not "a token is checked" but the failure modes around
it, because those are what a gate on a security boundary actually needs:

* an **unset** server token rejects rather than admits, so dropping an env var
  cannot silently reopen the endpoint;
* a **wrong** token is rejected with the same 401 body as a missing one, so a
  caller cannot probe how the server is configured;
* the **rejection is 401, not 403**, and carries a challenge header;
* ``author`` comes from the credential, so a caller cannot attribute a mission
  to somebody else;
* **read routes stay open**, which is what keeps the dashboard working.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from jocky.server import db
from jocky.server.api import app, get_session
from jocky.server.auth import (
    TOKEN_ENV,
    TOKEN_HEADER,
    TOKEN_IDENTITY,
    expected_token,
    new_token,
    require_token,
)

TOKEN = "test-token-not-a-real-secret"

MISSION = '''
@requires(process:list)
mission "AuthProbe" {
  let p = collect_processes();
  emit p |count;
}
'''

MUTATING_ROUTES = ("/missions", "/measures/run")


@pytest.fixture(autouse=True)
def _token_env(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    return TOKEN


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    db.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)

    def override():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_session] = override
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _post(client: TestClient, url: str, token: str | None, **body):
    headers = {TOKEN_HEADER: token} if token is not None else {}
    return client.post(url, json=body, headers=headers)


# ----------------------------------------------------------- the refusals


@pytest.mark.parametrize("url", MUTATING_ROUTES)
def test_no_token_is_rejected(client, url):
    r = _post(client, url, None, source=MISSION)
    assert r.status_code == 401
    assert TOKEN_HEADER in r.headers.get("www-authenticate", "")


@pytest.mark.parametrize("url", MUTATING_ROUTES)
def test_wrong_token_is_rejected(client, url):
    r = _post(client, url, "not-the-token", source=MISSION)
    assert r.status_code == 401


def test_empty_and_whitespace_tokens_are_rejected(client):
    for bad in ("", "   "):
        r = _post(client, "/missions", bad, source=MISSION)
        assert r.status_code == 401, f"token {bad!r} was accepted"


def test_a_token_that_is_a_prefix_of_the_real_one_is_rejected(client):
    """Guards against an accidental ``startswith`` comparison."""
    r = _post(client, "/missions", TOKEN[:-1], source=MISSION)
    assert r.status_code == 401


def test_missing_and_wrong_tokens_are_indistinguishable(client, monkeypatch):
    """A caller must not learn whether the server has a token configured."""
    missing = _post(client, "/missions", None, source=MISSION)
    wrong = _post(client, "/missions", "nope", source=MISSION)
    assert missing.status_code == wrong.status_code == 401
    assert missing.json()["detail"] == wrong.json()["detail"]


def test_unset_server_token_fails_closed(client, monkeypatch):
    """The important one: forgetting to configure a token must lock, not open."""
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    assert expected_token() == ""
    r = _post(client, "/missions", TOKEN, source=MISSION)
    assert r.status_code == 401
    assert TOKEN_ENV in r.json()["detail"]


def test_unset_server_token_also_rejects_a_blank_token(client, monkeypatch):
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    r = _post(client, "/missions", "", source=MISSION)
    assert r.status_code == 401


# -------------------------------------------------------- the happy path


def test_valid_token_is_accepted(client):
    r = _post(client, "/missions", TOKEN, source=MISSION)
    assert r.status_code == 200, r.text
    assert r.json()["evidence_count"] >= 1


def test_author_comes_from_the_token_not_the_body(client):
    r = _post(client, "/missions", TOKEN, source=MISSION, author="someone-else")
    assert r.status_code == 200
    missions = client.get("/missions").json()
    assert missions[0]["author"] == TOKEN_IDENTITY
    assert missions[0]["author"] != "someone-else"


def test_dependencies_do_not_stack_after_success(client):
    """A second valid call must not trip state left by the first."""
    for _ in range(3):
        assert _post(client, "/missions", TOKEN, source=MISSION).status_code == 200
    assert client.get("/missions").json() != []


# ------------------------------------------------------------ read routes

READ_ROUTES = (
    "/health",
    "/coverage",
    "/metrics/interop",
    "/measures",
    "/missions",
    "/agents",
    "/evidence",
)


@pytest.mark.parametrize("url", READ_ROUTES)
def test_read_routes_stay_open(client, url):
    """The dashboard reads these with no credential, so they must not lock."""
    r = client.get(url)
    assert r.status_code == 200, f"{url} -> {r.status_code}"


def test_dashboard_is_still_public(client):
    r = client.get("/ui/")
    assert r.status_code == 200
    assert TOKEN_HEADER in r.text


def test_dashboard_sends_the_token_header(client):
    """The page must present the token, or the demo buttons cannot work."""
    body = client.get("/ui/").text
    assert "authHeaders" in body
    assert TOKEN_HEADER in body
    assert "sessionStorage" in body


# ------------------------------------------------------- the unit surface


def test_require_token_returns_the_principal(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    assert require_token(TOKEN)["operator"] == TOKEN_IDENTITY


def test_require_token_ignores_surrounding_whitespace(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    assert require_token(f"  {TOKEN}  ")["operator"] == TOKEN_IDENTITY


def test_new_token_is_unguessable_and_distinct():
    a, b = new_token(), new_token()
    assert a != b
    assert len(a) >= 32


def test_token_is_never_echoed_by_the_401(client):
    r = _post(client, "/missions", TOKEN[:-1], source=MISSION)
    assert TOKEN[:-1] not in r.text
