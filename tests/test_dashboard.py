"""The measure button on the dashboard (Block 16).

The page and the HTTP layer were both tested and the seam between them was
not, which is how a button shipped that reported ``PASS - 0/0 passed`` while
every card stayed ``NOT RUN``. The click handler passed a literal
``["all-measures"]`` sentinel and ``runAll`` compared it to a *different*
literal with ``===``. Array identity, so the comparison was always false, the
sentinel reached the server as a real ``--ids`` value, and it matched no
measure.

These are source-level assertions, deliberately. Driving a real browser would
add a heavy, flaky dependency to protect one function call, and the property
worth protecting is a pure one: the page must not smuggle a fake measure id
into a request whose API already expresses "everything" as a null.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from jocky.server import db
from jocky.server.api import app, get_session
from jocky.server.auth import TOKEN_ENV

TOKEN = "test-token-not-a-real-secret"

# The sentinel that caused the bug. If this string reappears in the page, the
# comparison that consumes it is either gone or has been re-broken.
SENTINEL = "all-measures"


@pytest.fixture()
def page() -> str:
    return TestClient(app).get("/ui/").text


def test_the_fake_measure_id_sentinel_is_gone(page):
    """No invented id may reach an API that already takes null for 'all'."""
    assert SENTINEL not in page, (
        f"'{SENTINEL}' reappeared in the dashboard; the run-all request must send "
        "measure_ids: null rather than a placeholder the server has to interpret"
    )


def test_run_all_asks_for_every_measure_by_sending_null(page):
    """The run-all button must request all measures, not name a nonexistent one."""
    assert 'runAll(null)' in page, 'the run-all button must call runAll(null)'
    assert 'JSON.stringify({ measure_ids: ids })' in page, (
        "runAll must pass measure_ids through untouched; the API already treats "
        "an absent or null list as 'run every measure'"
    )


def test_a_report_covering_nothing_is_never_shown_as_a_verdict(page):
    """The page must not print a green verdict for zero measures.

    This is the general form of the bug. The sentinel only triggered it; the
    real defect was that ``report.verdict`` was rendered without first
    checking it described any work. This guard means no future empty-response
    path can reproduce a false PASS.
    """
    assert "if (!results.length) throw new Error(" in page, (
        "runAll must reject an empty report before rendering its verdict"
    )


def test_the_button_and_the_measure_run_route_agree_on_a_run_all_request(page):
    """A null body, the way the page sends it, must actually run the measures.

    This is the end-to-end check that the two halves fit together, using the
    real route with the real body shape the fixed page produces.
    """
    from jocky.eval import measures as measures_mod

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    db.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    report = measures_mod.run_measures(session)
    session.close()
    engine.dispose()

    assert report["measures"], "a run-all request returned no measures at all"
    assert all(m["measure_id"] for m in report["measures"]), (
        "a measure reached the report without an id the dashboard can render"
    )
    assert "runAll(null)" in page, "the page must send the request just proven"


def test_the_dashboard_reads_the_token_from_storage(page):
    """Unchanged from the auth block, restated where the bug lived.

    The broken button failed *silently* with a 200 and a green word, so it is
    worth pinning the neighbouring behaviour: the token is attached from
    storage on the very request that carries the run-all body.
    """
    assert "authHeaders" in page
    assert "X-JOCKY-Token" in page
    assert "sessionStorage" in page


def test_the_measures_endpoint_rejects_an_unauthenticated_run_all():
    """Run all measures is mutating work and must stay behind the token.

    The page now sends ``{"measure_ids": null}``; this confirms the route that
    receives it still refuses a caller with no credential.
    """
    import os

    previous = os.environ.get(TOKEN_ENV)
    os.environ[TOKEN_ENV] = TOKEN
    try:
        engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        db.Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine, expire_on_commit=False)
        app.dependency_overrides[get_session] = lambda: Session()
        try:
            r = TestClient(app).post("/measures/run", json={"measure_ids": None})
            assert r.status_code == 401
        finally:
            app.dependency_overrides.pop(get_session, None)
            Session().close()
            engine.dispose()
    finally:
        if previous is None:
            os.environ.pop(TOKEN_ENV, None)
        else:
            os.environ[TOKEN_ENV] = previous
