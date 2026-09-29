"""Active measures + dashboard/demo surface (Block 11).

Two things are worth testing here beyond "does it return 200":

* that a measure **fails** when JOCKY is broken (a measure that cannot fail is
  worthless), and
* that running the measures leaves the caller's database and agent key exactly
  as they were.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from jocky import config
from jocky.eval import measures as measures_mod
from jocky.eval.harness import clean_env
from jocky.server import db, dispatch
from jocky.server.api import app, get_session
from jocky.server.auth import TOKEN_ENV, TOKEN_HEADER

REPO_KEY = config.PROJECT_ROOT / "jocky" / "keys" / "agent_ed25519.pem"

#: Block 13 protects POST /measures/run, so the API fixture must present one.
TEST_TOKEN = "test-token-not-a-real-secret"


@pytest.fixture(autouse=True)
def _api_token(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TEST_TOKEN)
    return TEST_TOKEN


@pytest.fixture()
def measure_session():
    with clean_env() as session:
        yield session


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
            c.headers.update({TOKEN_HEADER: TEST_TOKEN})
            yield c
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _result(report, measure_id):
    for m in report["measures"]:
        if m["measure_id"] == measure_id:
            return m
    raise AssertionError(f"{measure_id} missing from report")


def _failed_observations(result):
    return [o["observation"] for o in result["observations"] if not o["holds"]]


# ------------------------------------------------------------- the measures

def test_every_measure_passes(measure_session):
    report = measures_mod.run_measures(measure_session)
    assert report["verdict"] == "PASS", _failed_observations(
        report["measures"][0]
    )
    assert [m["measure_id"] for m in report["measures"]] == [m.id for m in measures_mod.MEASURES]
    for m in report["measures"]:
        assert m["verdict"] == "PASS", (m["measure_id"], _failed_observations(m))
        # A measure with no observations would pass trivially.
        assert len(m["observations"]) >= 4


def test_no_escalation_refuses_undeclared_call(measure_session):
    result = _result(
        measures_mod.run_measures(measure_session, ["no-escalation"]), "no-escalation"
    )
    assert result["verdict"] == "PASS"
    assert "not declared by this mission" in result["detail"]
    assert "process:list" in result["detail"]


def test_never_grant_rejects_write_capabilities(measure_session):
    result = _result(
        measures_mod.run_measures(measure_session, ["never-grant"]), "never-grant"
    )
    assert result["verdict"] == "PASS"
    assert "never-grant set" in result["detail"]
    assert "unknown capability" in result["notes"]


def test_bounds_stop_the_runaway_mission(measure_session):
    result = _result(
        measures_mod.run_measures(measure_session, ["bounds.enforced"]),
        "bounds.enforced",
    )
    assert result["verdict"] == "PASS"
    assert "step budget exhausted" in result["detail"]
    # steps must exceed the cap: the cap stopped it, not an early exit
    assert "steps=2001 cap=2000" in result["notes"]


def test_tamper_is_caught_at_every_forgery_layer(measure_session):
    result = _result(
        measures_mod.run_measures(measure_session, ["tamper-evident"]), "tamper-evident"
    )
    assert result["verdict"] == "PASS", _failed_observations(result)
    labels = " ".join(o["observation"] for o in result["observations"])
    for layer in ("layer 1", "layer 2", "layer 3", "layer 4"):
        assert layer in labels
    assert "verifies again once restored" in labels


def test_jir_drift_is_refused(measure_session):
    result = _result(
        measures_mod.run_measures(measure_session, ["jir-pinned"]), "jir-pinned"
    )
    assert result["verdict"] == "PASS"
    assert "JIR drift" in result["detail"]


# ------------------------------------------------- a measure must be able to fail

def test_measure_fails_when_jocky_is_broken(measure_session, monkeypatch):
    """If every mission errors, no-escalation must FAIL, not PASS.

    Guards the exact failure mode from Block 10, where a mission that never ran
    satisfied a trivial expectation and scored PASS.
    """
    def broken(*args, **kwargs):
        raise RuntimeError("mission 'x' failed: interpreter exploded")

    monkeypatch.setattr(dispatch, "run_and_persist", broken)
    result = _result(
        measures_mod.run_measures(measure_session, ["no-escalation"]), "no-escalation"
    )
    assert result["verdict"] == "FAIL"
    assert _failed_observations(result)


def test_broken_measure_is_an_error_not_a_pass(measure_session):
    def explode(session):
        raise ValueError("kaboom")

    broken = measures_mod.Measure(
        id="broken",
        name="broken",
        property="test",
        claim="c",
        expects="e",
        does_not_prove="d",
        run=explode,
    )
    result = measures_mod.run_measure(measure_session, broken)
    assert result["verdict"] == "ERROR"
    assert "kaboom" in result["detail"]


def test_failing_observation_yields_fail(measure_session):
    def half(session):
        return measures_mod._verdict(
            measures_mod.MEASURE_BOUNDED, "detail", [("ok", True), ("not ok", False)]
        )

    partial = measures_mod.Measure(
        id="partial",
        name="partial",
        property="test",
        claim="c",
        expects="e",
        does_not_prove="d",
        run=half,
    )
    assert measures_mod.run_measure(measure_session, partial)["verdict"] == "FAIL"


def test_unknown_measure_id_is_rejected(measure_session):
    with pytest.raises(ValueError, match="unknown measure"):
        measures_mod.run_measures(measure_session, ["not-a-measure"])


# ------------------------------------------------------------- isolation

def test_measures_do_not_touch_the_real_key_or_database(tmp_path):
    """A measure must not be able to damage the state it is measuring."""
    before_keys_dir = config.KEYS_DIR
    before_signer = dispatch._agent_signer
    key_existed = REPO_KEY.exists()
    key_bytes = REPO_KEY.read_bytes() if key_existed else None

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    db.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    outer = Session()
    outer.add(db.Mission(name="outer", source_text="x", jir={}, jir_sha256="a" * 64))
    outer.commit()
    outer_missions = outer.query(db.Mission).count()

    with clean_env(keys_dir=tmp_path) as session:
        report = measures_mod.run_measures(session)
        session.commit()
    assert report["verdict"] == "PASS"

    # the eval key directory got its own key, distinct from the repo's
    eval_key = tmp_path / "agent_ed25519.pem"
    assert eval_key.exists()
    assert eval_key.read_bytes() != key_bytes

    # the caller's globals and data are untouched
    assert config.KEYS_DIR == before_keys_dir
    assert dispatch._agent_signer is before_signer
    assert REPO_KEY.exists() == key_existed
    if key_existed:
        assert REPO_KEY.read_bytes() == key_bytes
    assert outer.query(db.Mission).count() == outer_missions

    outer.close()
    engine.dispose()


def test_repository_key_is_not_created_by_a_measure_run(tmp_path):
    """If the repo key does not exist yet, a measure run must not create it."""
    if REPO_KEY.exists():
        pytest.skip("repository key already exists; nothing to prove")
    with clean_env(keys_dir=tmp_path) as session:
        measures_mod.run_measures(session)
    assert not REPO_KEY.exists()


def test_measures_pass_against_a_durable_database(tmp_path):
    """A measure run must not be broken by a database that already has data.

    Regression found against PostgreSQL, the documented deployment target. The
    ``tamper-evident`` measure re-read its mission by JIR digest with
    ``.first()``. On a durable database the same mission source is already
    present from an earlier run, so that lookup returned the *older* mission --
    whose records were signed by a different agent key. Two of its observations
    then failed ("record verifies before tampering", "record verifies again
    once restored") and the measure reported FAIL on a chain that was in fact
    intact. In-memory SQLite hid it because every run started empty.

    A file-backed SQLite database is durable the same way and needs no server.
    """
    url = f"sqlite:///{tmp_path / 'durable.db'}"
    with clean_env(url, keys_dir=tmp_path / "keys-a") as session:
        first = measures_mod.run_measures(session)
        session.commit()
    with clean_env(url, keys_dir=tmp_path / "keys-b") as session:
        second = measures_mod.run_measures(session)
        session.commit()

    for label, report in (("first", first), ("second", second)):
        failed = [m["measure_id"] for m in report["measures"] if m["verdict"] != "PASS"]
        assert report["verdict"] == "PASS", f"{label} run failed: {failed}"
    tamper = [m for m in second["measures"] if m["measure_id"] == "tamper-evident"][0]
    broken = [o["observation"] for o in tamper["observations"] if not o["holds"]]
    assert not broken, broken
    assert (tmp_path / "keys-a" / "agent_ed25519.pem").read_bytes() != (
        tmp_path / "keys-b" / "agent_ed25519.pem"
    ).read_bytes(), "precondition: the two runs used different keys"


# ------------------------------------------------------------- API surface

def test_measures_endpoint_lists_the_catalog(client):
    r = client.get("/measures")
    assert r.status_code == 200
    body = r.json()
    assert len(body["measures"]) == len(measures_mod.MEASURES)
    for m in body["measures"]:
        assert m["claim"] and m["expects"] and m["does_not_prove"]


def test_coverage_endpoint_reports_clauses_and_properties(client):
    r = client.get("/coverage")
    assert r.status_code == 200
    body = r.json()
    assert len(body["clauses"]) == 11
    assert sum(body["counts"].values()) == 11
    prop_ids = {p["property"] for p in body["properties"]}
    assert "1. least-privilege by default" in prop_ids
    assert "4. tamper-evident evidence" in prop_ids


def test_ui_is_served(client):
    r = client.get("/ui/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    body = r.text
    # no external assets: the demo must work air-gapped
    assert "http://" not in body.replace("http://www.w3.org", "")
    assert "cdn" not in body.lower()


def test_root_redirects_to_dashboard(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (307, 302)
    assert r.headers["location"] == "/ui/"


def test_measure_run_endpoint_executes_in_a_subprocess(client):
    r = client.post("/measures/run", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] == "PASS"
    assert len(body["measures"]) == len(measures_mod.MEASURES)


def test_measure_run_endpoint_rejects_unknown_id(client):
    r = client.post("/measures/run", json={"measure_ids": ["nope"]})
    assert r.status_code == 500
    assert "unknown measure" in r.json()["detail"]


# ------------------------------------------------------------------- demo

def test_redact_hides_the_password():
    from jocky.demo.bootstrap import redact

    url = "postgresql+psycopg://jocky:supersecret@localhost:5432/jocky"
    out = redact(url)
    assert "supersecret" not in out
    assert "jocky:***@localhost:5432/jocky" in out


def test_redact_leaves_passwordless_urls_alone():
    from jocky.demo.bootstrap import redact

    assert redact("sqlite:///./demo.db") == "sqlite:///./demo.db"


def test_check_database_fails_fast_on_an_unusable_url():
    from jocky.demo.bootstrap import check_database

    code = check_database("sqlite:///" + str(Path("no/such/dir/demo.db")))
    assert code == 1


def test_demo_main_prepares_without_serving(tmp_path, monkeypatch):
    from jocky.demo import bootstrap

    db_file = tmp_path / "demo.db"
    url = f"sqlite:///{db_file.as_posix()}"
    # DATABASE_URL is resolved at import (as it is everywhere else in JOCKY), so
    # the demo reads the already-bound value rather than re-reading the env.
    monkeypatch.setattr(config, "DATABASE_URL", url)
    monkeypatch.setattr(bootstrap, "REPO_ROOT", config.PROJECT_ROOT)

    assert bootstrap.main(["--no-serve"]) == 0
    assert db_file.exists()


def _banner(monkeypatch, capsys, *, token):
    from jocky.demo import bootstrap

    if token is None:
        monkeypatch.delenv(TOKEN_ENV, raising=False)
    else:
        monkeypatch.setenv(TOKEN_ENV, token)
    import argparse

    bootstrap.print_banner(argparse.Namespace(host="127.0.0.1", port=8000))
    return capsys.readouterr().out


def test_banner_says_the_mutating_routes_are_locked_without_a_token(monkeypatch, capsys):
    """An unset token must be announced, not discovered by a failed button.

    The demo fails closed, so an operator who forgets ``JOCKY_API_TOKEN`` gets a
    dashboard that loads and then refuses. Without this line the first symptom is
    a 401 in the browser, which reads like a bug rather than a missing variable.
    """
    out = _banner(monkeypatch, capsys, token=None)
    assert "api token  NOT set" in out
    assert "locked (401)" in out
    # The remedy has to be copy-pasteable, and has to name the variable.
    assert TOKEN_ENV in out
    assert "new_token()" in out
    assert "PowerShell" in out and "export" in out


def test_banner_does_not_print_the_token_value(monkeypatch, capsys):
    """The banner may say a token is set. It must never echo the secret."""
    out = _banner(monkeypatch, capsys, token="super-secret-value")
    assert "api token  set" in out
    assert TOKEN_ENV in out
    assert "super-secret-value" not in out


def test_banner_reports_the_effective_mode(monkeypatch, capsys):
    """The flag is not the truth; ``JOCKY_SAMPLE_DATA`` binds the collectors."""
    from jocky import config

    monkeypatch.setattr(config, "SAMPLE_DATA", False, raising=False)
    monkeypatch.setenv(TOKEN_ENV, "t")
    import argparse

    from jocky.demo import bootstrap

    bootstrap.print_banner(argparse.Namespace(host="127.0.0.1", port=8000))
    assert "mode=live" in capsys.readouterr().out
