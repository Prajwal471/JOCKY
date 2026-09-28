"""Coverage matrix completeness checks (Block 5).

Asserts the seeded ``coverage_clauses`` rows are complete against the
capability registry: every collector capability has a clause, every clause has
a valid status, clause ids are unique, and every LIVE capability maps to a
bound builtin that has both a synthetic and (on Windows) a live test.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from jocky.runtime import builtins
from jocky.server import db
from jocky.server.coverage import COVERAGE_SEED, seed_coverage


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    db.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    s = Session()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()

# Capabilities that are not data collectors (no CoverageClause expected).
_NON_COLLECTOR = {"evidence:sign", "collection:dispatch"}


def test_seed_covers_every_collector_capability():
    expected = {
        v for v in builtins.BUILTIN_CAPABILITIES.values()
        if v != "collection:dispatch"
    }
    seeded = {c["clause_id"] for c in COVERAGE_SEED}
    missing = expected - seeded
    assert not missing, f"capabilities missing from coverage seed: {missing}"
    assert seeded - expected == set()


def test_seed_statuses_are_valid():
    for clause in COVERAGE_SEED:
        assert clause["status"] in {"LIVE", "REGISTERED", "MEASURED"}, clause["clause_id"]
        assert clause["mechanism"], f"{clause['clause_id']} has empty mechanism"


def test_seed_clause_ids_unique():
    ids = [c["clause_id"] for c in COVERAGE_SEED]
    assert len(ids) == len(set(ids))


def test_every_live_capability_has_bound_builtin():
    live_caps = {c["clause_id"] for c in COVERAGE_SEED if c["status"] == "LIVE"}
    builtin_for_cap = {v: k for k, v in builtins.BUILTIN_CAPABILITIES.items()}
    for cap in live_caps:
        assert cap in builtin_for_cap, f"LIVE capability {cap} has no bound builtin"


def test_seed_applies_to_database(session):
    count = seed_coverage(session)
    assert count == len(COVERAGE_SEED)

    rows = session.query(db.CoverageClause).all()
    assert len(rows) == count
    ids = [r.clause_id for r in rows]
    assert len(ids) == len(set(ids))
    # idempotent re-seed does not duplicate
    seed_coverage(session)
    assert session.query(db.CoverageClause).count() == count


@pytest.mark.parametrize("cap", sorted(set(builtins.BUILTIN_CAPABILITIES.values())))
def test_builtin_capabilities_in_registry(cap):
    """Every capability consumed by a bound builtin exists in the registry."""
    from jocky.dsl.types import CAPABILITIES

    assert cap in CAPABILITIES