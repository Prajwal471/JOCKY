"""Pytest bootstrap: keep the suite deterministic with synthetic collector rows.

Real Windows harvesters are exercised by ``tests/test_harvesters.py``, which
reads them directly and is not affected by this flag.

The suite is also hermetic with respect to the evaluation environment. An
operator who has ``JOCKY_EVAL_DATABASE_URL`` exported -- the normal state after
running the harness against a real database -- would otherwise have the tests
measure *that* database instead of an isolated one, and a failure in
``test_matrix_interop_all_ok`` would say nothing about the code. These variables
steer ``clean_env``; the tests pass their own database and key directories, so
clearing them cannot change what is under test.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("JOCKY_SAMPLE_DATA", "1")

#: Removed before collection so an operator's shell cannot change what a test
#: measures. ``setdefault`` above deliberately does *not* apply to these.
for _leaked in ("JOCKY_EVAL_DATABASE_URL", "JOCKY_EVAL_KEYS_DIR"):
    os.environ.pop(_leaked, None)
del _leaked


@pytest.fixture()
def session():
    """In-memory SQLite session sharing a single pooled connection.

    StaticPool + check_same_thread=False keeps the connection alive across the
    commits dispatch performs (file-backed SQLite would be torn down on
    Windows and the mission would trip WinError 32).
    """
    from jocky.server import db

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
        db.Base.metadata.drop_all(engine)
        engine.dispose()