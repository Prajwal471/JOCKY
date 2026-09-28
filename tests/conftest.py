"""Pytest bootstrap: keep the suite deterministic with synthetic collector rows.

Real Windows harvesters are exercised by ``tests/test_harvesters.py``, which
reads them directly and is not affected by this flag.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("JOCKY_SAMPLE_DATA", "1")


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