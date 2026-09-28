"""Pytest bootstrap: keep the suite deterministic with synthetic collector rows.

Real Windows harvesters are exercised by ``tests/test_harvesters.py``, which
reads them directly and is not affected by this flag.
"""

from __future__ import annotations

import os

os.environ.setdefault("JOCKY_SAMPLE_DATA", "1")