"""Central configuration for JOCKY.

Single source of truth for the runtime database URL and paths.
Tests override ``DATABASE_URL`` with an in-memory SQLite URL.
"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

KEYS_DIR = PROJECT_ROOT / "jocky" / "keys"

DEFAULT_DATABASE_URL = "postgresql+psycopg://jocky:demo@localhost:5432/jocky"

DATABASE_URL = os.environ.get("JOCKY_DATABASE_URL", DEFAULT_DATABASE_URL)

IS_TESTING = DATABASE_URL.startswith("sqlite")

DEMO_TOLERANCE = float(os.environ.get("JOCKY_DEMO_TOLERANCE", "1e-6"))

MAX_RECURSION_DEPTH = int(os.environ.get("JOCKY_MAX_RECURSION", "64"))

WHILE_ITERATION_CAP = int(os.environ.get("JOCKY_WHILE_CAP", "1_000_000"))

LLVM_PASSES = ["opt -O0", "opt -O1", "opt -O2"]