"""Central configuration for JOCKY.

Single source of truth for the runtime database URL and paths.
Tests override ``DATABASE_URL`` with an in-memory SQLite URL.
"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def package_version() -> str:
    """The project's version, read from ``pyproject.toml``.

    Single-sourced on purpose. This string used to be hardcoded in three places
    (``pyproject.toml``, the FastAPI app, and ``/health``), which is how the
    runbook ended up quoting a version the server no longer reported. Reading
    the manifest means there is one place to change, and
    ``test_reported_version_matches_the_package_version`` fails if they ever
    disagree again.

    ``pyproject.toml`` is the source of truth rather than installed package
    metadata, because that is what ``jocky.release``'s ``version`` gate reads --
    and a source checkout installed with ``pip install -e .`` keeps stale
    metadata until it is reinstalled, which would report the *previous* version
    after a bump. Installed metadata is the fallback for a deployment where the
    manifest is not shipped; ``"0.0.0+unknown"`` is the last resort, because an
    honest placeholder beats a stale literal.
    """
    pyproject = PROJECT_ROOT / "pyproject.toml"
    if pyproject.is_file():
        try:
            import tomllib

            return str(tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"])
        except Exception:  # noqa: BLE001 - a broken manifest must not stop the server
            pass
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("jocky")
        except PackageNotFoundError:
            pass
    except ImportError:  # pragma: no cover - importlib.metadata is stdlib on 3.8+
        pass
    return "0.0.0+unknown"


#: Distribution version of the package. **Not** the language version: the JIR
#: document version lives in :data:`jocky.dsl.jir.JIR_VERSION` and changes
#: independently, because bumping it re-digests every pinned mission.
VERSION = package_version()

KEYS_DIR = PROJECT_ROOT / "jocky" / "keys"

DEFAULT_DATABASE_URL = "postgresql+psycopg://jocky:demo@localhost:5432/jocky"

DATABASE_URL = os.environ.get("JOCKY_DATABASE_URL", DEFAULT_DATABASE_URL)

IS_TESTING = DATABASE_URL.startswith("sqlite")

# Set JOCKY_SAMPLE_DATA=1 for deterministic synthetic rows (tests). The demo
# and production runs use the live Windows harvesters (Block 4 seam).
SAMPLE_DATA = os.environ.get("JOCKY_SAMPLE_DATA", "").lower() in {"1", "true", "yes", "on"}

DEMO_TOLERANCE = float(os.environ.get("JOCKY_DEMO_TOLERANCE", "1e-6"))

MAX_RECURSION_DEPTH = int(os.environ.get("JOCKY_MAX_RECURSION", "64"))

WHILE_ITERATION_CAP = int(os.environ.get("JOCKY_WHILE_CAP", "1_000_000"))

LLVM_PASSES = ["opt -O0", "opt -O1", "opt -O2"]