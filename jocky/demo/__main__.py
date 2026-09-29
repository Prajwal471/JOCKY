"""``python -m jocky.demo`` -> migrate, seed, and serve the dashboard."""

from __future__ import annotations

from jocky.demo.bootstrap import main

if __name__ == "__main__":
    raise SystemExit(main())
