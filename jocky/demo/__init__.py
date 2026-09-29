"""Demo environment bootstrap for JOCKY (Block 11).

``python -m jocky.demo`` brings up everything a judge needs to see the claimed
properties fail closed: a migrated database, a seeded coverage matrix, an agent
key, and the dashboard. It is deliberately the *only* supported way to start the
demo, so a fresh checkout has one command between clone and first page.
"""

from jocky.demo.bootstrap import main

__all__ = ["main"]
