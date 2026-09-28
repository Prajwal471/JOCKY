"""Independent-citation corroboration (Block 10).

``gap-proof.md`` argues that every JOCKY observation is reproducible without
JOCKY, by reading the same public OS API.  This module makes that argument
*measurable* on the live host: it counts the same objects through the
independent, native citation path (``tasklist`` / ``netstat -ano`` / ``sc
query``) and reports the delta against JOCKY's own counts.

A non-zero delta is not a failure — process and connection tables are live and
the two reads are not atomic.  The report is therefore a *delta* with an
explicit status, never a silent pass:

- ``MATCH``      the two independent reads agree exactly
- ``DELTA n``    the counts differ by ``n`` (recorded, with both numbers)
- ``UNAVAILABLE`` the citation path could not be run (non-Windows, sample mode,
                 or the tool was absent) — the capability is then uncorroborated
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass

_CITATION_TIMEOUT_S = 30


@dataclass(frozen=True)
class CitationResult:
    capability: str
    citation_path: str
    jocky_count: int | None
    native_count: int | None
    status: str
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "capability": self.capability,
            "citation_path": self.citation_path,
            "jocky_count": self.jocky_count,
            "native_count": self.native_count,
            "status": self.status,
            "detail": self.detail,
        }


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=_CITATION_TIMEOUT_S,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def _delta(jocky_count: int | None, native_count: int | None) -> str:
    if jocky_count is None or native_count is None:
        return "UNAVAILABLE"
    if jocky_count == native_count:
        return "MATCH"
    return f"DELTA {abs(jocky_count - native_count)}"


def cite_processes(jocky_count: int | None) -> CitationResult:
    """`tasklist /nh /fo csv` — the independent citation for process:list."""
    path = "tasklist /nh /fo csv"
    if not sys.platform.startswith("win") or jocky_count is None:
        return CitationResult("process:list", path, jocky_count, None, "UNAVAILABLE",
                              "requires a live Windows host")
    code, out = _run(["tasklist", "/nh", "/fo", "csv"])
    if code != 0:
        return CitationResult("process:list", path, jocky_count, None, "UNAVAILABLE",
                              f"tasklist exit {code}")
    native = len([ln for ln in out.splitlines() if ln.strip()])
    return CitationResult("process:list", path, jocky_count, native, _delta(jocky_count, native))


def cite_connections(jocky_count: int | None) -> CitationResult:
    """`netstat -ano` — the independent citation for network:analyze."""
    path = "netstat -ano"
    if not sys.platform.startswith("win") or jocky_count is None:
        return CitationResult("network:analyze", path, jocky_count, None, "UNAVAILABLE",
                              "requires a live Windows host")
    code, out = _run(["netstat", "-ano"])
    if code != 0:
        return CitationResult("network:analyze", path, jocky_count, None, "UNAVAILABLE",
                              f"netstat exit {code}")
    native = 0
    for line in out.splitlines():
        tok = line.strip().split()
        if tok and tok[0] in ("TCP", "UDP"):
            native += 1
    detail = ""
    if jocky_count is not None and jocky_count != native:
        detail = (
            "netstat reports IPv4 and IPv6 sockets; the JOCKY collector reads the "
            "IPv4 extended table, so a large native count is expected to exceed it"
        )
    return CitationResult("network:analyze", path, jocky_count, native,
                          _delta(jocky_count, native), detail)


def cite_services(jocky_count: int | None) -> CitationResult:
    """`sc query type= service state= all` — the citation for service:list."""
    path = "sc query type= service state= all"
    if not sys.platform.startswith("win") or jocky_count is None:
        return CitationResult("service:list", path, jocky_count, None, "UNAVAILABLE",
                              "requires a live Windows host")
    code, out = _run(["sc", "query", "type=", "service", "state=", "all"])
    if code != 0:
        return CitationResult("service:list", path, jocky_count, None, "UNAVAILABLE",
                              f"sc exit {code}")
    native = out.count("SERVICE_NAME:")
    return CitationResult("service:list", path, jocky_count, native, _delta(jocky_count, native))


__all__ = [
    "CitationResult",
    "cite_processes",
    "cite_connections",
    "cite_services",
]
