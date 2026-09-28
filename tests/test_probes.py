"""Self-assertive probe tests (Block 8).

The probe builtins return findings under their read-only capabilities.  The
live variants are exercised on Windows (guarded); the sample variants are
deterministic and run everywhere via the JOCKY_SAMPLE_DATA seam.
"""

from __future__ import annotations

import sys

import pytest

from jocky.runtime import builtins

NEEDS_WINDOWS = pytest.mark.skipif(
    sys.platform != "win32", reason="live probe collectors are Windows-only"
)

PROBE_MISSION = '''
@requires(identity:probe, registry:query, service:probe)
mission "ProbeMission" {
  let who = probe_identity();
  emit who;

  let reg = probe_registry("HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run");
  emit reg |count;

  let svc = probe_service("wuauserv");
  emit svc;
}
'''


def test_probe_identity_capability_bound():
    assert builtins.BUILTIN_CAPABILITIES["probe_identity"] == "identity:probe"


def test_probe_identity_sample():
    rows = builtins.probe_identity()
    assert len(rows) == 1
    assert rows[0]["privileges"] == "none"
    assert rows[0]["user"] == "lab-operator"
    assert set(rows[0]) == {"user", "domain", "sid", "privileges", "hostname"}


def test_probe_registry_sample():
    rows = builtins.probe_registry(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
    assert len(rows) == 3
    assert rows[0]["hive"] == "HKCU"
    assert rows[0]["value_type"] == "REG_SZ"


def test_probe_service_sample():
    rows = builtins.probe_service("wuauserv")
    assert len(rows) == 2
    assert rows[0]["name"] == "wuauserv"
    assert rows[0]["path"]
    assert set(rows[0]) == {"name", "display", "start_type", "path", "account", "binary_path"}


@NEEDS_WINDOWS
def test_probe_identity_live():
    from jocky.runtime import harvesters

    rows = harvesters.identity_probe()
    assert len(rows) == 1
    assert rows[0]["user"]
    assert rows[0]["privileges"] in ("none", "administrator")


@NEEDS_WINDOWS
def test_probe_registry_live_run_key():
    from jocky.runtime import harvesters

    rows = harvesters.registry_probe(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
    assert rows
    assert rows[0]["hive"] == "HKCU"


@NEEDS_WINDOWS
def test_probe_service_live_known_service():
    from jocky.runtime import harvesters

    rows = harvesters.service_probe("LanmanServer")
    assert len(rows) == 1
    assert rows[0]["name"] == "LanmanServer"
    assert rows[0]["binary_path"]


def test_probe_mission_dispatches_to_evidence():
    """A probe mission parses, gates against its declared caps, and emits."""
    from jocky.runtime.interpreter import run_mission
    from jocky.dsl.parser import parse

    prog = parse(PROBE_MISSION)
    assert len(prog.units) == 1
    run = run_mission(prog, prog.units[0])
    assert run.error is None
    assert len(run.emitted) == 3
    assert run.card_verified is None or run.card_verified is True


def test_probe_capabilities_in_registry():
    from jocky.dsl.types import CAPABILITIES

    for cap in ("identity:probe", "registry:query", "service:probe"):
        assert cap in CAPABILITIES