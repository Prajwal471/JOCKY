"""Live harvesters smoke tests (Block 4).

These run the real Windows collectors under the caller's token.  They are
guarded to skip on non-Windows hosts and only assert broad sanity bounds so
they never depend on exact machine state.
"""

from __future__ import annotations

import os
import sys

import pytest

windows = pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows collectors")


@windows
def test_process_snapshot_sane():
    from jocky.runtime.harvesters import proc_rows

    rows = proc_rows()
    assert len(rows) >= 10
    fields = {"pid", "ppid", "name", "exe", "username", "created", "threads"}
    for row in rows:
        assert set(row) == fields


@windows
def test_connections_sane():
    from jocky.runtime.harvesters import connection_rows

    rows = connection_rows()
    assert len(rows) >= 1
    for row in rows:
        assert isinstance(row["pid"], int)
        assert row["local_port"] >= 0


@windows
def test_services_sane():
    from jocky.runtime.harvesters import service_rows

    rows = service_rows()
    assert len(rows) >= 20
    assert any(r["state"] == "RUNNING" for r in rows)


@windows
def test_drivers_sane():
    from jocky.runtime.harvesters import driver_rows

    rows = driver_rows()
    assert len(rows) >= 20
    signed = [r for r in rows if r["signed"]]
    assert len(signed) >= 1
    assert any(r["signer"] for r in signed)


@windows
def test_autostarts_sane():
    from jocky.runtime.harvesters import autostart_rows

    assert len(autostart_rows()) >= 1


@windows
def test_events_sane():
    from jocky.runtime.harvesters import event_rows

    assert len(event_rows()) >= 1


@windows
def test_system_info_sane():
    from jocky.runtime.harvesters import system_info

    info = system_info()
    assert info[0]["hostname"]
    assert info[0]["privileges"] in ("none", "administrator")


def test_lotl_scan_is_static():
    from jocky.runtime.harvesters import lotl_rows

    assert len(lotl_rows()) >= 5


def test_harvesters_domains_match_registry():
    from jocky.dsl.types import DOMAIN_REGISTRY
    from jocky.runtime import harvesters as H

    cases = [
        ("process", H.proc_rows(), "Process"),
        ("services", H.service_rows(), "Service"),
        ("drivers", H.driver_rows(), "Driver"),
        ("autostarts", H.autostart_rows(), "Autostart"),
        ("events", H.event_rows(), "Event"),
        ("network", H.connection_rows(), "NetworkConnection"),
        ("sysinfo", H.system_info(), "SystemInfo"),
        ("lotl", H.lotl_rows(), "LotlVector"),
    ]
    if not sys.platform.startswith("win"):
        return
    for label, rows, dtype in cases:
        fields = set(DOMAIN_REGISTRY[dtype]["fields"])
        for row in rows:
            assert set(row) <= fields, f"{label}: unexpected {set(row) - fields}"