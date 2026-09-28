"""Interpreter & runtime-library tests for JOCKY v0.1."""

from __future__ import annotations

import pytest

from jocky.dsl.ast import FunctionDef
from jocky.dsl.parser import parse
from jocky.runtime.builtins import BUILTIN_CAPABILITIES
from jocky.runtime.evidence import Ed25519Signer, sha256_bytes, sign_evidence_record
from jocky.runtime.interpreter import JockyRuntimeError, run_mission


def test_mission_pipes_and_emit():
    src = '''
@requires(process:list, network:analyze)
mission "Surface" {
  let procs = collect_processes();
  let suspicious = procs | (p => p.pid == 4);
  let hot = procs |sort_by("pid") |take 3 |count;
  emit suspicious;
  emit hot;
}
'''
    prog = parse(src)
    run = run_mission(prog, prog.units[0])
    assert run.error is None
    assert [r["pid"] for r in run.emitted[0]["value"]] == [4]
    assert run.emitted[1]["value"] == 3


def test_capability_gate_blocks_undeclared():
    src = '''
mission "Under" {
  let s = list_services();
  emit s;
}
'''
    prog = parse(src)
    run = run_mission(prog, prog.units[0])
    assert "not declared" in run.error


def test_capability_gate_permits_declared():
    src = '''
@requires(service:list)
mission "Over" {
  let s = list_services();
  emit s |count;
}
'''
    prog = parse(src)
    run = run_mission(prog, prog.units[0])
    assert run.error is None
    assert run.emitted[0]["value"] == 3


def test_while_bounded_passes():
    src = '''
mission "Loop" {
  let x = 10;
  let acc = 0;
  while x > 0 { acc = acc + x; x = x - 1; }
  emit acc;
}
'''
    run = run_mission(parse(src), parse(src).units[0])
    assert run.error is None
    assert run.emitted[0]["value"] == 55


def test_for_and_match():
    src = '''
experiment "M1" {
  let arr = [1, 2, 3] |count;
  match arr {
    case 3 => emit "three";
    default => emit "other";
  }
}
'''
    prog = parse(src)
    run = run_mission(prog, prog.units[0])
    assert run.error is None
    assert run.emitted[0]["label"] == "three" or run.emitted[0]["value"] == "three"


def test_step_budget_exhausted():
    src = '''
mission "Burn" {
  let i = 1000000;
  while i > 0 { i = i - 1; }
}
'''
    run = run_mission(parse(src), parse(src).units[0], maximum_steps=2000)
    assert "step budget" in run.error


def test_user_fn_and_requires_union():
    src = '''
@requires(process:list)
mission "Fn" {
  @requires(process:list)
  fn count_procs() -> int {
    return collect_processes() |count;
  }
  emit count_procs();
}
'''
    prog = parse(src)
    run = run_mission(prog, prog.units[0])
    assert run.error is None
    assert run.emitted[0]["value"] == 6


def test_user_fn_escalation_rejected():
    src = '''
mission "Esc" {
  @requires(network:analyze)
  fn leak() {
    return analyze_network_connections() |count;
  }
  emit leak();
}
'''
    prog = parse(src)
    run = run_mission(prog, prog.units[0])
    assert "not declared" in run.error


def test_recursion_cap():
    src = '''
mission "Rec" {
  fn down(n: int) {
    return down(n - 1);
  }
  let _ = down(10);
}
'''
    prog = parse(src)
    run = run_mission(prog, prog.units[0], recursion_cap=4)
    assert "recursion depth" in run.error


def test_evidence_signing_roundtrip():
    signer = Ed25519Signer()
    rec = sign_evidence_record(
        finding_type="observation",
        source="collectors.test",
        payload={"rows": [1, 2, 3]},
        privileges="none",
        capability="process:list",
        chain_index=0,
        prev_hash="",
        mission_digest="a" * 64,
        signer=signer,
    )
    assert len(rec["chain_hash"]) == 64
    assert len(rec["signature"]) == 128
    assert rec["signed_by"] == signer.public_key_hex
    assert rec["payload_sha256"] == sha256_bytes(rec["payload"])


def test_every_builtin_has_capability():
    from jocky.runtime.builtins import BOUND_BUILTINS
    assert set(BUILTIN_CAPABILITIES) == set(BOUND_BUILTINS)


def test_collect_rows_match_domain_fields():
    from jocky.dsl.types import DOMAIN_REGISTRY
    from jocky.runtime import builtins as B
    probes = {
        "collect_processes": "Process",
        "analyze_network_connections": "NetworkConnection",
        "list_services": "Service",
        "list_drivers": "Driver",
        "list_autostarts": "Autostart",
        "read_events": "Event",
        "scan_lotl": "LotlVector",
        "dispatch": "SystemInfo",
    }
    for fn_name, dtype in probes.items():
        rows = getattr(B, fn_name)("W10-CLIENT", "probe") if fn_name == "dispatch" else getattr(B, fn_name)()
        fields = DOMAIN_REGISTRY[dtype]["fields"]
        for row in rows:
            assert set(row) <= set(fields), f"{fn_name}: {set(row) - set(fields)}"