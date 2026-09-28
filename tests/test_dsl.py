"""Front-end tests: grammar, parser, semantic checks, and JIR identity."""

from __future__ import annotations

import pytest

from jocky.dsl.ast import (
    CompareExpr,
    LambdaExpr,
    LetStmt,
    LiteralExpr,
    PipeExpr,
)
from jocky.dsl.checker import BOUND_BUILTINS
from jocky.dsl.grammar import KEYWORDS
from jocky.dsl.jir import digest, jir_document, serialize
from jocky.dsl.parser import JockySyntaxError, parse
from jocky.dsl.types import CAPABILITIES, NEVER_GRANT, DOMAIN_REGISTRY


def test_keyword_contract():
    assert len(KEYWORDS) == 34
    assert "mission" in KEYWORDS and "|>" in KEYWORDS and "=>" in KEYWORDS


def test_capability_and_never_grant_disjoint():
    assert not (CAPABILITIES & NEVER_GRANT)


def test_parse_mission_with_pipes():
    src = '''
@requires(process:list, network:analyze)
mission "Attack Surface" {
  fn surface() -> int {
    let procs = collect_processes();
    let suspicious = procs | (p => p.pid == 4);
    let hot = procs |sort_by("pid") |take 3 |sum;
    emit suspicious;
    return hot;
  }
  let r = surface();
  emit r;
}
'''
    prog = parse(src)
    assert prog.units[0].name == "Attack Surface"
    assert prog.units[0].requires == ["process:list", "network:analyze"]
    assert prog.all_requires() == ["process:list", "network:analyze"]
    f = prog.functions[0]
    filter_let = [s for s in f.body if isinstance(s, LetStmt) and s.name == "suspicious"][0]
    pe = filter_let.value
    assert isinstance(pe, PipeExpr)
    op = pe.ops[0]
    assert op.op == "filter" and isinstance(op.arg, LambdaExpr)
    assert isinstance(op.arg.body, CompareExpr)


def test_parse_while_and_match():
    src = '''
experiment "Baseline" {
  let x = 42;
  while x > 0 { x = x - 1; }
  match x { case 0 => emit "zero"; default => fail "nonzero"; }
}
'''
    prog = parse(src)
    assert prog.units[0].kind == "experiment"
    assert prog.units[0].body[1].kind == "while"
    m = prog.units[0].body[2]
    assert m.kind == "match"
    assert isinstance(m.cases[0].pattern, LiteralExpr)
    assert m.cases[0].pattern.type == "int"


def test_while_true_rejected():
    with pytest.raises(JockySyntaxError):
        parse('mission "A" { while true { }; }')


def test_unknown_capability_rejected():
    with pytest.raises(JockySyntaxError, match="unknown capability"):
        parse('@requires(frobnicate:all) mission "A" { }')


def test_never_grant_capability_rejected():
    with pytest.raises(JockySyntaxError, match="never-grant"):
        parse('@requires(edr:disable) mission "A" { }')


def test_use_before_define_rejected():
    with pytest.raises(JockySyntaxError, match="before it is defined"):
        parse('mission "A" { emit ghost; let ghost = 1; }')


def test_bad_pipe_arg_arity():
    with pytest.raises(JockySyntaxError, match="exactly one"):
        parse('mission "A" { let x = collect_processes() | group_by("a", "b"); }')


def test_bad_pipe_arg_kind():
    with pytest.raises(JockySyntaxError, match="string literal"):
        parse('mission "A" { let x = collect_processes() | group_by(42); }')


def test_pipe_to_unbound_target():
    with pytest.raises(JockySyntaxError, match="not a bound collector"):
        parse('mission "A" { let x = collect_processes() |> not_a_collector(); }')


def test_jir_digest_deterministic_and_sensitive():
    src = '@requires(process:list) mission "A" { let x = collect_processes() |count; emit x; }'
    p1 = parse(src)
    d1 = digest(p1)
    assert d1 == digest(p1)
    alt = '@requires(process:list, network:analyze) mission "A" { let x = collect_processes() |count; emit x; }'
    assert digest(parse(alt)) != d1


def test_jir_canonical_json_roundtrip():
    src = 'mission "A" { let x = [1, 2, 3] |sum; emit x; }'
    doc = jir_document(parse(src))
    assert json_roundtrip_sha(doc) == digest(parse(src))


def json_roundtrip_sha(doc) -> str:
    import hashlib

    text = serialize(doc)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_domain_registry_fields():
    for dtype, info in DOMAIN_REGISTRY.items():
        assert "fields" in info
        for fname, tref in info["fields"].items():
            assert tref.name in {
                "int", "float", "bool", "string", "bytes",
                "timestamp", "duration", "none", "map",
            } or tref.name in {d for d in DOMAIN_REGISTRY}
        assert all(str(c).startswith(("process:", "network:", "service:",
                                      "driver:", "persistence:", "event:",
                                      "lotl:", "evidence:", "collection:",
                                      "registry:", "identity:"))
                   for c in CAPABILITIES)


def test_bound_collectors_align_with_policy():
    assert "collect_processes" in BOUND_BUILTINS