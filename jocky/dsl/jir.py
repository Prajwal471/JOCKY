"""JIR: the JOCKY Intermediate Representation.

A program is reduced to a single canonical JSON document:

  * key order is fixed by the spec (version, mission units, functions);
  * the document is serialized with sorted keys and stable separators;
  * the digest is the JOCKY-defined identity ``sha256(canonical_json)``.

The digest binds the mission's *intent*, so any change to source (or to the
capability gates) produces a different JIR identity — this is what the
evidence chain later anchors to.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from jocky.dsl.ast import (
    AssignStmt,
    BinOpExpr,
    CallExpr,
    CastExpr,
    CompareExpr,
    EmitStmt,
    Expr,
    ExprStmt,
    FailStmt,
    FieldExpr,
    ForStmt,
    FunctionDef,
    IfExpr,
    IfStmt,
    LambdaExpr,
    LetStmt,
    ListExpr,
    LiteralExpr,
    MapExpr,
    MatchCase,
    MatchStmt,
    NameExpr,
    PipeExpr,
    PipeOp,
    Program,
    ReturnStmt,
    SetExpr,
    SubscriptExpr,
    UnitDef,
    UnaryOpExpr,
    WhileStmt,
)
from jocky.dsl.types import TypeRef

JIR_VERSION = "0.1.0"


def jir_document(
    prog: Program, *, declared_capabilities: list[str] | None = None
) -> dict[str, Any]:
    """Reduce a Program to its canonical JIR document."""
    caps = declared_capabilities if declared_capabilities is not None else prog.all_requires()
    doc: dict[str, Any] = {
        "version": JIR_VERSION,
        "program": {
            "name": prog.name,
            "declared_capabilities": sorted(caps),
            "missions": [_unit(u) for u in prog.units],
            "functions": [_fn(f) for f in prog.functions],
        },
    }
    return doc


def serialize(doc: dict[str, Any]) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(doc: dict[str, Any]) -> str:
    return hashlib.sha256(serialize(doc).encode("utf-8")).hexdigest()


def digest(prog: Program) -> str:
    return sha256_hex(jir_document(prog))


def _expr(e: Expr) -> dict[str, Any]:
    if isinstance(e, LiteralExpr):
        return {"literal": e.type, "value": e.value}
    if isinstance(e, NameExpr):
        return {"name": e.name}
    if isinstance(e, CompareExpr):
        return {
            "compare": {
                "ops": e.ops,
                "operands": [_expr(o) for o in e.operands],
            }
        }
    if isinstance(e, BinOpExpr):
        return {
            "binop": {
                "op": e.op,
                "left": _expr(e.left),
                "right": _expr(e.right),
            }
        }
    if isinstance(e, UnaryOpExpr):
        return {"unary": {"op": e.op, "operand": _expr(e.operand)}}
    if isinstance(e, FieldExpr):
        return {"field": {"obj": _expr(e.obj), "name": e.field}}
    if isinstance(e, SubscriptExpr):
        return {"subscript": {"obj": _expr(e.obj), "key": _expr(e.key)}}
    if isinstance(e, CastExpr):
        return {"cast": {"expr": _expr(e.expr), "to": e.to.to_jir()}}
    if isinstance(e, CallExpr):
        return {"call": {"func": e.func, "args": [_expr(a) for a in e.args]}}
    if isinstance(e, ListExpr):
        return {"list": [_expr(i) for i in e.items]}
    if isinstance(e, SetExpr):
        return {"set": [_expr(i) for i in e.items]}
    if isinstance(e, MapExpr):
        return {"map": [[_expr(k), _expr(v)] for k, v in e.pairs]}
    if isinstance(e, LambdaExpr):
        return {"lambda": {"params": e.params, "body": _expr(e.body)}}
    if isinstance(e, IfExpr):
        return {
            "ifexpr": {"cond": _expr(e.cond), "then": _expr(e.then), "else_": _expr(e.else_)}
        }
    if isinstance(e, PipeExpr):
        return {"pipe": {"lhs": _expr(e.lhs), "ops": [_pipe(o) for o in e.ops]}}
    return {"raw": repr(e)}


def _pipe(op: PipeOp) -> dict[str, Any]:
    d: dict[str, Any] = {"op": op.op}
    if op.op == "filter":
        d["arg"] = _expr(op.arg)
    elif op.op == "apply":
        arg = op.arg or {}
        d["arg"] = {
            "name": arg.get("name"),
            "args": [_expr(a) for a in (arg.get("args") or [])],
        }
    elif isinstance(op.arg, list):
        d["arg"] = [_expr(a) if isinstance(a, Expr) else a for a in op.arg]
    else:
        d["arg"] = op.arg
    return d


def _stmt(s) -> dict[str, Any]:
    kinds = {
        "let": ("let", lambda: {"name": s.name, "value": _expr(s.value)}),
        "assign": ("assign", lambda: {"target": s.target, "value": _expr(s.value)}),
        "if": (
            "if",
            lambda: {
                "cond": _expr(s.cond),
                "body": [_stmt(x) for x in s.body],
                "elifs": [[_expr(c), [_stmt(x) for x in b]] for c, b in s.elifs],
                "else_": [_stmt(x) for x in s.else_] if s.else_ else None,
            },
        ),
        "for": (
            "for",
            lambda: {"var": s.var, "iterable": _expr(s.iterable), "body": [_stmt(x) for x in s.body]},
        ),
        "while": ("while", lambda: {"cond": _expr(s.cond), "body": [_stmt(x) for x in s.body]}),
        "return": ("return", lambda: {"value": _expr(s.value) if s.value else None}),
        "emit": ("emit", lambda: {"value": _expr(s.value), "label": s.label}),
        "assert": ("assert", lambda: {"cond": _expr(s.cond), "message": s.message}),
        "fail": ("fail", lambda: {"message": s.message}),
        "match": (
            "match",
            lambda: {
                "subject": _expr(s.subject),
                "cases": [
                    {"pattern": _expr(c.pattern) if isinstance(c.pattern, Expr) else {"raw": c.pattern},
                     "body": [_stmt(x) for x in c.body]}
                    for c in s.cases
                ],
            },
        ),
        "expr_stmt": ("expr", lambda: {"expr": _expr(s.expr)}),
    }
    if s.kind not in kinds:
        return {"stmt": s.kind}
    kind, body = kinds[s.kind]
    return {"stmt": kind, "body": body()}


def _unit(u: UnitDef) -> dict[str, Any]:
    return {
        "kind": u.kind,
        "name": u.name,
        "purpose": u.purpose,
        "requires": sorted(u.requires),
        "body": [_stmt(s) for s in u.body],
    }


def _fn(f: FunctionDef) -> dict[str, Any]:
    return {
        "name": f.name,
        "params": [[p[0], p[1].to_jir() if p[1] else None] for p in f.params],
        "returns": f.returns.to_jir() if f.returns else None,
        "requires": sorted(f.requires),
        "purpose": f.purpose,
        "body": [_stmt(s) for s in f.body],
    }


__all__ = ["JIR_VERSION", "jir_document", "serialize", "sha256_hex", "digest"]