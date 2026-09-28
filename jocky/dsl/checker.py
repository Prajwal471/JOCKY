"""Semantic checks and capability policy for JOCKY v0.1.

Runs after parsing. Enforces the structural safety properties that matter
for the selectivity guarantee:

  * every ``@requires`` capability must exist in the capability registry;
  * capabilities in the never-grant set are rejected explicitly
    (they name reference techniques JOCKY will never implement);
  * pipe verbs are type-checked against their arity and literal kinds;
  * names are bound before use (a light scope walk).

The checker is deliberately simple: domain values are constructed only by
the runtime, so normal code cannot forge them.
"""

from __future__ import annotations

from jocky.dsl.ast import (
    AssignStmt,
    CallExpr,
    Expr,
    ForStmt,
    FunctionDef,
    LambdaExpr,
    LetStmt,
    LiteralExpr,
    NameExpr,
    PipeExpr,
    PipeOp,
    Program,
    Stmt,
)
from jocky.dsl.parser import JockySyntaxError
from jocky.dsl.types import CAPABILITIES, NEVER_GRANT

_PIPE_ARITY: dict[str, str] = {
    "apply": "bag",
    "filter": "lambda",
    "group_by": "string",
    "sort_by": "string",
    "take": "int",
    "dedupe": "none",
    "sum": "none",
    "count": "none",
}

BOUND_BUILTINS = frozenset({
    "collect_processes", "analyze_network_connections", "list_services",
    "list_drivers", "list_autostarts", "read_events", "scan_lotl",
    "sign_evidence", "dispatch", "len", "int", "float", "str", "bool",
    "probe_registry", "probe_service", "probe_identity",
})


def validate_capabilities(prog: Program) -> None:
    """Reject unknown and never-granted capability names."""
    for cap in prog.all_requires():
        if cap in NEVER_GRANT:
            raise JockySyntaxError(
                f"capability '{cap}' is in the never-grant set; JOCKY will not perform that action"
            )
        if cap not in CAPABILITIES:
            raise JockySyntaxError(
                f"unknown capability '{cap}' (not present in the capability registry)"
            )


def _check_pipe_op(op: PipeOp) -> None:
    kind = _PIPE_ARITY.get(op.op)
    if op.op == "apply":
        fn = (op.arg or {}).get("name") if isinstance(op.arg, dict) else None
        if fn not in BOUND_BUILTINS:
            raise JockySyntaxError(f"pipe target '{fn}' is not a bound collector")
        return
    if op.op == "filter":
        if not isinstance(op.arg, LambdaExpr):
            raise JockySyntaxError("filter pipe requires a lambda")
        return
    if kind is None:
        raise JockySyntaxError(f"unregistered pipe operator '{op.op}'")
    args = op.arg if isinstance(op.arg, list) else [op.arg]
    if not args or args[0] is None:
        args = []
    if kind == "none":
        if args:
            raise JockySyntaxError(f"pipe operator '{op.op}' takes no arguments")
        return
    if len(args) != 1:
        raise JockySyntaxError(f"pipe operator '{op.op}' takes exactly one argument")
    lit = args[0]
    if kind == "int":
        if not (isinstance(lit, int) or (isinstance(lit, LiteralExpr) and lit.type == "int")):
            raise JockySyntaxError(f"pipe operator '{op.op}' expects an int literal")
    else:
        if not (isinstance(lit, LiteralExpr) and lit.type == "string"):
            raise JockySyntaxError(f"pipe operator '{op.op}' expects a string literal")
        return


def _check_expr(expr: Expr, scope: frozenset[str]) -> None:
    if isinstance(expr, PipeExpr):
        _check_expr(expr.lhs, scope)
        for op in expr.ops:
            _check_pipe_op(op)
            if isinstance(op.arg, LambdaExpr):
                sub = scope | frozenset(op.arg.params)
                _check_expr(op.arg.body, sub)
        return
    if isinstance(expr, NameExpr):
        if expr.name not in scope and expr.name not in BOUND_BUILTINS:
            raise JockySyntaxError(f"name '{expr.name}' is used before it is defined")
        return
    for field in type(expr).model_fields:
        if field in ("ops", "pairs"):
            continue
        if field in ("left", "right", "operand", "obj", "key", "expr", "to", "cond", "then", "else_"):
            child = getattr(expr, field)
            if isinstance(child, Expr):
                _check_expr(child, scope)
        elif field == "operands":
            op = getattr(expr, "operands", None)
            if op and isinstance(op, list):
                for child in op:
                    if isinstance(child, Expr):
                        _check_expr(child, scope)
        elif field == "args":
            args = getattr(expr, "args", None)
            if args and isinstance(args, list):
                for child in args:
                    if isinstance(child, Expr):
                        _check_expr(child, scope)


def _check_stmt(stmt: Stmt, scope: frozenset[str]) -> frozenset[str]:
    kind = stmt.kind
    if kind == "let":
        _check_expr(stmt.value, scope)
        return scope | {stmt.name}
    if kind == "assign":
        _check_expr(stmt.value, scope)
        if stmt.target not in scope:
            raise JockySyntaxError(f"assign to undefined variable '{stmt.target}'")
        return scope
    if kind == "emit":
        _check_expr(stmt.value, scope)
        return scope
    if kind == "return":
        if stmt.value is not None:
            _check_expr(stmt.value, scope)
        return scope
    if kind == "expr_stmt":
        _check_expr(stmt.expr, scope)
        return scope
    if kind == "assert":
        _check_expr(stmt.cond, scope)
        return scope
    if kind == "fail":
        return scope
    if kind == "while":
        _check_expr(stmt.cond, scope)
        for s in stmt.body:
            scope = _check_stmt(s, scope)
        return scope
    if kind == "if":
        _check_expr(stmt.cond, scope)
        branch = scope
        for s in stmt.body:
            branch = _check_stmt(s, branch)
        for cond, body in stmt.elifs:
            _check_expr(cond, scope)
            b = scope
            for s in body:
                b = _check_stmt(s, b)
        if stmt.else_:
            b = scope
            for s in stmt.else_:
                b = _check_stmt(s, b)
        return scope
    if kind == "for":
        _check_expr(stmt.iterable, scope)
        inner = scope | {stmt.var}
        for s in stmt.body:
            inner = _check_stmt(s, inner)
        return scope
    if kind == "match":
        _check_expr(stmt.subject, scope)
        for case in stmt.cases:
            b = scope
            for s in case.body:
                b = _check_stmt(s, b)
        return scope
    return scope


def validate(prog: Program) -> Program:
    """Run all front-end semantic checks on a parsed program."""
    validate_capabilities(prog)
    for unit in prog.units:
        scope: frozenset[str] = BOUND_BUILTINS
        for stmt in unit.body:
            scope = _check_stmt(stmt, scope)
    for fn in prog.functions:
        _check_fn(fn)
    return prog


def _check_fn(fn: FunctionDef) -> None:
    scope = frozenset({p[0] for p in fn.params}) | BOUND_BUILTINS
    for stmt in fn.body:
        scope = _check_stmt(stmt, scope)