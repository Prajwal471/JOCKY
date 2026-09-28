"""Interpreter for JOCKY v0.1 missions.

Enforces the two runtime invariants the paper's Section 16 argument rests on:

  1. No capability-gated call is dispatched unless the invoking mission
     declared that capability (no escalation, no bypass of @requires).
  2. Every control-flow path is bounded: ``while true`` is rejected at
     parse time, loop iterations are capped, recursion depth is capped, and
     the whole run has a finite step budget.

``emit`` records are collected with provenance; signing and chain anchoring
happen in Block 3 via ``evidence:sign`` so that evidence remains
verifiable externally.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from jocky.config import MAX_RECURSION_DEPTH, WHILE_ITERATION_CAP
from jocky.dsl.jir import digest
from jocky.runtime.identity import MissionCard
from jocky.dsl.ast import (
    AssertStmt,
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
    Stmt,
    SubscriptExpr,
    UnaryOpExpr,
    UnitDef,
    WhileStmt,
)
from jocky.runtime.builtins import (
    BOUND_BUILTINS,
    BUILTIN_CAPABILITIES,
    collect_processes,
    analyze_network_connections,
    list_services,
    list_drivers,
    list_autostarts,
    read_events,
    scan_lotl,
    sign_evidence,
    dispatch,
)
from jocky.runtime.evidence import canonical_bytes

_BUILTIN_FUNCS = {
    "collect_processes": collect_processes,
    "analyze_network_connections": analyze_network_connections,
    "list_services": list_services,
    "list_drivers": list_drivers,
    "list_autostarts": list_autostarts,
    "read_events": read_events,
    "scan_lotl": scan_lotl,
    "sign_evidence": sign_evidence,
    "dispatch": dispatch,
}


class JockyRuntimeError(RuntimeError):
    pass


class _ReturnSignal(Exception):
    def __init__(self, value: Any):
        self.value = value


class _FailSignal(Exception):
    def __init__(self, message: str):
        self.message = message


@dataclass
class MissionRun:
    unit: UnitDef
    emitted: list[dict[str, Any]] = field(default_factory=list)
    steps: int = 0
    result: Any = None
    error: str | None = None
    mission_digest: str = ""
    card_verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "unit": self.unit.kind,
            "name": self.unit.name,
            "emitted": self.emitted,
            "steps": self.steps,
            "result": self.result,
            "error": self.error,
            "mission_digest": self.mission_digest,
            "card_verified": self.card_verified,
        }


class Interpreter:
    def __init__(
        self,
        *,
        maximum_steps: int = 500_000,
        loop_cap: int = WHILE_ITERATION_CAP,
        recursion_cap: int = MAX_RECURSION_DEPTH,
        mission_card: MissionCard | None = None,
        on_emit: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.maximum_steps = maximum_steps
        self.loop_cap = loop_cap
        self.recursion_cap = recursion_cap
        self.mission_card = mission_card
        self.on_emit = on_emit
        self._budget = maximum_steps
        self._depth = 0
        self._caps: frozenset[str] = frozenset()
        self._emitted: list[dict[str, Any]] = []

    # ---- budget ----------------------------------------------------------
    def _spend(self, n: int = 1) -> None:
        self._budget -= n
        if self._budget < 0:
            raise JockyRuntimeError("step budget exhausted; aborting bounded run")

    # ---- public API ------------------------------------------------------
    def run(self, prog: Program, unit: UnitDef) -> MissionRun:
        mission_digest = digest(prog)
        run = MissionRun(unit=unit, mission_digest=mission_digest)
        self._caps = frozenset(unit.requires)
        if self.mission_card is not None:
            if not self.mission_card.verify():
                run.error = "mission card signature or expiry failed"
                run.card_verified = False
            elif not self.mission_card.authorizes(self._caps):
                run.error = (
                    "mission requires capabilities beyond the signed mission card: "
                    f"{sorted(self._caps - set(self.mission_card.capabilities))}"
                )
            elif self.mission_card.mission_digest != mission_digest:
                run.error = "mission JIR digest does not match the pinned mission card (JIR drift)"
            if run.error:
                return run
        scope: dict[str, Any] = {f.name: f for f in prog.functions}
        try:
            last = None
            for stmt in unit.body:
                out = self._exec_stmt(stmt, scope)
                if stmt.kind == "expr_stmt":
                    last = out
            run.result = last
        except _ReturnSignal as sig:
            run.result = sig.value
        except _FailSignal as sig:
            run.error = sig.message
        except JockyRuntimeError as exc:
            run.error = str(exc)
        finally:
            run.steps = self.maximum_steps - self._budget
            run.emitted = list(self._emitted)
            self._emitted = []
            self._budget = self.maximum_steps
        return run

    # ---- capability gate -------------------------------------------------
    def _gate(self, fn_name: str) -> None:
        cap = BUILTIN_CAPABILITIES.get(fn_name)
        if cap is None:
            if fn_name not in BOUND_BUILTINS and fn_name not in ("len", "int", "float", "str", "bool"):
                raise JockyRuntimeError(
                    f"not a bound collector: '{fn_name}' (undefined function)"
                )
            return
        if cap not in self._caps:
            raise JockyRuntimeError(
                f"capability '{cap}' not declared by this mission; refusing to call '{fn_name}'"
            )

    # ---- statements -------------------------------------------------------
    def _exec_stmt(self, stmt: Stmt, scope: dict[str, Any]) -> Any:
        self._spend()
        kind = stmt.kind
        if kind == "let":
            value = self._eval_expr(stmt.value, scope)
            if stmt.name in scope and callable(scope[stmt.name]):
                raise JockyRuntimeError(f"cannot shadow function '{stmt.name}'")
            scope[stmt.name] = value
            return None
        if kind == "assign":
            if stmt.target not in scope:
                raise JockyRuntimeError(f"assignment to undefined variable '{stmt.target}'")
            scope[stmt.target] = self._eval_expr(stmt.value, scope)
            return None
        if kind == "expr_stmt":
            return self._eval_expr(stmt.expr, scope)
        if kind == "emit":
            value = self._eval_expr(stmt.value, scope)
            record = {"label": stmt.label, "value": value, "source": "emit"}
            self._emitted.append(record)
            if self.on_emit is not None:
                self.on_emit(record)
            return None
        if kind == "assert":
            if not self._truthy(self._eval_expr(stmt.cond, scope)):
                raise _FailSignal(stmt.message or "assertion failed")
            return None
        if kind == "fail":
            raise _FailSignal(stmt.message or "mission failed")
        if kind == "return":
            value = self._eval_expr(stmt.value, scope) if stmt.value is not None else None
            raise _ReturnSignal(value)
        if kind == "while":
            iterations = 0
            while self._truthy(self._eval_expr(stmt.cond, scope)):
                if iterations >= self.loop_cap:
                    raise JockyRuntimeError("loop exceeded bounded iteration cap")
                for s in stmt.body:
                    self._exec_stmt(s, scope)
                iterations += 1
            return None
        if kind == "if":
            if self._truthy(self._eval_expr(stmt.cond, scope)):
                for s in stmt.body:
                    self._exec_stmt(s, scope)
                return None
            for cond, body in stmt.elifs:
                if self._truthy(self._eval_expr(cond, scope)):
                    for s in body:
                        self._exec_stmt(s, scope)
                    return None
            if stmt.else_:
                for s in stmt.else_:
                    self._exec_stmt(s, scope)
            return None
        if kind == "for":
            iterable = self._eval_expr(stmt.iterable, scope)
            if not isinstance(iterable, (list, tuple, str)):
                raise JockyRuntimeError("for loop requires a sequence")
            for item in iterable:
                if self._budget <= 0:
                    raise JockyRuntimeError("step budget exhausted in for loop")
                scope[stmt.var] = item
                for s in stmt.body:
                    self._exec_stmt(s, scope)
            return None
        if kind == "match":
            subject = self._eval_expr(stmt.subject, scope)
            for case in stmt.cases:
                if self._matches(case, subject, scope):
                    for s in case.body:
                        self._exec_stmt(s, scope)
                    return None
            return None
        raise JockyRuntimeError(f"unhandled statement kind '{kind}'")

    def _matches(self, case: MatchCase, subject: Any, scope: dict[str, Any]) -> bool:
        pat = case.pattern
        if pat == "":
            return True  # default
        if isinstance(pat, LiteralExpr):
            return self._equals(subject, pat.value)
        if isinstance(pat, NameExpr):
            if pat.name == "_":
                return True
            scope[pat.name] = subject  # bind
            return True
        raise JockyRuntimeError("unsupported match pattern")

    # ---- expressions ------------------------------------------------------
    def _eval_expr(self, expr: Expr, scope: dict[str, Any]) -> Any:
        self._spend()
        if isinstance(expr, LiteralExpr):
            return expr.value
        if isinstance(expr, NameExpr):
            if expr.name in scope:
                return scope[expr.name]
            if expr.name in _BUILTIN_FUNCS:
                self._gate(expr.name)
                return _BUILTIN_FUNCS[expr.name]
            raise JockyRuntimeError(f"undefined name '{expr.name}'")
        if isinstance(expr, FieldExpr):
            obj = self._eval_expr(expr.obj, scope)
            if isinstance(obj, dict) and expr.field in obj:
                return obj[expr.field]
            if hasattr(obj, expr.field):
                return getattr(obj, expr.field)
            if isinstance(obj, (list, tuple)) and expr.field == "len":
                return len(obj)
            raise JockyRuntimeError(f"no field '{expr.field}'")
        if isinstance(expr, SubscriptExpr):
            obj = self._eval_expr(expr.obj, scope)
            key = self._eval_expr(expr.key, scope)
            try:
                return obj[key]
            except (KeyError, TypeError, IndexError) as exc:
                raise JockyRuntimeError(f"index error: {exc}") from exc
        if isinstance(expr, CallExpr):
            return self._call(expr, scope)
        if isinstance(expr, BinOpExpr):
            left = self._eval_expr(expr.left, scope)
            right = self._eval_expr(expr.right, scope)
            return self._binop(expr.op, left, right)
        if isinstance(expr, CompareExpr):
            return self._compare(expr, scope)
        if isinstance(expr, UnaryOpExpr):
            if expr.op == "not":
                return not self._truthy(self._eval_expr(expr.operand, scope))
            if expr.op == "-":
                return -self._eval_expr(expr.operand, scope)
            if expr.op == "+":
                return +self._eval_expr(expr.operand, scope)
            raise JockyRuntimeError(f"bad unary op {expr.op}")
        if isinstance(expr, ListExpr):
            return [self._eval_expr(i, scope) for i in expr.items]
        if isinstance(expr, SetExpr):
            return {canonical_bytes(self._eval_expr(i, scope)) for i in expr.items}
        if isinstance(expr, MapExpr):
            return {self._eval_expr(k, scope): self._eval_expr(v, scope) for k, v in expr.pairs}
        if isinstance(expr, IfExpr):
            if self._truthy(self._eval_expr(expr.cond, scope)):
                return self._eval_expr(expr.then, scope)
            return self._eval_expr(expr.else_, scope)
        if isinstance(expr, CastExpr):
            value = self._eval_expr(expr.expr, scope)
            target = expr.to.name
            try:
                return _CASTS[target](value)
            except KeyError:
                raise JockyRuntimeError(f"unknown cast target '{target}'") from None
            except (TypeError, ValueError) as exc:
                raise JockyRuntimeError(f"cannot cast to {target}: {exc}") from exc
        if isinstance(expr, LambdaExpr):
            scope[expr.params[0]] = None
            raise JockyRuntimeError("lambda is not a first-class value in v0.1")
        if isinstance(expr, PipeExpr):
            return self._eval_pipe(expr, scope)
        raise JockyRuntimeError(f"unhandled expression {type(expr).__name__}")

    def _call(self, expr: CallExpr, scope: dict[str, Any]) -> Any:
        name = expr.func
        if name in scope and isinstance(scope[name], FunctionDef):
            fn: FunctionDef = scope[name]
            self._depth += 1
            if self._depth > self.recursion_cap:
                self._depth -= 1
                raise JockyRuntimeError("function recursion depth exceeded")
            for cap in fn.requires:
                if cap not in self._caps:
                    self._depth -= 1
                    raise JockyRuntimeError(
                        f"function '{name}' requires '{cap}' not declared by this mission"
                    )
            args = [self._eval_expr(a, scope) for a in expr.args]
            if len(args) != len(fn.params):
                self._depth -= 1
                raise JockyRuntimeError(
                    f"'{name}' expects {len(fn.params)} args, got {len(args)}"
                )
            inner: dict[str, Any] = dict(scope)
            for (pname, _pann), value in zip(fn.params, args):
                inner[pname] = value
            try:
                for s in fn.body:
                    self._exec_stmt(s, inner)
            except _ReturnSignal as sig:
                self._depth -= 1
                return sig.value
            self._depth -= 1
            return None
        if name in _BUILTIN_FUNCS:
            self._gate(name)
            args = [self._eval_expr(a, scope) for a in expr.args]
            return _BUILTIN_FUNCS[name](*args)
        if name in ("len", "int", "float", "str", "bool"):
            args = [self._eval_expr(a, scope) for a in expr.args]
            return _CASTS[name](args[0] if args else None)
        raise JockyRuntimeError(f"call to undefined function '{name}'")

    def _eval_pipe(self, expr: PipeExpr, scope: dict[str, Any]) -> Any:
        value = self._eval_expr(expr.lhs, scope)
        for op in expr.ops:
            value = self._apply_pipe(op, value, scope)
        return value

    def _str_arg(self, arg: Any) -> Any:
        if isinstance(arg, list):
            arg = arg[0] if arg else None
        if isinstance(arg, LiteralExpr):
            return arg.value
        return arg

    def _apply_pipe(self, op: PipeOp, value: Any, scope: dict[str, Any]) -> Any:
        name = op.op
        if name in ("sum", "count", "dedupe"):
            if not isinstance(value, (list, tuple)):
                raise JockyRuntimeError(f"pipe '{name}' requires a list")
            if name == "count":
                return len(value)
            if name == "dedupe":
                out: list[Any] = []
                seen: set[str] = set()
                for item in value:
                    key = canonical_bytes(item)
                    if key not in seen:
                        seen.add(key)
                        out.append(item)
                return out
            if value and isinstance(value[0], (int, float)):
                return sum(value)
            if value and isinstance(value[0], dict):
                first = value[0]
                numerics = [k for k, v in first.items() if isinstance(v, (int, float))]
                if len(numerics) == 1:
                    col = numerics[0]
                    return sum(r[col] for r in value)
            raise JockyRuntimeError("pipe 'sum' needs a numeric list or a single numeric column")
        if name == "take":
            n = op.arg
            return value[: n]
        if name == "filter":
            lam = op.arg
            if not isinstance(lam, LambdaExpr):
                raise JockyRuntimeError("filter pipe requires a lambda")
            return [r for r in value if self._truthy(self._lambda(lam, [r], scope))]
        if name == "group_by":
            field = self._str_arg(op.arg)
            groups: dict[Any, list[Any]] = {}
            for row in value:
                v = row[field] if isinstance(row, dict) else getattr(row, field)
                groups.setdefault(v, []).append(row)
            return groups
        if name == "sort_by":
            field = self._str_arg(op.arg)
            rows = list(value)
            rows.sort(key=lambda row: row[field] if isinstance(row, dict) else getattr(row, field))
            return rows
        if name == "apply":
            arg = op.arg or {}
            fn_name = arg.get("name")
            args = [value] + [self._eval_expr(a, scope) for a in (arg.get("args") or [])]
            if fn_name in _BUILTIN_FUNCS:
                self._gate(fn_name)
                return _BUILTIN_FUNCS[fn_name](*args)
            if fn_name in scope and isinstance(scope[fn_name], FunctionDef):
                return self._call_user_fn(fn_name, args, scope)
            raise JockyRuntimeError(f"pipe target '{fn_name}' not found")
        raise JockyRuntimeError(f"unknown pipe operator '{name}'")

    def _call_user_fn(self, name: str, args: list[Any], scope: dict[str, Any]) -> Any:
        fn: FunctionDef = scope[name]
        self._depth += 1
        if self._depth > self.recursion_cap:
            self._depth -= 1
            raise JockyRuntimeError("function recursion depth exceeded")
        inner: dict[str, Any] = dict(scope)
        for (pname, _ann), value in zip(fn.params, args):
            inner[pname] = value
        try:
            for s in fn.body:
                self._exec_stmt(s, inner)
        except _ReturnSignal as sig:
            self._depth -= 1
            return sig.value
        self._depth -= 1
        return None

    def _lambda(self, lam: LambdaExpr, args: list[Any], scope: dict[str, Any]) -> Any:
        inner: dict[str, Any] = dict(scope)
        for pname, value in zip(lam.params, args):
            inner[pname] = value
        return self._eval_expr(lam.body, inner)

    # ---- operators --------------------------------------------------------
    def _binop(self, op: str, left: Any, right: Any) -> Any:
        try:
            if op == "+":
                return left + right
            if op == "-":
                return left - right
            if op == "*":
                return left * right
            if op == "/":
                return left / right
            if op == "%":
                return left % right
            if op == "//":
                return left // right
            if op == "^":
                return left**right
        except Exception as exc:  # noqa: BLE001
            raise JockyRuntimeError(f"operator {op} failed: {exc}") from exc
        raise JockyRuntimeError(f"unknown binary operator {op}")

    def _compare(self, expr: CompareExpr, scope: dict[str, Any]) -> bool:
        parts = [self._eval_expr(o, scope) for o in expr.operands]
        ops = list(expr.ops)
        ok = True
        for i, opera in enumerate(ops):
            a, b = parts[i], parts[i + 1]
            if opera == "==":
                acc = self._equals(a, b)
            elif opera == "!=":
                acc = not self._equals(a, b)
            elif opera == "<":
                acc = a < b
            elif opera == "<=":
                acc = a <= b
            elif opera == ">":
                acc = a > b
            elif opera == ">=":
                acc = a >= b
            else:
                raise JockyRuntimeError(f"bad comparison op {opera}")
            ok = ok and acc
            if not ok:
                return False
        return True

    @staticmethod
    def _equals(a: Any, b: Any) -> bool:
        if isinstance(a, dict) and isinstance(b, dict):
            return canonical_bytes(a) == canonical_bytes(b)
        return type(a) is type(b) and a == b

    @staticmethod
    def _truthy(v: Any) -> bool:
        if v is None:
            return False
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return v != 0
        if isinstance(v, (str, list, tuple, dict, set)):
            return len(v) > 0
        return bool(v)


_CASTS = {
    "int": int,
    "float": float,
    "str": str,
    "bool": bool,
}


def run_mission(prog: Program, unit: UnitDef, **kwargs: Any) -> MissionRun:
    return Interpreter(**kwargs).run(prog, unit)


__all__ = [
    "Interpreter",
    "MissionRun",
    "JockyRuntimeError",
    "run_mission",
]