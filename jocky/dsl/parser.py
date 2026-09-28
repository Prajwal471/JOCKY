"""Front-end: Lark text -> CST -> typed AST.

Also performs structural safety checks on the way out:
  - pipes are desugared to explicit PipeExpr nodes
  - ``while`` conditions must not be constant-true (bounded-only)
  - ``@requires`` gates are collected onto functions and missions
The resulting Program is the input to the JIR serializer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from lark import Lark, ParseError, Token, Transformer, Tree

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
from jocky.dsl.grammar import JOCKY_GRAMMAR, KEYWORDS
from jocky.dsl.types import TypeRef


class JockySyntaxError(ValueError):
    pass


@dataclass
class _UnitItem:
    kind: str  # "stmt" | "fn"
    value: Any
    requires: list[str] = field(default_factory=list)
    purpose: str = ""


@dataclass
class _Mission:
    kind: str
    name: str
    purpose: str = ""
    requires: list[str] = field(default_factory=list)
    body: list[Stmt] = field(default_factory=list)
    fns: list[FunctionDef] = field(default_factory=list)


def _unescape(s: str) -> str:
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            nxt = s[i + 1]
            if nxt == "n":
                out.append("\n")
                i += 2
            elif nxt == "t":
                out.append("\t")
                i += 2
            elif nxt == "r":
                out.append("\r")
                i += 2
            elif nxt == '"':
                out.append('"')
                i += 2
            elif nxt == "\\":
                out.append("\\")
                i += 2
            elif nxt == "x" and i + 3 < n:
                out.append(chr(int(s[i + 2 : i + 4], 16)))
                i += 4
            elif nxt == "u" and i + 5 < n:
                out.append(chr(int(s[i + 2 : i + 6], 16)))
                i += 6
            else:
                out.append(nxt)
                i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _parse_bytes(text: str) -> bytes:
    inner = _unescape(text)
    return inner.encode("latin-1")


class _Builder(Transformer):
    """Lark CST -> AST."""

    def start(self, children):
        return children[0]

    # ---- language units -------------------------------------------------
    def unit_def(self, children):
        return children[0]

    def program(self, children):
        units: list[UnitDef] = []
        fns: list[FunctionDef] = []
        for child in children:
            if isinstance(child, _Mission):
                for f in child.fns:
                    fns.append(f)
                units.append(
                    UnitDef(
                        kind=child.kind,
                        name=child.name,
                        purpose=child.purpose,
                        requires=child.requires,
                        body=child.body,
                    )
                )
            elif isinstance(child, FunctionDef):
                fns.append(child)
        name = units[0].name if units else "unnamed"
        return Program(name=name, units=units, functions=fns)

    def item(self, children):
        decos, value = self._split_decos(children)
        if isinstance(value, FunctionDef):
            return value.model_copy(
                update={"requires": decos["requires"], "purpose": decos["purpose"]}
            )
        if isinstance(value, _Mission):
            value.requires = decos["requires"]
            value.purpose = decos["purpose"] or value.purpose
            return value
        raise JockySyntaxError("top-level item must be a mission or function")

    def mission_def(self, children):
        return self._unit("mission", children)

    def experiment_def(self, children):
        return self._unit("experiment", children)

    def _unit(self, kind: str, children):
        name_tok = children[1]
        name = _unescape(str(name_tok)[1:-1])
        m = _Mission(kind=kind, name=name)
        for c in children[1:]:
            if isinstance(c, _UnitItem):
                if c.kind == "fn":
                    f = c.value.model_copy(
                        update={"requires": c.requires, "purpose": c.purpose}
                    )
                    m.fns.append(f)
                else:
                    m.body.append(c.value)
        return m

    def unit_item(self, children):
        decos, value = self._split_decos(children)
        if isinstance(value, FunctionDef):
            return _UnitItem(
                kind="fn", value=value, requires=decos["requires"], purpose=decos["purpose"]
            )
        return _UnitItem(kind="stmt", value=value)

    @staticmethod
    def _split_decos(children):
        decos = {"requires": [], "purpose": ""}
        values = []
        for c in children:
            if isinstance(c, tuple) and c and c[0] in ("requires", "purpose"):
                if c[0] == "requires":
                    decos["requires"].extend(c[1])
                else:
                    decos["purpose"] = c[1]
            else:
                values.append(c)
        if len(values) != 1:
            raise JockySyntaxError("expected exactly one decorated value")
        return decos, values[0]

    def deco_requires(self, children):
        caps = [c for c in children if isinstance(c, str) and not isinstance(c, Token)]
        return ("requires", caps)

    def cap(self, children):
        names = [c for c in children if isinstance(c, Token) and c.type == "NAME"]
        return ":".join(str(n) for n in names)

    def deco_purpose(self, children):
        tok = children[-1]
        return ("purpose", _unescape(str(tok)[1:-1]))

    # ---- functions ------------------------------------------------------
    def fn_def(self, children):
        name = None
        returns: TypeRef | None = None
        lists: list[list] = []
        for c in children:
            if isinstance(c, Token):
                if c.type == "NAME" and name is None:
                    name = str(c)
            elif isinstance(c, TypeRef) and returns is None:
                returns = c
            elif isinstance(c, list):
                lists.append(c)
        if len(lists) == 1:
            params, body = [], lists[0]
        elif len(lists) > 1:
            params, body = lists[0], lists[-1]
        else:
            params, body = [], []
        return FunctionDef(name=name or "", params=params, returns=returns, body=body)

    def params(self, children):
        return children

    def param(self, children):
        name = str(children[0])
        ann = children[1] if len(children) > 1 else None
        return (name, ann)

    # ---- statements -----------------------------------------------------
    def block(self, children):
        return children

    def let_stmt(self, children):
        name = None
        value = None
        ann = None
        for c in children:
            if isinstance(c, Token) and c.type == "NAME" and name is None:
                name = str(c)
            elif isinstance(c, TypeRef) and ann is None:
                ann = c
            elif isinstance(c, Expr):
                value = c
        if name is None or value is None:
            raise JockySyntaxError("malformed let statement")
        return LetStmt(name=name, annotation=ann, value=value)

    def assign_stmt(self, children):
        target = str(children[0])
        value = next((c for c in children if isinstance(c, Expr)), None)
        if value is None:
            raise JockySyntaxError("malformed assignment")
        return AssignStmt(target=target, value=value)

    def if_stmt(self, children):
        cond = children[1]
        body = children[2]
        elifs = []
        else_body = None
        i = 3
        while i < len(children):
            if isinstance(children[i], Token) and children[i].type == "ELSE":
                else_body = children[i + 1]
                i += 2
            else:
                elifs.append((children[i + 1], children[i + 2]))
                i += 3
        return IfStmt(cond=cond, body=body, elifs=elifs, else_=else_body)

    def for_stmt(self, children):
        return ForStmt(var=str(children[1]), iterable=children[3], body=children[4])

    def while_stmt(self, children):
        cond = children[1]
        body = children[2]
        if isinstance(cond, LiteralExpr) and cond.type == "bool" and cond.value is True:
            raise JockySyntaxError("while true is prohibited: loops must be bounded")
        return WhileStmt(cond=cond, body=body)

    def return_stmt(self, children):
        value = children[1] if len(children) > 1 else None
        return ReturnStmt(value=value)

    def emit_stmt(self, children):
        value = children[1]
        label = ""
        if len(children) > 2:
            label = _unescape(str(children[2])[1:-1])
        return EmitStmt(value=value, label=label)

    def assert_stmt(self, children):
        cond = next((c for c in children if isinstance(c, Expr)), None)
        if cond is None:
            raise JockySyntaxError("malformed assert")
        message = ""
        for c in children:
            if isinstance(c, Token) and c.type == "STRING":
                message = _unescape(str(c)[1:-1])
        return AssertStmt(cond=cond, message=message)

    def fail_stmt(self, children):
        message = ""
        for c in children:
            if isinstance(c, Token) and c.type == "STRING":
                message = _unescape(str(c)[1:-1])
        return FailStmt(message=message)

    def expr_stmt(self, children):
        return ExprStmt(expr=children[0])

    def match_stmt(self, children):
        subject = children[1]
        cases = [c for c in children if isinstance(c, MatchCase)]
        return MatchStmt(subject=subject, cases=cases, has_default=any(c.pattern == "" for c in cases))

    def match_case(self, children):
        kind_tok = children[0]
        body = children[-1]
        if not isinstance(body, list):
            body = [body]
        if kind_tok.type == "DEFAULTS":
            return MatchCase(pattern="", body=body)
        return MatchCase(pattern=children[1], body=body)

    def pattern(self, children):
        tok = children[0]
        if tok.type in ("TRUE", "FALSE"):
            return LiteralExpr(type="bool", value=(tok.type == "TRUE"))
        if tok.type == "NONE":
            return LiteralExpr(type="none", value=None)
        if tok.type == "STRING":
            return LiteralExpr(type="string", value=_unescape(str(tok)[1:-1]))
        if tok.type == "INT":
            return LiteralExpr(type="int", value=int(str(tok)))
        if tok.type == "SIGNED_NUMBER":
            s = str(tok)
            try:
                return LiteralExpr(type="int", value=int(s))
            except ValueError:
                return LiteralExpr(type="float", value=float(s))
        if tok.type == "NAME":
            return NameExpr(name=str(tok))
        raise JockySyntaxError(f"unsupported pattern token {tok.type}")

    # ---- types ----------------------------------------------------------
    def type_expr(self, children):
        name = str(children[0])
        params: list[TypeRef] = []
        for c in children:
            if isinstance(c, TypeRef):
                params.append(c)
        return TypeRef(name, tuple(params))

    # ---- pipes ----------------------------------------------------------
    def expr(self, children):
        return children[0]

    def pipe_expr(self, children):
        lhs = children[0]
        ops = [c for c in children[1:] if isinstance(c, PipeOp)]
        if not ops:
            return lhs
        return PipeExpr(lhs=lhs, ops=ops)

    def pipe_apply(self, children):
        callable_node = children[1]
        name, args = callable_node
        return PipeOp(op="apply", arg={"name": name, "args": args or []})

    def callable(self, children):
        name = str(children[0])
        args = children[1] if len(children) > 1 else []
        return (name, args)

    def pipe_rest(self, children):
        return children[0] if children else None

    def pipe_filter(self, children):
        names = [c for c in children if isinstance(c, Token) and c.type == "NAME"]
        exprs = [c for c in children if isinstance(c, Expr)]
        if not names or not exprs:
            raise JockySyntaxError("malformed filter pipe")
        lam = LambdaExpr(params=[str(names[0])], body=exprs[-1])
        return PipeOp(op="filter", arg=lam)

    def pipe_filter_p(self, children):
        params = [str(c) for c in children if isinstance(c, Token) and c.type == "NAME"]
        body = children[-1]
        return PipeOp(op="filter", arg=LambdaExpr(params=params, body=body))

    def pipe_filter_i(self, children):
        return self.pipe_filter_p(children)

    def args(self, children):
        return children

    def arg_list(self, children):
        return children

    def pipe_param_op(self, children):
        names = [c for c in children if isinstance(c, Token) and c.type == "NAME"]
        if not names:
            raise JockySyntaxError("pipe operator requires a name")
        name = str(names[0])
        arg_slots = [c for c in children if isinstance(c, list)]
        args = arg_slots[0] if arg_slots else []
        if name not in ("group_by", "sort_by", "take", "dedupe", "sum", "count"):
            raise JockySyntaxError(f"unknown pipe operator '{name}'")
        return PipeOp(op=name, arg=args)

    def pipe_bare_verb(self, children):
        names = [c for c in children if isinstance(c, Token) and c.type == "NAME"]
        if not names:
            raise JockySyntaxError("bare pipe verb missing")
        name = str(names[0])
        if name not in ("sum", "count", "dedupe", "take"):
            raise JockySyntaxError(f"bare pipe verb '{name}' requires an argument")
        return PipeOp(op=name, arg=[] if name != "take" else [1])

    def pipe_sum(self, children):
        return PipeOp(op="sum")

    def pipe_count(self, children):
        return PipeOp(op="count")

    def pipe_take(self, children):
        tok = children[-1]
        return PipeOp(op="take", arg=int(str(tok)))

    def pipe_dedupe(self, children):
        return PipeOp(op="dedupe")

    # ---- booleans / arithmetic ------------------------------------------
    def disj(self, children):
        return self._fold_bin(children, "or")

    def conj(self, children):
        return self._fold_bin(children, "and")

    def neg(self, children):
        if len(children) == 2:
            return UnaryOpExpr(op="not", operand=children[1])
        return children[0]

    def comparison(self, children):
        ops, operands = [], []
        for c in children:
            if isinstance(c, Token):
                ops.append(str(c))
            else:
                operands.append(c)
        if len(operands) == 1:
            return operands[0]
        if len(ops) != len(operands) - 1:
            raise JockySyntaxError("malformed comparison")
        return CompareExpr(ops=ops, operands=operands)

    def arith(self, children):
        return self._fold_bin(children, None)

    def term(self, children):
        return self._fold_bin(children, None)

    def unary(self, children):
        if len(children) == 2:
            return UnaryOpExpr(op=str(children[0]), operand=children[1])
        return children[0]

    def power(self, children):
        if any(isinstance(c, Token) and c.type == "CARET" for c in children):
            operands = [c for c in children if isinstance(c, Expr)]
            if len(operands) == 2:
                return BinOpExpr(op="^", left=operands[0], right=operands[1])
        return children[0]

    @staticmethod
    def _fold_bin(children, fixed_op: str | None):
        if len(children) == 1:
            return children[0]
        if fixed_op:
            op = fixed_op
            out = children[0]
            for operand in children[1:]:
                out = BinOpExpr(op=op, left=out, right=operand)
            return out
        out = children[0]
        i = 1
        while i < len(children):
            op = str(children[i])
            out = BinOpExpr(op=op, left=out, right=children[i + 1])
            i += 2
        return out

    # ---- postfix --------------------------------------------------------
    def postfix_tail(self, children):
        return children[0] if children else None

    def postfix(self, children):
        out = children[0]
        for tail in children[1:]:
            if tail is None:
                continue
            if tail[0] == "field":
                out = FieldExpr(obj=out, field=tail[1])
            elif tail[0] == "index":
                out = SubscriptExpr(obj=out, key=tail[1])
            elif tail[0] == "cast":
                out = CastExpr(expr=out, to=tail[1])
            else:
                raise JockySyntaxError(f"unknown postfix {tail[0]}")
        return out

    def dot(self, children):
        return ("field", str(children[-1]))

    def index(self, children):
        exprs = [c for c in children if isinstance(c, Expr)]
        if not exprs:
            raise JockySyntaxError("index requires an expression")
        return ("index", exprs[-1])

    def ascast(self, children):
        types = [c for c in children if isinstance(c, TypeRef)]
        if not types:
            raise JockySyntaxError("cast requires a type")
        return ("cast", types[-1])

    # ---- atoms ----------------------------------------------------------
    def duration_lit(self, children):
        text = str(children[0])
        scale = {"ms": 0.001, "s": 1.0, "min": 60.0, "hr": 3600.0}
        for suffix, mult in scale.items():
            if text.endswith(suffix):
                return LiteralExpr(type="duration", value=int(text[: -len(suffix)]) * mult)
        raise JockySyntaxError(f"unrecognised duration literal {text}")

    def int_lit(self, children):
        return LiteralExpr(type="int", value=int(str(children[0])))

    def float(self, children):
        return LiteralExpr(type="float", value=float(str(children[0])))

    def string(self, children):
        text = _unescape(str(children[0])[1:-1])
        return LiteralExpr(type="string", value=text)

    def bytes(self, children):
        text = str(children[0])[2:-1]
        return LiteralExpr(type="bytes", value=_parse_bytes(text).hex())

    def true(self, children):
        return LiteralExpr(type="bool", value=True)

    def false(self, children):
        return LiteralExpr(type="bool", value=False)

    def none(self, children):
        return LiteralExpr(type="none", value=None)

    def name(self, children):
        return NameExpr(name=str(children[0]))

    def call(self, children):
        name = str(children[0])
        args = children[1] if len(children) > 1 else []
        return CallExpr(func=name, args=args)

    def args(self, children):
        return children

    def list_lit(self, children):
        items: list[Expr] = []
        for c in children:
            if isinstance(c, list):
                items.extend(c)
            elif isinstance(c, Expr):
                items.append(c)
        return ListExpr(items=items)

    def list_items(self, children):
        return children

    def map_lit(self, children):
        exprs = [c for c in children if isinstance(c, Expr)]
        for c in children:
            if isinstance(c, list):
                exprs.extend(c)
        pairs = []
        if exprs:
            it = iter(exprs)
            for k in it:
                v = next(it)
                pairs.append((k, v))
        return MapExpr(pairs=pairs)

    def map_items(self, children):
        return children

    def paren(self, children):
        exprs = [c for c in children if isinstance(c, Expr)]
        if not exprs:
            raise JockySyntaxError("parenthesised expression missing")
        return exprs[0]


_PARSER = Lark(
    JOCKY_GRAMMAR,
    parser="lalr",
    lexer="contextual",
    propagate_positions=True,
    start="start",
)


def parse(source: str) -> Program:
    """Parse JOCKY source into a typed AST Program (and run semantic checks)."""
    try:
        tree: Tree = _PARSER.parse(source)
    except ParseError as exc:
        raise JockySyntaxError(str(exc)) from exc
    prog = _Builder().transform(tree)
    from jocky.dsl.checker import validate

    return validate(prog)


__all__ = ["parse", "Program", "JockySyntaxError", "KEYWORDS"]