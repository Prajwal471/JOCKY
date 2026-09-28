"""AST for JOCKY v0.1.

Pydantic models with ``kind`` discriminators so the tree serializes to a
canonical, schema-stable JIR that both the Python compiler and the Rust
agent can consume.

Nodes are pure data: no logic beyond validation lives here.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from jocky.dsl.types import TypeRef


def _span_factory() -> tuple[int, int]:
    return (0, 0)


class Node(BaseModel):
    """Base AST node. All models are frozen for hashability / canonicity."""

    span: tuple[int, int] = Field(default_factory=_span_factory)

    model_config = ConfigDict(frozen=True, extra="forbid")


# --------------------------------------------------------------------------
# Expressions
# --------------------------------------------------------------------------


class Expr(Node):
    kind: str


class LiteralExpr(Expr):
    kind: Literal["literal"] = "literal"
    type: str
    value: Any


class NameExpr(Expr):
    kind: Literal["name"] = "name"
    name: str


class BinOpExpr(Expr):
    kind: Literal["binop"] = "binop"
    op: str
    left: Expr
    right: Expr


class UnaryOpExpr(Expr):
    kind: Literal["unary"] = "unary"
    op: str
    operand: Expr


class CompareExpr(Expr):
    kind: Literal["compare"] = "compare"
    ops: list[str]
    operands: list[Expr]


class FieldExpr(Expr):
    kind: Literal["field"] = "field"
    obj: Expr
    field: str


class SubscriptExpr(Expr):
    kind: Literal["subscript"] = "subscript"
    obj: Expr
    key: Expr


class CallExpr(Expr):
    kind: Literal["call"] = "call"
    func: str
    args: list[Expr] = Field(default_factory=list)


class CastExpr(Expr):
    kind: Literal["cast"] = "cast"
    expr: Expr
    to: TypeRef
    explicit: bool = True


class ListExpr(Expr):
    kind: Literal["list"] = "list"
    items: list[Expr] = Field(default_factory=list)


class SetExpr(Expr):
    kind: Literal["set"] = "set"
    items: list[Expr] = Field(default_factory=list)


class MapExpr(Expr):
    kind: Literal["map"] = "map"
    pairs: list[tuple[Expr, Expr]] = Field(default_factory=list)


class LambdaExpr(Expr):
    kind: Literal["lambda"] = "lambda"
    params: list[str]
    body: Expr = Field(default_factory=NameExpr, validate_default=False)


class IfExpr(Expr):
    kind: Literal["ifexpr"] = "ifexpr"
    cond: Expr
    then: Expr
    else_: Expr


# --------------------------------------------------------------------------
# Pipe operators (surface syntax desugars these into PipeExpr nodes)
# --------------------------------------------------------------------------


class PipeOp(Node):
    op: str  # apply | filter | sum | count | take | group_by | sort_by | dedupe
    arg: Any = None  # target name (apply), lambda (filter), name/index, int, bool


class PipeExpr(Expr):
    kind: Literal["pipe"] = "pipe"
    lhs: Expr
    ops: list[PipeOp] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Statements
# --------------------------------------------------------------------------


class Stmt(Node):
    kind: str


class LetStmt(Stmt):
    kind: Literal["let"] = "let"
    name: str
    annotation: TypeRef | None = None
    value: Expr


class AssignStmt(Stmt):
    kind: Literal["assign"] = "assign"
    target: str
    value: Expr


class ExprStmt(Stmt):
    kind: Literal["expr_stmt"] = "expr_stmt"
    expr: Expr


class IfStmt(Stmt):
    kind: Literal["if"] = "if"
    cond: Expr
    body: list[Stmt]
    elifs: list[tuple[Expr, list[Stmt]]] = Field(default_factory=list)
    else_: list[Stmt] | None = None


class ForStmt(Stmt):
    kind: Literal["for"] = "for"
    var: str
    iterable: Expr
    body: list[Stmt]


class WhileStmt(Stmt):
    kind: Literal["while"] = "while"
    cond: Expr
    body: list[Stmt]


class EmitStmt(Stmt):
    kind: Literal["emit"] = "emit"
    value: Expr
    label: str = ""


class AssertStmt(Stmt):
    kind: Literal["assert"] = "assert"
    cond: Expr
    message: str = ""


class FailStmt(Stmt):
    kind: Literal["fail"] = "fail"
    message: str = ""


class ReturnStmt(Stmt):
    kind: Literal["return"] = "return"
    value: Expr | None = None


class MatchCase(Node):
    pattern: Expr | str  # literal expression, free name, or "default"
    body: list[Stmt]


class MatchStmt(Stmt):
    kind: Literal["match"] = "match"
    subject: Expr
    cases: list[MatchCase]
    has_default: bool = False


# --------------------------------------------------------------------------
# Top-level units
# --------------------------------------------------------------------------


class FunctionDef(Node):
    kind: Literal["fn"] = "fn"
    name: str
    params: list[tuple[str, TypeRef | None]] = Field(default_factory=list)
    returns: TypeRef | None = None
    requires: list[str] = Field(default_factory=list)
    purpose: str = ""
    body: list[Stmt]


class UnitDef(Node):
    """A ``mission`` (executable) or ``experiment`` (controlled evaluation)."""

    kind: Literal["mission", "experiment"]
    name: str
    purpose: str = ""
    requires: list[str] = Field(default_factory=list)
    body: list[Stmt]


class Program(Node):
    kind: Literal["program"] = "program"
    name: str
    units: list[UnitDef] = Field(default_factory=list)
    functions: list[FunctionDef] = Field(default_factory=list)

    def all_requires(self) -> list[str]:
        seen: list[str] = []
        for u in self.units:
            for c in u.requires:
                if c not in seen:
                    seen.append(c)
        for f in self.functions:
            for c in f.requires:
                if c not in seen:
                    seen.append(c)
        return seen