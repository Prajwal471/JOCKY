"""Lark grammar for JOCKY v0.1.

The reserved-keyword set is exactly the 34 keywords named by the language
spec. Statement terminator is ``;`` (explicit); braces delimit blocks.
Whitespace and newlines are insignificant.
"""

from __future__ import annotations

JOCKY_GRAMMAR = r"""
start: program

program: item*

// ------------------------------------------------------------------ units
item: deco* (unit_def | fn_def)

unit_def: mission_def | experiment_def

mission_def: MISSION STRING "{" unit_item* "}"
experiment_def: EXPERIMENT STRING "{" unit_item* "}"
unit_item: deco* (fn_def | stmt)

deco: DECO REQUIRE "(" cap ("," cap)* ")"      -> deco_requires
    | DECO PURPOSE STRING                      -> deco_purpose

cap: NAME (":" NAME)?

fn_def: FN NAME "(" params? ")" (RARROW type_expr)? block
params: param ("," param)*
param: NAME (":" type_expr)?
block: "{" stmt* "}"

stmt: LET NAME (":" type_expr)? "=" expr ";"  -> let_stmt
    | NAME "=" expr ";"                        -> assign_stmt
    | IF expr block (ELIF expr block)* (ELSE block)?  -> if_stmt
    | FOR NAME IN expr block                   -> for_stmt
    | WHILE expr block                         -> while_stmt
    | RETURN expr? ";"                         -> return_stmt
    | EMIT expr STRING? ";"                    -> emit_stmt
    | ASSERT expr ("," STRING)? ";"            -> assert_stmt
    | FAIL STRING? ";"                         -> fail_stmt
    | MATCH expr "{" match_case* "}"           -> match_stmt
    | expr ";"                                 -> expr_stmt

match_case: (CASE pattern ARROW | DEFAULTS ARROW) (block | stmt)
pattern: "_" | STRING | INT | SIGNED_NUMBER | NAME | TRUE | FALSE | NONE

// ------------------------------------------------------------------ types
type_expr: NAME (LT type_expr ("," type_expr)* GT)?

// --------------------------------------------------------------- pipes
expr: pipe_expr

pipe_expr: disj pipe_rest*

pipe_rest: PIPE2 callable                             -> pipe_apply
    | "|" NAME ARROW expr                        -> pipe_filter
    | "|" "(" NAME ("," NAME)* ")" ARROW expr    -> pipe_filter_p
    | "|" "(" NAME ("," NAME)* ARROW expr ")"    -> pipe_filter_i
    | "|" NAME "(" args? ")"                    -> pipe_param_op
    | "|" NAME                                   -> pipe_bare_verb
    | PIPESUM                                    -> pipe_sum
    | PIPECOUNT                                  -> pipe_count
    | PIPE_TAKE (NAME | INT)                     -> pipe_take
    | PIPEDEDUPE                                 -> pipe_dedupe

callable: NAME ("(" args? ")")?

// --------------------------------------------------------- booleans/arith
disj: conj (OR conj)*
conj: neg (AND neg)*
neg: NOT neg | comparison

comparison: arith ((EQ | NE | LT | LE | GT | GE) arith)*
arith: term ((PLUS | MINUS) term)*
term: unary ((TIMES | FLOORDIV | DIVIDE | PERCENT) unary)*
unary: (MINUS | PLUS) unary | power
power: postfix (CARET unary)?
postfix: atomic postfix_tail*

postfix_tail: "." NAME            -> dot
    | "[" expr "]"        -> index
    | AS type_expr        -> ascast

atomic: DURATION                         -> duration_lit
    | INT                              -> int_lit
    | FLOAT                            -> float
    | STRING                           -> string
    | BYTES                            -> bytes
    | TRUE                             -> true
    | FALSE                            -> false
    | NONE                             -> none
    | NAME "(" args? ")"               -> call
    | NAME                             -> name
    | "[" list_items? "]"                 -> list_lit
    | "{" map_items? "}"                  -> map_lit
    | "(" expr ")"                        -> paren

list_items: expr ("," expr)*

map_items: expr ":" expr ("," expr ":" expr)*

args: expr ("," expr)*

// ----------------------------------------------------------------- tokens
%ignore WS_INLINE
%ignore NEWLINE
%ignore COMMENT

COMMENT: /\#[^\n]*/
WS_INLINE: /[ \t\f\v]+/
NEWLINE: /\n/
DECO: "@"

LET.100: "let"
FN.100: "fn"
MISSION.100: "mission"
EXPERIMENT.100: "experiment"
IF.100: "if"
ELIF.100: "elif"
ELSE.100: "else"
FOR.100: "for"
IN.100: "in"
WHILE.100: "while"
RETURN.100: "return"
EMIT.100: "emit"
ASSERT.100: "assert"
FAIL.100: "fail"
MATCH.100: "match"
CASE.100: "case"
DEFAULTS.100: "default"
AND.100: "and"
OR.100: "or"
NOT.100: "not"
AS.100: "as"
REQUIRE.100: "requires"
PURPOSE.100: "purpose"
TRUE.100: "true"
FALSE.100: "false"
NONE.100: "none"

PIPE2.101: "|>"
PIPESUM.101: "|sum"
PIPECOUNT.101: "|count"
PIPE_TAKE.101: "|take"
PIPEDEDUPE.101: "|dedupe"

ARROW.102: "=>"
RARROW.102: "->"

EQ: "=="
NE: "!="
LT: "<"
LE: "<="
GT: ">"
GE: ">="
ASSIGN: "="
PLUS: "+"
MINUS: "-"
TIMES: "*"
DIVIDE: "/"
PERCENT: "%"
FLOORDIV: "//"
CARET: "^"

CAP: /[a-z][a-z0-9_]*\:[a-z][a-z0-9_]*/
NAME.80: /[A-Za-z_][A-Za-z0-9_]*/
INT: /\d+/
DURATION: /\d+(ms|s|min|hr)/
FLOAT: /\d+\.\d+([eE][+-]?\d+)?|\d+[eE][+-]?\d+/
SIGNED_NUMBER: /[+-]?\d+(\.\d+)?([eE][+-]?\d+)?/
STRING: /"(?:\\.|[^"\\])*"/
BYTES: /b"(?:\\.|[^"\\])*"/
"""

KEYWORDS: tuple[str, ...] = (
    "let", "fn", "mission", "experiment", "if", "elif", "else", "for", "in",
    "while", "return", "emit", "assert", "fail", "match", "case", "default",
    "and", "or", "not", "as", "requires", "purpose",
    "true", "false", "none",
    "|>", "|sum", "|count", "|take", "|group_by", "|sort_by", "|dedupe", "=>",
)

assert len(KEYWORDS) == 34, f"expect 34 keywords, got {len(KEYWORDS)}"