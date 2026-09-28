"""Tests for mission identity, JIR pinning and chain anchors."""

from __future__ import annotations

import pytest

from jocky.dsl.jir import digest
from jocky.dsl.parser import parse
from jocky.runtime.evidence import Ed25519Signer
from jocky.runtime.identity import (
    issue_mission_card,
    mission_card_from_dict,
    mission_card_to_dict,
    card_signable,
)


def test_mission_digest_is_pinned_by_signed_card(tmp_path):
    prog = parse(
        '\n@requires(process:list)\nmission "Pin" {\n  let p = collect_processes();\n  emit p |count;\n}\n'
    )
    signer = Ed25519Signer(key_path=tmp_path / "requester.pem")
    card = issue_mission_card(
        signer=signer,
        mission_digest=digest(prog),
        capabilities=["process:list"],
        purpose="defense lab",
    )
    assert card.verify()
    assert card.authorizes({"process:list"})


def test_tampered_digest_fails_verification(tmp_path):
    signer = Ed25519Signer(key_path=tmp_path / "req2.pem")
    card = issue_mission_card(
        signer=signer, mission_digest="a" * 64, capabilities=["service:list"], purpose="p"
    )
    forged = mission_card_from_dict(
        {**mission_card_to_dict(card), "mission_digest": "b" * 64}
    )
    assert not forged.verify()


def test_capability_escalation_blocked(tmp_path):
    signer = Ed25519Signer(key_path=tmp_path / "req3.pem")
    card = issue_mission_card(
        signer=signer, mission_digest="a" * 64, capabilities=["process:list"], purpose="p"
    )
    assert not card.authorizes({"process:list", "network:analyze"})


def test_expired_card_rejected(tmp_path):
    signer = Ed25519Signer(key_path=tmp_path / "req4.pem")
    card = issue_mission_card(
        signer=signer, mission_digest="a" * 64, capabilities=["process:list"], purpose="p"
    )
    from jocky.runtime.identity import _parse_iso, _now_iso

    expired = mission_card_from_dict(
        {**mission_card_to_dict(card), "expires_at": "2020-01-01T00:00:00+00:00"}
    )
    assert not expired.verify()


def test_card_roundtrip_dict_stable(tmp_path):
    signer = Ed25519Signer(key_path=tmp_path / "req5.pem")
    card = issue_mission_card(
        signer=signer, mission_digest="a" * 64, capabilities=["event:read", "process:list"], purpose="p"
    )
    assert card_signable(mission_card_from_dict(mission_card_to_dict(card))) == card_signable(card)


from jocky.dsl.parser import parse
from jocky.runtime.interpreter import run_mission


def _untyped_src(name: str, n: int, caps: str) -> str:
    return f'\n@requires({caps})\nmission "{name}" {{\n  let i = {n};\n  let acc = 0;\n  while i > 0 {{ acc = acc + i; i = i - 1; }}\n  emit acc;\n}}\n'


def test_run_accepts_signed_card(tmp_path):
    src = _untyped_src("CardOK", 3, "process:list")
    prog = parse(src)
    card = issue_mission_card(
        signer=Ed25519Signer(key_path=tmp_path / "ok.pem"),
        mission_digest=digest(prog),
        capabilities=["process:list"],
        purpose="defense lab",
    )
    run = run_mission(prog, prog.units[0], mission_card=card)
    assert run.error is None
    assert run.card_verified
    assert run.emitted[0]["value"] == 6


def test_run_rejects_escalation_beyond_card(tmp_path):
    prog = parse(_untyped_src("CardEsc", 1, "network:analyze"))
    card = issue_mission_card(
        signer=Ed25519Signer(key_path=tmp_path / "esc.pem"),
        mission_digest=digest(prog),
        capabilities=["process:list"],
        purpose="defense lab",
    )
    run = run_mission(prog, prog.units[0], mission_card=card)
    assert "beyond the signed mission card" in run.error


def test_run_rejects_jir_drift(tmp_path):
    prog = parse(_untyped_src("CardDrift", 1, "process:list"))
    card = issue_mission_card(
        signer=Ed25519Signer(key_path=tmp_path / "drift.pem"),
        mission_digest="f" * 64,
        capabilities=["process:list"],
        purpose="defense lab",
    )
    run = run_mission(prog, prog.units[0], mission_card=card)
    assert "JIR drift" in run.error