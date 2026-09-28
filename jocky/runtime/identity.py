"""Mission identity and JIR pinning for JOCKY v0.1.

A mission is not just a program -- it is an authorization.  A requester
holds an Ed25519 keypair (their JOCKY identity).  For every mission they
hand to the agent they bind their public key to the mission's canonical
JIR digest, list the capabilities the mission is authorized to use and the
purpose the requester declares.  The signed mission card lets the agent (and
any external verifier) confirm that:

  * the mission's JIR digest has not drifted (JIR pinning), and
  * mission @requires never exceeds the card's authorized capabilities.

Evidence chain anchors (evidence.chain_hash) already fix the mission JIR
digest; the card binds that digest to an identity so receivers can also
answer "who asked for this evidence and under what authorization".
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from jocky.runtime.evidence import Ed25519Signer, canonical_bytes, sha256_bytes

MISSION_CARD_ALGORITHM = "ed25519"
MISSION_CARD_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


@dataclass(frozen=True)
class MissionCard:
    """Signed authorization binding a requester identity to a mission digest."""

    version: int
    algorithm: str
    mission_digest: str
    requester_public_key: str
    capabilities: tuple[str, ...]
    purpose: str
    issued_at: str
    expires_at: str
    nonce: str
    signature: str

    def verify(self) -> bool:
        body = card_signable(self)
        pub_hex = self.requester_public_key
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            pub.verify(bytes.fromhex(self.signature), body)
        except Exception:
            return False
        if _parse_iso(self.expires_at) < datetime.now(timezone.utc):
            return False
        return True

    def authorizes(self, requires: set[str]) -> bool:
        return requires <= set(self.capabilities)


def card_signable(card: MissionCard) -> bytes:
    doc = {
        "version": card.version,
        "algorithm": card.algorithm,
        "mission_digest": card.mission_digest,
        "requester_public_key": card.requester_public_key,
        "capabilities": sorted(card.capabilities),
        "purpose": card.purpose,
        "issued_at": card.issued_at,
        "expires_at": card.expires_at,
        "nonce": card.nonce,
    }
    return canonical_bytes(doc)


def issue_mission_card(
    *,
    signer: Ed25519Signer,
    mission_digest: str,
    capabilities: list[str],
    purpose: str,
    ttl_hours: int = 24,
) -> MissionCard:
    """Issue a signed mission card for the requester's identity."""
    now = datetime.now(timezone.utc)
    card = MissionCard(
        version=MISSION_CARD_VERSION,
        algorithm=MISSION_CARD_ALGORITHM,
        mission_digest=mission_digest,
        requester_public_key=signer.public_key_hex,
        capabilities=tuple(sorted(set(capabilities))),
        purpose=purpose,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=ttl_hours)).isoformat(),
        nonce=secrets.token_hex(8),
        signature="",
    )
    sig_hex, _ = signer.sign(card_signable(card))
    return MissionCard(**{**card.__dict__, "signature": sig_hex})


def mission_card_to_dict(card: MissionCard) -> dict[str, Any]:
    return {
        "version": card.version,
        "algorithm": card.algorithm,
        "mission_digest": card.mission_digest,
        "requester_public_key": card.requester_public_key,
        "capabilities": list(card.capabilities),
        "purpose": card.purpose,
        "issued_at": card.issued_at,
        "expires_at": card.expires_at,
        "nonce": card.nonce,
        "signature": card.signature,
    }


def mission_card_from_dict(data: dict[str, Any]) -> MissionCard:
    return MissionCard(
        version=data["version"],
        algorithm=data["algorithm"],
        mission_digest=data["mission_digest"],
        requester_public_key=data["requester_public_key"],
        capabilities=tuple(data["capabilities"]),
        purpose=data["purpose"],
        issued_at=data["issued_at"],
        expires_at=data["expires_at"],
        nonce=data["nonce"],
        signature=data["signature"],
    )


__all__ = [
    "MissionCard",
    "issue_mission_card",
    "mission_card_to_dict",
    "mission_card_from_dict",
    "card_signable",
    "MISSION_CARD_ALGORITHM",
    "MISSION_CARD_VERSION",
]