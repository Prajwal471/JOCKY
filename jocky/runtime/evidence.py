"""Least-privilege evidence signing for JOCKY v0.1.

Every emitted evidence record is bound to a canonical JSON payload and to
the ongoing chain state (index, previous anchor, mission JIR digest). The
record is Ed25519-signed with the agent key so receivers can authenticate
who produced the evidence and that it was not altered in transit.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from jocky.config import KEYS_DIR

JIR_CHAIN_ALGORITHM = "sha256"


def canonical_bytes(obj: Any) -> bytes:
    """Stable, minimal JSON serialization for digesting."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


class Ed25519Signer:
    """Ed25519 signer backed by a persistent agent key on disk."""

    def __init__(self, key_path: Path | None = None):
        self.key_path = key_path or (KEYS_DIR / "agent_ed25519.pem")
        self.private: Ed25519PrivateKey = self._load_or_create()
        self.public_key_hex = self._public_hex()

    def _load_or_create(self) -> Ed25519PrivateKey:
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if self.key_path.exists():
            data = self.key_path.read_bytes()
            return serialization.load_pem_private_key(data, password=None)  # type: ignore[return-value]
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.key_path.write_bytes(pem)
        return key

    def _public_hex(self) -> str:
        pub = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub.hex()

    def sign(self, payload: bytes) -> tuple[str, str]:
        sig = self.private.sign(payload)
        return sig.hex(), self.public_key_hex


def sign_evidence_record(
    *,
    finding_type: str,
    source: str,
    payload: dict[str, Any],
    privileges: str,
    capability: str,
    chain_index: int,
    prev_hash: str,
    mission_digest: str,
    signer: Ed25519Signer,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Build a signed evidence record ready to persist into EvidenceRecord."""
    payload["_mission_digest"] = mission_digest
    nonce = nonce or secrets.token_hex(8)
    payload["_nonce"] = nonce
    payload_sha256 = sha256_bytes(payload)
    record = {
        "finding_type": finding_type,
        "source": source,
        "privileges": privileges,
        "payload": payload,
        "payload_sha256": payload_sha256,
        "chain_index": chain_index,
        "prev_hash": prev_hash,
        "chain_hash": "",
        "capability": capability,
        "signature": "",
        "signed_by": "",
    }
    chain_hash = sha256_bytes(
        {
            "index": chain_index,
            "prev": prev_hash,
            "payload_sha256": payload_sha256,
            "mission": mission_digest,
        }
    )
    record["chain_hash"] = chain_hash
    signed_blob = canonical_bytes(
        {"chain_hash": chain_hash, "payload_sha256": payload_sha256, "prev": prev_hash}
    )
    sig_hex, pub_hex = signer.sign(signed_blob)
    record["signature"] = sig_hex
    record["signed_by"] = pub_hex
    return record


def verify_record(record: dict[str, Any], public_key_hex: str) -> bool:
    """Recompute and verify a persisted evidence record (Block 9, P4/P5).

    Checks, in order: the payload digest, the chain hash, then the Ed25519
    signature over the canonical signed blob. Returns True only if all three
    reproduce.  ``record`` must carry the fields persisted by
    :class:`jocky.server.db.EvidenceRecord`.
    """
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return False
    if sha256_bytes(payload) != record.get("payload_sha256"):
        return False
    chain_hash = sha256_bytes(
        {
            "index": record["chain_index"],
            "prev": record["prev_hash"],
            "payload_sha256": record["payload_sha256"],
            "mission": payload.get("_mission_digest", ""),
        }
    )
    if chain_hash != record.get("chain_hash"):
        return False
    signed_blob = canonical_bytes(
        {
            "chain_hash": chain_hash,
            "payload_sha256": record["payload_sha256"],
            "prev": record["prev_hash"],
        }
    )
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(record["signature"]), signed_blob)
    except Exception:
        return False
    return True


def harvest_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip evidence-injected fields so two harvests of identical host state
    can be compared byte-for-byte (Block 9, P6 collection determinism)."""
    return {
        k: v
        for k, v in payload.items()
        if k not in {"_mission_digest", "_nonce"}
    }


__all__ = [
    "canonical_bytes",
    "sha256_bytes",
    "Ed25519Signer",
    "sign_evidence_record",
    "verify_record",
    "harvest_payload",
    "JIR_CHAIN_ALGORITHM",
]