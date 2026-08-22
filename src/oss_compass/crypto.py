"""Small, explicit Ed25519 helpers used by PVC-U protocol v2.

Private keys are encoded as URL-safe base64 of the 32-byte Ed25519 seed. Public
keys are URL-safe base64 of the 32-byte raw public key. These helpers do not
store, rotate or transmit private key material.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json(value: Any) -> bytes:
    """Produce the byte-for-byte representation covered by signatures and hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str, *, expected_size: int) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("key material must be URL-safe base64") from exc
    if len(raw) != expected_size:
        raise ValueError(f"key material must contain exactly {expected_size} bytes")
    return raw


def generate_keypair() -> tuple[str, str]:
    """Generate a private/public Ed25519 pair for provisioning outside the repository."""
    private_key = Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _encode(private_raw), _encode(public_raw)


def public_key_for(private_key: str) -> str:
    private = Ed25519PrivateKey.from_private_bytes(_decode(private_key, expected_size=32))
    return _encode(private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))


def key_fingerprint(public_key: str) -> str:
    """Return a short SHA-256 key identifier suitable for logs and receipts."""
    return hashlib.sha256(_decode(public_key, expected_size=32)).hexdigest()[:16]


def sign_payload(private_key: str, payload: Any) -> str:
    signer = Ed25519PrivateKey.from_private_bytes(_decode(private_key, expected_size=32))
    return _encode(signer.sign(canonical_json(payload)))


def verify_payload(public_key: str, payload: Any, signature: str) -> bool:
    try:
        verifier = Ed25519PublicKey.from_public_bytes(_decode(public_key, expected_size=32))
        verifier.verify(_decode(signature, expected_size=64), canonical_json(payload))
        return True
    except (InvalidSignature, ValueError):
        return False
