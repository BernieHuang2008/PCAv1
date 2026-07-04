from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .constants import ED25519_SEED_BYTES, ED25519_SIGNATURE_BYTES
from .encoding import ensure_bytes_length, validate_iso8601_z, validate_namespace
from .errors import PCAAuthenticationError, PCAValidationError
from .jcs import canonicalize_bytes


@dataclass(frozen=True)
class RevocationCheck:
    revoked: bool
    ignored: bool
    reason: str
    successor_namespace_hint: str | None = None


def generate_emergency_private_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def private_key_from_seed(seed: bytes) -> ed25519.Ed25519PrivateKey:
    ensure_bytes_length(seed, ED25519_SEED_BYTES, "Ed25519 private seed")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def raw_public_key_b64(private_key: ed25519.Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def sign_revocation_statement(
    private_seed: bytes,
    namespace: str,
    revoked_at: str,
    reason: str,
    successor_namespace_hint: str | None = None,
) -> dict[str, Any]:
    validate_namespace(namespace)
    validate_iso8601_z(revoked_at, "revoked_at")
    if not isinstance(reason, str) or not reason:
        raise PCAValidationError("reason must be a non-empty string")
    payload: dict[str, Any] = {
        "namespace": namespace,
        "reason": reason,
        "revoked_at": revoked_at,
        "version": 1,
    }
    if successor_namespace_hint is not None:
        validate_namespace(successor_namespace_hint)
        payload["successor_namespace_hint"] = successor_namespace_hint
    private_key = private_key_from_seed(private_seed)
    signature = private_key.sign(canonicalize_bytes(payload))
    signed = dict(payload)
    signed["signature"] = base64.b64encode(signature).decode("ascii")
    return signed


def verify_revocation_statement(
    statement: dict[str, Any], trusted_namespace: str, emergency_public_key_b64: str
) -> RevocationCheck:
    validate_namespace(trusted_namespace)
    if not isinstance(statement, dict):
        raise PCAValidationError("revocation statement must be a JSON object")
    statement_namespace = statement.get("namespace")
    if statement_namespace != trusted_namespace:
        return RevocationCheck(revoked=False, ignored=True, reason="namespace mismatch")
    validate_namespace(statement_namespace)
    signature_b64 = statement.get("signature")
    if not isinstance(signature_b64, str):
        raise PCAValidationError("revocation statement signature is required")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key_bytes = base64.b64decode(emergency_public_key_b64, validate=True)
    except Exception as exc:
        raise PCAValidationError("revocation key and signature must be valid Base64") from exc
    ensure_bytes_length(signature, ED25519_SIGNATURE_BYTES, "Ed25519 signature")
    ensure_bytes_length(public_key_bytes, ED25519_SEED_BYTES, "Ed25519 public key")
    payload = dict(statement)
    del payload["signature"]
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature, canonicalize_bytes(payload))
    except InvalidSignature as exc:
        raise PCAAuthenticationError("revocation signature is invalid") from exc
    hint = statement.get("successor_namespace_hint")
    if hint is not None:
        validate_namespace(hint)
    return RevocationCheck(
        revoked=True,
        ignored=False,
        reason="namespace revoked",
        successor_namespace_hint=hint,
    )

