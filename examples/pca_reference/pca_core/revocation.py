from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .constants import ED25519_SEED_BYTES, ED25519_SIGNATURE_BYTES
from .encoding import ensure_bytes_length, validate_iso8601_z, validate_namespace
from .errors import PCAAuthenticationError, PCARevokedNamespaceError, PCAValidationError
from .jcs import canonicalize_bytes
from .trust import resolve_hardcoded_namespace

_REQUIRED_FIELDS = {"namespace", "reason", "revoked_at", "signature", "version"}
_OPTIONAL_FIELDS = {"successor_namespace_hint"}
EXAMPLE_EMERGENCY_REVOCATION_PUBLIC_KEY = "EXAMPLE"
HARDCODED_EMERGENCY_REVOCATION_PUBLIC_KEY: str | None = EXAMPLE_EMERGENCY_REVOCATION_PUBLIC_KEY


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


def _public_key_from_b64(public_key_b64: str) -> ed25519.Ed25519PublicKey:
    try:
        public_key_bytes = base64.b64decode(public_key_b64, validate=True)
    except Exception as exc:
        raise PCAValidationError("emergency revocation public key must be valid Base64") from exc
    ensure_bytes_length(public_key_bytes, ED25519_SEED_BYTES, "Ed25519 public key")
    return ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)


def set_hardcoded_emergency_revocation_public_key(public_key_b64: str | None) -> None:
    if public_key_b64 is not None and public_key_b64 != EXAMPLE_EMERGENCY_REVOCATION_PUBLIC_KEY:
        _public_key_from_b64(public_key_b64)
    global HARDCODED_EMERGENCY_REVOCATION_PUBLIC_KEY
    HARDCODED_EMERGENCY_REVOCATION_PUBLIC_KEY = public_key_b64


def _resolve_emergency_revocation_public_key(
    emergency_public_key_b64: str | None,
    hardcoded_emergency_revocation_public_key: str | None,
) -> ed25519.Ed25519PublicKey | None:
    configured_key = (
        hardcoded_emergency_revocation_public_key
        if hardcoded_emergency_revocation_public_key is not None
        else HARDCODED_EMERGENCY_REVOCATION_PUBLIC_KEY
    )
    if configured_key == EXAMPLE_EMERGENCY_REVOCATION_PUBLIC_KEY:
        if emergency_public_key_b64 is None:
            return None
        return _public_key_from_b64(emergency_public_key_b64)
    if configured_key is None:
        raise PCAValidationError(
            "HARDCODED_EMERGENCY_REVOCATION_PUBLIC_KEY must be set to an emergency public key or EXAMPLE"
        )
    return _public_key_from_b64(configured_key)


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
    statement: dict[str, Any],
    trusted_namespace: str | None = None,
    emergency_public_key_b64: str | None = None,
    *,
    hardcoded_namespace: str | None = None,
    hardcoded_emergency_revocation_public_key: str | None = None,
) -> RevocationCheck:
    trusted_namespace = resolve_hardcoded_namespace(trusted_namespace, hardcoded_namespace)
    if not isinstance(statement, dict):
        raise PCAValidationError("revocation statement must be a JSON object")
    statement_namespace = statement.get("namespace")
    if statement_namespace != trusted_namespace:
        return RevocationCheck(revoked=False, ignored=True, reason="namespace mismatch")
    validate_namespace(statement_namespace)
    fields = set(statement)
    allowed_fields = _REQUIRED_FIELDS | _OPTIONAL_FIELDS
    if fields - allowed_fields:
        raise PCAValidationError("revocation statement contains unsupported fields")
    if not _REQUIRED_FIELDS.issubset(fields):
        raise PCAValidationError("revocation statement is missing required fields")
    if statement.get("version") != 1:
        raise PCAValidationError("revocation statement version must be 1")
    validate_iso8601_z(statement.get("revoked_at"), "revoked_at")
    if not isinstance(statement.get("reason"), str) or not statement["reason"]:
        raise PCAValidationError("revocation statement reason must be a non-empty string")
    signature_b64 = statement.get("signature")
    if not isinstance(signature_b64, str):
        raise PCAValidationError("revocation statement signature is required")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise PCAValidationError("revocation signature must be valid Base64") from exc
    ensure_bytes_length(signature, ED25519_SIGNATURE_BYTES, "Ed25519 signature")
    payload = dict(statement)
    del payload["signature"]
    public_key = _resolve_emergency_revocation_public_key(
        emergency_public_key_b64,
        hardcoded_emergency_revocation_public_key,
    )
    if public_key is None:
        hint = statement.get("successor_namespace_hint")
        if hint is not None:
            validate_namespace(hint)
        return RevocationCheck(
            revoked=True,
            ignored=False,
            reason="namespace revoked",
            successor_namespace_hint=hint,
        )
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


def require_namespace_not_revoked(
    statement: dict[str, Any] | None,
    trusted_namespace: str | None,
    emergency_public_key_b64: str | None,
    *,
    hardcoded_namespace: str | None = None,
    hardcoded_emergency_revocation_public_key: str | None = None,
) -> None:
    """Reject operational use of a namespace once a valid revocation is known."""
    if statement is None:
        return
    check = verify_revocation_statement(
        statement,
        trusted_namespace,
        emergency_public_key_b64,
        hardcoded_namespace=hardcoded_namespace,
        hardcoded_emergency_revocation_public_key=hardcoded_emergency_revocation_public_key,
    )
    if check.revoked:
        raise PCARevokedNamespaceError("namespace is revoked; refuse subsequent PCA operations")
