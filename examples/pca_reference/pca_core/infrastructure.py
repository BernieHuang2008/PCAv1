from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .constants import ED25519_SEED_BYTES, ED25519_SIGNATURE_BYTES
from .encoding import ensure_bytes_length, validate_iso8601_z
from .errors import PCAAuthenticationError, PCAValidationError
from .jcs import canonicalize_bytes

PCA_INFRASTRUCTURE_PATH = "Identity/V1/PCA"
_INFRA_SIGNATURE_FIELD = "signature"


def _decode_b64(value: str, expected_len: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise PCAValidationError(f"{field} must be a Base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise PCAValidationError(f"{field} must be valid Base64") from exc
    return ensure_bytes_length(decoded, expected_len, field)


def public_key_from_b64(public_key_b64: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(
        _decode_b64(public_key_b64, ED25519_SEED_BYTES, "Ed25519 public key")
    )


def signature_from_b64(signature_b64: str) -> bytes:
    return _decode_b64(signature_b64, ED25519_SIGNATURE_BYTES, "Ed25519 signature")


def private_key_from_seed(seed: bytes) -> ed25519.Ed25519PrivateKey:
    ensure_bytes_length(seed, ED25519_SEED_BYTES, "Ed25519 private seed")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def require_pca_signer_path(signer_path: Any) -> str:
    if signer_path != PCA_INFRASTRUCTURE_PATH:
        raise PCAValidationError("signer_path must be Identity/V1/PCA in this reference implementation")
    return signer_path


def sign_infrastructure_statement(private_seed: bytes, payload: dict[str, Any]) -> dict[str, Any]:
    if _INFRA_SIGNATURE_FIELD in payload:
        raise PCAValidationError("payload must not already contain signature")
    require_pca_signer_path(payload.get("signer_path"))
    issued_at = payload.get("issued_at")
    if issued_at is not None:
        validate_iso8601_z(issued_at, "issued_at")
    signature = private_key_from_seed(private_seed).sign(canonicalize_bytes(payload))
    signed = dict(payload)
    signed[_INFRA_SIGNATURE_FIELD] = base64.b64encode(signature).decode("ascii")
    return signed


def verify_infrastructure_statement(
    statement: dict[str, Any],
    trusted_pca_public_key_b64: str,
    *,
    required_statement_type: str | None = None,
) -> dict[str, Any]:
    if not isinstance(statement, dict):
        raise PCAValidationError("infrastructure statement must be a JSON object")
    require_pca_signer_path(statement.get("signer_path"))
    if required_statement_type is not None and statement.get("statement_type") != required_statement_type:
        raise PCAValidationError(f"statement_type must be {required_statement_type}")
    signature_b64 = statement.get(_INFRA_SIGNATURE_FIELD)
    if not isinstance(signature_b64, str):
        raise PCAValidationError("infrastructure statement signature is required")
    payload = dict(statement)
    del payload[_INFRA_SIGNATURE_FIELD]
    public_key = public_key_from_b64(trusted_pca_public_key_b64)
    try:
        public_key.verify(signature_from_b64(signature_b64), canonicalize_bytes(payload))
    except InvalidSignature as exc:
        raise PCAAuthenticationError("infrastructure statement signature is invalid") from exc
    return payload
