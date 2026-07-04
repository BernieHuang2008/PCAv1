from __future__ import annotations

import base64
import re
from typing import Any

from .constants import ED25519_SIGNATURE_BYTES
from .encoding import validate_iso8601_z
from .errors import PCAValidationError
from .infrastructure import (
    PCA_INFRASTRUCTURE_PATH,
    sign_infrastructure_statement,
    verify_infrastructure_statement,
)

_UPPER_HEX_RE = re.compile(r"^[0-9A-F]{64}$")


def _validate_revoked_identifiers(values: Any) -> list[str]:
    if not isinstance(values, list):
        raise PCAValidationError("revoked_identifiers must be a JSON array")
    for value in values:
        if not isinstance(value, str) or not _UPPER_HEX_RE.fullmatch(value):
            raise PCAValidationError("revoked_identifiers entries must be SHA-256 Uppercase HEX strings")
    return values


def sign_crl(private_seed: bytes, issued_at: str, revoked_identifiers: list[str]) -> dict[str, Any]:
    validate_iso8601_z(issued_at, "issued_at")
    identifiers = _validate_revoked_identifiers(revoked_identifiers)
    return sign_infrastructure_statement(
        private_seed,
        {
            "issued_at": issued_at,
            "revoked_identifiers": identifiers,
            "signer_path": PCA_INFRASTRUCTURE_PATH,
            "version": 1,
        },
    )


def verify_crl(
    crl: dict[str, Any],
    trusted_pca_public_key_b64: str | None = None,
    *,
    hardcoded_identity_pca: str | None = None,
) -> dict[str, Any]:
    payload = verify_infrastructure_statement(
        crl,
        trusted_pca_public_key_b64,
        hardcoded_identity_pca=hardcoded_identity_pca,
    )
    if payload.get("version") != 1:
        raise PCAValidationError("CRL version must be 1")
    validate_iso8601_z(payload.get("issued_at"), "issued_at")
    if payload.get("signer_path") != PCA_INFRASTRUCTURE_PATH:
        raise PCAValidationError("CRL signer_path must be Identity/V1/PCA")
    _validate_revoked_identifiers(payload.get("revoked_identifiers"))
    signature_b64 = crl.get("signature")
    if not isinstance(signature_b64, str):
        raise PCAValidationError("CRL signature is required")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise PCAValidationError("CRL signature must be valid Base64") from exc
    if len(signature) != ED25519_SIGNATURE_BYTES:
        raise PCAValidationError("CRL signature must be an Ed25519 signature")
    return payload


def is_identifier_revoked(
    crl: dict[str, Any],
    trusted_pca_public_key_b64: str | None,
    identifier_hex: str,
    *,
    hardcoded_identity_pca: str | None = None,
) -> bool:
    if not isinstance(identifier_hex, str) or not _UPPER_HEX_RE.fullmatch(identifier_hex):
        raise PCAValidationError("identifier must be a SHA-256 Uppercase HEX string")
    payload = verify_crl(crl, trusted_pca_public_key_b64, hardcoded_identity_pca=hardcoded_identity_pca)
    return identifier_hex in payload["revoked_identifiers"]
