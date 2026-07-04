from __future__ import annotations

from typing import Any

from .encoding import validate_iso8601_z
from .errors import PCAValidationError
from .infrastructure import PCA_INFRASTRUCTURE_PATH, sign_infrastructure_statement, verify_infrastructure_statement


def sign_protocol_migration_statement(
    private_seed: bytes,
    issued_at: str,
    from_protocol: str,
    to_protocol: str,
    migration_text: str,
) -> dict[str, Any]:
    validate_iso8601_z(issued_at, "issued_at")
    if not from_protocol or not to_protocol:
        raise PCAValidationError("protocol names must be non-empty strings")
    if not isinstance(migration_text, str) or not migration_text:
        raise PCAValidationError("migration_text must be a non-empty string")
    return sign_infrastructure_statement(
        private_seed,
        {
            "from_protocol": from_protocol,
            "issued_at": issued_at,
            "migration_text": migration_text,
            "signer_path": PCA_INFRASTRUCTURE_PATH,
            "statement_type": "protocol_migration",
            "to_protocol": to_protocol,
            "version": 1,
        },
    )


def verify_protocol_migration_statement(
    statement: dict[str, Any], trusted_pca_public_key_b64: str
) -> dict[str, Any]:
    payload = verify_infrastructure_statement(
        statement,
        trusted_pca_public_key_b64,
        required_statement_type="protocol_migration",
    )
    if payload.get("version") != 1:
        raise PCAValidationError("protocol migration statement version must be 1")
    validate_iso8601_z(payload.get("issued_at"), "issued_at")
    for field in ("from_protocol", "to_protocol", "migration_text"):
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise PCAValidationError(f"{field} must be a non-empty string")
    return payload
