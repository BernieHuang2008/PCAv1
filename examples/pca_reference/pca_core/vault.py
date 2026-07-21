from __future__ import annotations

import io
import json
import secrets
import zipfile
from dataclasses import dataclass
from typing import Any

from .constants import HKDF_SHA512_BYTES, XCHACHA20_KEY_BYTES, XCHACHA20_NONCE_BYTES
from .encoding import (
    canonical_path_bytes,
    generate_file_id,
    validate_file_id,
    validate_vault_permission_path,
)
from .errors import PCAValidationError
from .hkdf import derive_child_key, derive_path_key
from .jcs import loads_no_duplicates
from .xchacha20poly1305 import xchacha20poly1305_decrypt, xchacha20poly1305_encrypt


VAULT_PACKAGE_METADATA_NAME = "metadata.json"
VAULT_PACKAGE_CIPHERTEXT_NAME = "ciphertext.bin"


@dataclass(frozen=True)
class VaultCiphertext:
    file_id: str
    canonical_path: str
    data: bytes


@dataclass(frozen=True)
class VaultPackage:
    file_id: str
    canonical_path: str
    permission_path: str
    encrypted: bytes


def vault_permission_full_path(permission_path: str) -> str:
    relative = validate_vault_permission_path(permission_path)
    return f"Encrypt/V1/Vault/{relative}"


def vault_file_full_path(permission_path: str, file_id: str) -> str:
    validate_file_id(file_id)
    return f"{vault_permission_full_path(permission_path)}/{file_id}"


def derive_permission_node_key(master_secret: bytes, namespace: str, permission_path: str) -> bytes:
    return derive_path_key(master_secret, namespace, vault_permission_full_path(permission_path), HKDF_SHA512_BYTES)


def derive_per_file_key(permission_node_key: bytes, namespace: str, file_id: str) -> bytes:
    validate_file_id(file_id)
    return derive_child_key(permission_node_key, namespace, f"File/{file_id}", XCHACHA20_KEY_BYTES)


def encrypt_file_bytes(master_secret: bytes, namespace: str, permission_path: str, plaintext: bytes) -> VaultCiphertext:
    if not isinstance(plaintext, bytes):
        raise PCAValidationError("plaintext must be bytes")
    file_id = generate_file_id()
    permission_key = derive_permission_node_key(master_secret, namespace, permission_path)
    return encrypt_file_bytes_with_permission_key(permission_key, namespace, permission_path, plaintext, file_id=file_id)


def encrypt_file_bytes_with_permission_key(
    permission_node_key: bytes,
    namespace: str,
    permission_path: str,
    plaintext: bytes,
    *,
    file_id: str | None = None,
) -> VaultCiphertext:
    if not isinstance(plaintext, bytes):
        raise PCAValidationError("plaintext must be bytes")
    file_id = file_id or generate_file_id()
    permission_key = permission_node_key
    per_file_key = derive_per_file_key(permission_key, namespace, file_id)
    nonce = secrets.token_bytes(XCHACHA20_NONCE_BYTES)
    full_path = vault_file_full_path(permission_path, file_id)
    ciphertext_and_tag = xchacha20poly1305_encrypt(
        per_file_key,
        nonce,
        plaintext,
        canonical_path_bytes(full_path),
    )
    return VaultCiphertext(file_id=file_id, canonical_path=full_path, data=nonce + ciphertext_and_tag)


def vault_metadata(ciphertext: VaultCiphertext, permission_path: str) -> dict[str, str]:
    full_path = vault_file_full_path(permission_path, ciphertext.file_id)
    if ciphertext.canonical_path != full_path:
        raise PCAValidationError("Vault metadata does not match ciphertext path")
    return {
        "canonical_path": ciphertext.canonical_path,
        "file_id": ciphertext.file_id,
        "permission_path": validate_vault_permission_path(permission_path),
    }


def pack_vault_ciphertext(ciphertext: VaultCiphertext, permission_path: str) -> bytes:
    metadata = vault_metadata(ciphertext, permission_path)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as package:
        package.writestr(
            VAULT_PACKAGE_METADATA_NAME,
            json.dumps(metadata, indent=2, sort_keys=True).encode("utf-8"),
        )
        package.writestr(VAULT_PACKAGE_CIPHERTEXT_NAME, ciphertext.data)
    return buffer.getvalue()


def is_vault_package(data: bytes) -> bool:
    if not isinstance(data, bytes):
        raise PCAValidationError("Vault package data must be bytes")
    return zipfile.is_zipfile(io.BytesIO(data))


def unpack_vault_package(data: bytes) -> VaultPackage:
    if not isinstance(data, bytes):
        raise PCAValidationError("Vault package data must be bytes")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as package:
            names = package.namelist()
            if VAULT_PACKAGE_METADATA_NAME not in names:
                raise PCAValidationError("Vault package is missing metadata.json")
            if VAULT_PACKAGE_CIPHERTEXT_NAME not in names:
                raise PCAValidationError("Vault package is missing ciphertext.bin")
            metadata = _parse_vault_metadata(package.read(VAULT_PACKAGE_METADATA_NAME))
            encrypted = package.read(VAULT_PACKAGE_CIPHERTEXT_NAME)
    except zipfile.BadZipFile as exc:
        raise PCAValidationError("Vault package is not a valid ZIP file") from exc
    return VaultPackage(
        file_id=metadata["file_id"],
        canonical_path=metadata["canonical_path"],
        permission_path=metadata["permission_path"],
        encrypted=encrypted,
    )


def _parse_vault_metadata(data: bytes) -> dict[str, str]:
    try:
        value = loads_no_duplicates(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise PCAValidationError("Vault metadata must be UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise PCAValidationError("Vault metadata must be a JSON object")
    metadata: dict[str, str] = {}
    for field in ("canonical_path", "file_id", "permission_path"):
        item: Any = value.get(field)
        if not isinstance(item, str):
            raise PCAValidationError(f"Vault metadata field {field} must be a string")
        metadata[field] = item
    full_path = vault_file_full_path(metadata["permission_path"], metadata["file_id"])
    if metadata["canonical_path"] != full_path:
        raise PCAValidationError("Vault metadata canonical_path does not match permission_path and file_id")
    return metadata


def decrypt_file_bytes(
    master_secret: bytes, namespace: str, permission_path: str, file_id: str, encrypted: bytes
) -> bytes:
    permission_key = derive_permission_node_key(master_secret, namespace, permission_path)
    return decrypt_file_bytes_with_permission_key(permission_key, namespace, permission_path, file_id, encrypted)


def decrypt_file_bytes_with_permission_key(
    permission_node_key: bytes, namespace: str, permission_path: str, file_id: str, encrypted: bytes
) -> bytes:
    if not isinstance(encrypted, bytes):
        raise PCAValidationError("encrypted data must be bytes")
    if len(encrypted) < XCHACHA20_NONCE_BYTES + 16:
        raise PCAValidationError("encrypted Vault data is too short")
    nonce = encrypted[:XCHACHA20_NONCE_BYTES]
    ciphertext_and_tag = encrypted[XCHACHA20_NONCE_BYTES:]
    permission_key = permission_node_key
    per_file_key = derive_per_file_key(permission_key, namespace, file_id)
    full_path = vault_file_full_path(permission_path, file_id)
    return xchacha20poly1305_decrypt(
        per_file_key,
        nonce,
        ciphertext_and_tag,
        canonical_path_bytes(full_path),
    )
