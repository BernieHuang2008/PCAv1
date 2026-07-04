from __future__ import annotations

import secrets
from dataclasses import dataclass

from .constants import HKDF_SHA512_BYTES, XCHACHA20_KEY_BYTES, XCHACHA20_NONCE_BYTES
from .encoding import (
    canonical_path_bytes,
    generate_file_id,
    validate_file_id,
    validate_vault_permission_path,
)
from .errors import PCAValidationError
from .hkdf import derive_child_key, derive_path_key
from .xchacha20poly1305 import xchacha20poly1305_decrypt, xchacha20poly1305_encrypt


@dataclass(frozen=True)
class VaultCiphertext:
    file_id: str
    canonical_path: str
    data: bytes


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


def decrypt_file_bytes(
    master_secret: bytes, namespace: str, permission_path: str, file_id: str, encrypted: bytes
) -> bytes:
    if not isinstance(encrypted, bytes):
        raise PCAValidationError("encrypted data must be bytes")
    if len(encrypted) < XCHACHA20_NONCE_BYTES + 16:
        raise PCAValidationError("encrypted Vault data is too short")
    nonce = encrypted[:XCHACHA20_NONCE_BYTES]
    ciphertext_and_tag = encrypted[XCHACHA20_NONCE_BYTES:]
    permission_key = derive_permission_node_key(master_secret, namespace, permission_path)
    per_file_key = derive_per_file_key(permission_key, namespace, file_id)
    full_path = vault_file_full_path(permission_path, file_id)
    return xchacha20poly1305_decrypt(
        per_file_key,
        nonce,
        ciphertext_and_tag,
        canonical_path_bytes(full_path),
    )

