from __future__ import annotations

import hashlib
import hmac
import math

from .constants import HKDF_SHA512_BYTES, MASTER_SECRET_BYTES, TRUST_ROOT_INFO_PATH
from .encoding import (
    canonical_path_bytes,
    ensure_bytes_length,
    validate_canonical_path,
    validate_namespace,
    validate_protocol_path,
)
from .errors import PCAValidationError


def hkdf_sha512(ikm: bytes, namespace: str, info_path: str, length: int) -> bytes:
    if not isinstance(ikm, bytes) or not ikm:
        raise PCAValidationError("HKDF IKM must be non-empty bytes")
    validate_namespace(namespace)
    info = canonical_path_bytes(info_path)
    if length <= 0 or length > 255 * HKDF_SHA512_BYTES:
        raise PCAValidationError("HKDF length must be in the RFC 5869 range")
    salt = namespace.encode("ascii")
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    blocks: list[bytes] = []
    previous = b""
    for counter in range(1, math.ceil(length / HKDF_SHA512_BYTES) + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha512).digest()
        blocks.append(previous)
    return b"".join(blocks)[:length]


def derive_trust_root(master_secret: bytes, namespace: str) -> bytes:
    ensure_bytes_length(master_secret, MASTER_SECRET_BYTES, "Master Secret")
    return hkdf_sha512(master_secret, namespace, TRUST_ROOT_INFO_PATH, HKDF_SHA512_BYTES)


def derive_path_key(master_secret: bytes, namespace: str, canonical_path: str, length: int) -> bytes:
    path = validate_protocol_path(canonical_path)
    key = derive_trust_root(master_secret, namespace)
    parts = path.split("/")
    for depth in range(3, len(parts) + 1):
        prefix = "/".join(parts[:depth])
        key = hkdf_sha512(key, namespace, prefix, HKDF_SHA512_BYTES)
    return key[:length]


def derive_descendant_key(
    parent_key: bytes,
    namespace: str,
    parent_path: str,
    target_path: str,
    length: int,
) -> bytes:
    if not isinstance(parent_key, bytes) or not parent_key:
        raise PCAValidationError("parent key must be non-empty bytes")
    if parent_path == TRUST_ROOT_INFO_PATH:
        path = validate_protocol_path(target_path)
        key = parent_key
        parts = path.split("/")
        for depth in range(3, len(parts) + 1):
            prefix = "/".join(parts[:depth])
            key = hkdf_sha512(key, namespace, prefix, HKDF_SHA512_BYTES)
        return key[:length]

    parent = validate_protocol_path(parent_path)
    target = validate_protocol_path(target_path)
    if target == parent:
        return parent_key[:length]
    if not target.startswith(parent + "/"):
        raise PCAValidationError("target path must be a descendant of parent path")
    key = parent_key
    parts = target.split("/")
    parent_depth = len(parent.split("/"))
    for depth in range(parent_depth + 1, len(parts) + 1):
        prefix = "/".join(parts[:depth])
        key = hkdf_sha512(key, namespace, prefix, HKDF_SHA512_BYTES)
    return key[:length]


def derive_child_key(parent_key: bytes, namespace: str, child_info_path: str, length: int) -> bytes:
    validate_canonical_path(child_info_path)
    if not isinstance(parent_key, bytes) or not parent_key:
        raise PCAValidationError("parent key must be non-empty bytes")
    return hkdf_sha512(parent_key, namespace, child_info_path, length)
