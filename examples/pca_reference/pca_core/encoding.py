from __future__ import annotations

import re
import secrets

from .constants import FILE_ID_BYTES, MASTER_SECRET_BYTES, NAMESPACE_ID_BYTES, NAMESPACE_PREFIX
from .errors import PCAValidationError

_CANONICAL_PATH_RE = re.compile(r"^[A-Za-z0-9/-]+$")
_UPPER_HEX_RE = re.compile(r"^[0-9A-F]+$")
_VERSION_RE = re.compile(r"^V[0-9]+$")
_ISO_Z_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def ensure_bytes_length(value: bytes, expected: int, field: str) -> bytes:
    if not isinstance(value, bytes):
        raise PCAValidationError(f"{field} must be bytes")
    if len(value) != expected:
        raise PCAValidationError(f"{field} must be exactly {expected} bytes")
    return value


def parse_upper_hex(value: str, expected_bytes: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise PCAValidationError(f"{field} must be a string")
    if len(value) != expected_bytes * 2 or not _UPPER_HEX_RE.fullmatch(value):
        raise PCAValidationError(f"{field} must be {expected_bytes * 8}-bit Uppercase HEX")
    return bytes.fromhex(value)


def to_upper_hex(value: bytes) -> str:
    return value.hex().upper()


def random_upper_hex(byte_len: int) -> str:
    return secrets.token_bytes(byte_len).hex().upper()


def generate_master_secret() -> bytes:
    return secrets.token_bytes(MASTER_SECRET_BYTES)


def generate_namespace() -> str:
    return f"{NAMESPACE_PREFIX}/{random_upper_hex(NAMESPACE_ID_BYTES)}"


def generate_file_id() -> str:
    return random_upper_hex(FILE_ID_BYTES)


def validate_namespace(namespace: str) -> str:
    if not isinstance(namespace, str):
        raise PCAValidationError("namespace must be a string")
    prefix = f"{NAMESPACE_PREFIX}/"
    if not namespace.startswith(prefix):
        raise PCAValidationError(f"namespace must start with {prefix}")
    parse_upper_hex(namespace[len(prefix):], NAMESPACE_ID_BYTES, "Namespace ID")
    return namespace


def canonical_path_bytes(path: str) -> bytes:
    return validate_canonical_path(path).encode("ascii")


def validate_canonical_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise PCAValidationError("Canonical Info Path must be a non-empty string")
    try:
        path.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PCAValidationError("Canonical Info Path must contain US-ASCII only") from exc
    if not _CANONICAL_PATH_RE.fullmatch(path):
        raise PCAValidationError("Canonical Info Path may contain only [A-Za-z0-9/-]")
    if "//" in path or path.startswith("/") or path.endswith("/"):
        raise PCAValidationError("Canonical Info Path must not contain empty path components")
    parts = path.split("/")
    for part in parts:
        if "-" in part:
            raise PCAValidationError("Path components must not contain '-'")
        if part and part[0].isalpha() and not part[0].isupper():
            raise PCAValidationError("Named path components must use CamelCase")
    return path


def validate_protocol_path(path: str, branch: str | None = None) -> str:
    path = validate_canonical_path(path)
    parts = path.split("/")
    if len(parts) < 3:
        raise PCAValidationError("Protocol paths must have Branch/Version/Object...")
    if branch is not None and parts[0] != branch:
        raise PCAValidationError(f"path must start with {branch}/")
    if parts[0] not in {"Identity", "Encrypt", "PCA"}:
        raise PCAValidationError("path branch must be Identity, Encrypt, or PCA")
    if not _VERSION_RE.fullmatch(parts[1]):
        raise PCAValidationError("path version segment must look like V1, V2, ...")
    return path


def validate_identity_path(path: str) -> str:
    path = validate_protocol_path(path, "Identity")
    if not path.startswith("Identity/V1/"):
        raise PCAValidationError("PCA v1.2 identity paths must start with Identity/V1/")
    return path


def validate_generation_path(path: str) -> str:
    path = validate_protocol_path(path, "Encrypt")
    if not path.startswith("Encrypt/V1/Generation/"):
        raise PCAValidationError("Generation paths must start with Encrypt/V1/Generation/")
    return path


def validate_vault_permission_path(permission_path: str) -> str:
    path = validate_canonical_path(permission_path)
    if path.startswith("Encrypt/"):
        raise PCAValidationError("permission_path must be relative, not a full Encrypt path")
    return path


def validate_file_id(file_id: str) -> str:
    parse_upper_hex(file_id, FILE_ID_BYTES, "File ID")
    return file_id


def validate_iso8601_z(value: str, field: str) -> str:
    if not isinstance(value, str) or not _ISO_Z_RE.fullmatch(value):
        raise PCAValidationError(f"{field} must use UTC format YYYY-MM-DDTHH:MM:SSZ")
    return value

