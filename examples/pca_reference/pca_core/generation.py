from __future__ import annotations

import hashlib
import ipaddress
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .constants import BIP32_MASTER_SEED_BYTES
from .encoding import validate_generation_path
from .errors import PCAValidationError
from .hkdf import derive_path_key, hkdf_sha512
from .jcs import canonicalize_bytes


PASSWORD_ROOT_PATH = "Encrypt/V1/Generation/PasswordRoot1"
PASSWORD_DEFAULT_CHARSET = "PRINTABLE-88"
PASSWORD_DEFAULT_LENGTH = 20
PASSWORD_DEFAULT_COUNTER = 1

PASSWORD_CHARSET_BUCKETS: dict[str, tuple[str, ...]] = {
    "PRINTABLE-88": (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "!@#$%^&*()-_=+[]{}|;:,.<>?",
    ),
    "BASE-62": (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
    ),
    "BASE-32": (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "234567",
    ),
    "BASE-16": ("0123456789ABCDEF",),
    "BASE-10": ("0123456789",),
}


@dataclass(frozen=True)
class GeneratedPassword:
    password: str
    service: str
    username: str
    counter: int
    pwdcharset: str
    pwdlength: int
    account_json_sha256_hex: str
    info_path: str
    account: dict[str, Any]


def derive_generation_secret(master_secret: bytes, namespace: str, generation_path: str, length: int = 32) -> bytes:
    if length not in {32, 64}:
        raise PCAValidationError("Generation examples expose only 32-byte or 64-byte outputs")
    return derive_path_key(master_secret, namespace, validate_generation_path(generation_path), length)


def derive_bip32_master_seed(master_secret: bytes, namespace: str, network: str = "Mainnet") -> bytes:
    if network not in {"Mainnet", "Testnet"}:
        raise PCAValidationError("network must be Mainnet or Testnet")
    path = f"Encrypt/V1/Generation/Bitcoin/{network}"
    return derive_generation_secret(master_secret, namespace, path, BIP32_MASTER_SEED_BYTES)


def derive_password_root_key(master_secret: bytes, namespace: str) -> bytes:
    return derive_generation_secret(master_secret, namespace, PASSWORD_ROOT_PATH, 32)


def generate_password(
    master_secret: bytes,
    namespace: str,
    service: str,
    username: str,
    counter: int = PASSWORD_DEFAULT_COUNTER,
    pwdcharset: str = PASSWORD_DEFAULT_CHARSET,
    pwdlength: int = PASSWORD_DEFAULT_LENGTH,
    *,
    preserve_username_case: bool = False,
) -> GeneratedPassword:
    password_root_key = derive_password_root_key(master_secret, namespace)
    return generate_password_with_root_key(
        password_root_key,
        namespace,
        service,
        username,
        counter,
        pwdcharset,
        pwdlength,
        preserve_username_case=preserve_username_case,
    )


def generate_password_with_root_key(
    password_root_key: bytes,
    namespace: str,
    service: str,
    username: str,
    counter: int = PASSWORD_DEFAULT_COUNTER,
    pwdcharset: str = PASSWORD_DEFAULT_CHARSET,
    pwdlength: int = PASSWORD_DEFAULT_LENGTH,
    *,
    preserve_username_case: bool = False,
) -> GeneratedPassword:
    account = password_account(
        service,
        username,
        counter,
        pwdcharset,
        pwdlength,
        preserve_username_case=preserve_username_case,
    )
    account_bytes = canonicalize_bytes(_normalize_json_strings(account))
    account_hash = hashlib.sha256(account_bytes).hexdigest().upper()
    info_path = f"{PASSWORD_ROOT_PATH}/{account_hash}"
    raw_password_key = hkdf_sha512(password_root_key, namespace, info_path, 64)
    stream = hkdf_stream(raw_password_key, namespace, info_path)
    password = _build_bucket_shuffled_password(stream, account["pwdcharset"], account["pwdlength"])
    return GeneratedPassword(
        password=password,
        service=account["service"],
        username=account["username"],
        counter=account["counter"],
        pwdcharset=account["pwdcharset"],
        pwdlength=account["pwdlength"],
        account_json_sha256_hex=account_hash,
        info_path=info_path,
        account=account,
    )


def password_account(
    service: str,
    username: str,
    counter: int = PASSWORD_DEFAULT_COUNTER,
    pwdcharset: str = PASSWORD_DEFAULT_CHARSET,
    pwdlength: int = PASSWORD_DEFAULT_LENGTH,
    *,
    preserve_username_case: bool = False,
) -> dict[str, Any]:
    charset = _validate_password_charset(pwdcharset)
    length = _validate_password_length(pwdlength, charset)
    return {
        "counter": _validate_counter(counter),
        "pwdcharset": charset,
        "pwdlength": length,
        "service": normalize_service_identifier(service),
        "username": normalize_username(username, preserve_case=preserve_username_case),
    }


def normalize_username(username: str, *, preserve_case: bool = False) -> str:
    if not isinstance(username, str) or not username:
        raise PCAValidationError("username must be a non-empty string")
    value = username if preserve_case else username.lower()
    return unicodedata.normalize("NFC", value)


def normalize_service_identifier(service: str) -> str:
    if not isinstance(service, str) or not service:
        raise PCAValidationError("service must be a non-empty string")
    value = unicodedata.normalize("NFC", service)
    if value.startswith("["):
        host_end = value.find("]")
        if host_end == -1:
            raise PCAValidationError("IPv6 service identifiers must use [addr] or [addr]:port")
        host = value[1:host_end]
        suffix = value[host_end + 1 :]
        port = _parse_optional_port(suffix)
        normalized_host = f"[{ipaddress.IPv6Address(host).compressed}]"
        return normalized_host + (f":{port}" if port is not None else "")

    host, port = _split_host_port(value)
    try:
        ip = ipaddress.ip_address(host)
        normalized_host = ip.compressed
    except ValueError:
        normalized_host = _idna_domain_to_ascii(host)
    return normalized_host + (f":{port}" if port is not None else "")


def hkdf_stream(ikm: bytes, namespace: str, canonical_info_path: str) -> Iterator[int]:
    path = validate_generation_path(canonical_info_path)
    block_index = 0
    while True:
        block = hkdf_sha512(ikm, namespace, f"{path}/Block{block_index}", 256)
        yield from block
        block_index += 1


def rejection_sample(stream: Iterator[int], modulus: int) -> int:
    if modulus <= 0 or modulus > 256:
        raise PCAValidationError("rejection sampling modulus must be in 1..256")
    threshold = (256 // modulus) * modulus
    for value in stream:
        if value < threshold:
            return value % modulus
    raise PCAValidationError("HKDF stream ended unexpectedly")


def _build_bucket_shuffled_password(stream: Iterator[int], charset_name: str, length: int) -> str:
    buckets = PASSWORD_CHARSET_BUCKETS[charset_name]
    all_charset = "".join(buckets)
    chars = [bucket[rejection_sample(stream, len(bucket))] for bucket in buckets]
    while len(chars) < length:
        chars.append(all_charset[rejection_sample(stream, len(all_charset))])
    for index in range(len(chars) - 1, 0, -1):
        swap_index = rejection_sample(stream, index + 1)
        chars[index], chars[swap_index] = chars[swap_index], chars[index]
    return "".join(chars)


def _normalize_json_strings(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize_json_strings(item) for item in value]
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", key) if isinstance(key, str) else key: _normalize_json_strings(item)
            for key, item in value.items()
        }
    return value


def _validate_counter(counter: int) -> int:
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 1:
        raise PCAValidationError("counter must be a positive integer starting at 1")
    return counter


def _validate_password_charset(pwdcharset: str) -> str:
    if pwdcharset not in PASSWORD_CHARSET_BUCKETS:
        allowed = ", ".join(PASSWORD_CHARSET_BUCKETS)
        raise PCAValidationError(f"pwdcharset must be one of: {allowed}")
    return pwdcharset


def _validate_password_length(pwdlength: int, pwdcharset: str) -> int:
    if not isinstance(pwdlength, int) or isinstance(pwdlength, bool) or pwdlength < 1:
        raise PCAValidationError("pwdlength must be a positive integer")
    bucket_count = len(PASSWORD_CHARSET_BUCKETS[pwdcharset])
    if pwdlength < bucket_count:
        raise PCAValidationError(f"pwdlength must be at least {bucket_count} for {pwdcharset}")
    return pwdlength


def _split_host_port(value: str) -> tuple[str, int | None]:
    if value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        if not host:
            raise PCAValidationError("service host must be non-empty")
        return host, _parse_port(port_text)
    return value, None


def _parse_optional_port(suffix: str) -> int | None:
    if not suffix:
        return None
    if not suffix.startswith(":"):
        raise PCAValidationError("service port must follow ':'")
    return _parse_port(suffix[1:])


def _parse_port(port_text: str) -> int:
    if not port_text.isdecimal():
        raise PCAValidationError("service port must be decimal")
    port = int(port_text)
    if port < 0 or port > 65535:
        raise PCAValidationError("service port must be in 0..65535")
    return port


def _idna_domain_to_ascii(host: str) -> str:
    if not host or host.startswith(".") or host.endswith(".") or ".." in host:
        raise PCAValidationError("service domain must be a non-empty DNS name")
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            import idna

            return idna.encode(host, uts46=False).decode("ascii").lower()
        except ImportError:
            return host.encode("idna").decode("ascii").lower()
        except idna.IDNAError as exc:
            raise PCAValidationError(f"service domain IDNA encoding failed: {exc}") from exc
    ascii_host = host.lower()
    for label in ascii_host.split("."):
        if not label:
            raise PCAValidationError("service domain labels must be non-empty")
        if len(label) > 63:
            raise PCAValidationError("service domain labels must be at most 63 octets")
    return ascii_host

