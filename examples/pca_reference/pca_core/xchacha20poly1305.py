from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .constants import XCHACHA20_KEY_BYTES, XCHACHA20_NONCE_BYTES
from .encoding import ensure_bytes_length
from .errors import PCAAuthenticationError


def _rotl32(value: int, count: int) -> int:
    return ((value << count) & 0xFFFFFFFF) | (value >> (32 - count))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    ensure_bytes_length(key, XCHACHA20_KEY_BYTES, "XChaCha20 key")
    ensure_bytes_length(nonce16, 16, "HChaCha20 nonce")
    constants = b"expand 32-byte k"
    state = list(struct.unpack("<4I", constants))
    state.extend(struct.unpack("<8I", key))
    state.extend(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    return struct.pack("<8I", state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15])


def _ietf_chacha_key_and_nonce(key: bytes, nonce24: bytes) -> tuple[bytes, bytes]:
    ensure_bytes_length(key, XCHACHA20_KEY_BYTES, "XChaCha20 key")
    ensure_bytes_length(nonce24, XCHACHA20_NONCE_BYTES, "XChaCha20 nonce")
    subkey = hchacha20(key, nonce24[:16])
    return subkey, b"\x00\x00\x00\x00" + nonce24[16:]


def xchacha20poly1305_encrypt(key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes) -> bytes:
    subkey, nonce12 = _ietf_chacha_key_and_nonce(key, nonce24)
    return ChaCha20Poly1305(subkey).encrypt(nonce12, plaintext, aad)


def xchacha20poly1305_decrypt(key: bytes, nonce24: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
    subkey, nonce12 = _ietf_chacha_key_and_nonce(key, nonce24)
    try:
        return ChaCha20Poly1305(subkey).decrypt(nonce12, ciphertext_and_tag, aad)
    except InvalidTag as exc:
        raise PCAAuthenticationError("XChaCha20-Poly1305 authentication failed") from exc

