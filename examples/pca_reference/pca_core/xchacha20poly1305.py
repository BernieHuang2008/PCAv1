from __future__ import annotations

from nacl import bindings
from nacl.exceptions import CryptoError

from .constants import XCHACHA20_KEY_BYTES, XCHACHA20_NONCE_BYTES
from .encoding import ensure_bytes_length
from .errors import PCAAuthenticationError


def xchacha20poly1305_encrypt(key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes) -> bytes:
    ensure_bytes_length(key, XCHACHA20_KEY_BYTES, "XChaCha20 key")
    ensure_bytes_length(nonce24, XCHACHA20_NONCE_BYTES, "XChaCha20 nonce")
    return bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce24, key)


def xchacha20poly1305_decrypt(key: bytes, nonce24: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
    ensure_bytes_length(key, XCHACHA20_KEY_BYTES, "XChaCha20 key")
    ensure_bytes_length(nonce24, XCHACHA20_NONCE_BYTES, "XChaCha20 nonce")
    try:
        return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext_and_tag, aad, nonce24, key)
    except CryptoError as exc:
        raise PCAAuthenticationError("XChaCha20-Poly1305 authentication failed") from exc
