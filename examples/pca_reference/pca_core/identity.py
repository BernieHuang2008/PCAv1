from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .constants import ED25519_SEED_BYTES
from .encoding import validate_identity_path
from .hkdf import derive_path_key


def derive_identity_seed(master_secret: bytes, namespace: str, identity_path: str) -> bytes:
    return derive_path_key(master_secret, namespace, validate_identity_path(identity_path), ED25519_SEED_BYTES)


def derive_identity_private_key(
    master_secret: bytes, namespace: str, identity_path: str
) -> ed25519.Ed25519PrivateKey:
    seed = derive_identity_seed(master_secret, namespace, identity_path)
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def public_key_bytes(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign_identity_message(master_secret: bytes, namespace: str, identity_path: str, message: bytes) -> bytes:
    return derive_identity_private_key(master_secret, namespace, identity_path).sign(message)


def verify_identity_signature(public_key: bytes, message: bytes, signature: bytes) -> None:
    ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)

