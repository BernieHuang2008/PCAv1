from __future__ import annotations

from .constants import BIP32_MASTER_SEED_BYTES
from .encoding import validate_generation_path
from .errors import PCAValidationError
from .hkdf import derive_path_key


def derive_generation_secret(master_secret: bytes, namespace: str, generation_path: str, length: int = 32) -> bytes:
    if length not in {32, 64}:
        raise PCAValidationError("Generation examples expose only 32-byte or 64-byte outputs")
    return derive_path_key(master_secret, namespace, validate_generation_path(generation_path), length)


def derive_bip32_master_seed(master_secret: bytes, namespace: str, network: str = "Mainnet") -> bytes:
    if network not in {"Mainnet", "Testnet"}:
        raise PCAValidationError("network must be Mainnet or Testnet")
    path = f"Encrypt/V1/Generation/Bitcoin/{network}"
    return derive_generation_secret(master_secret, namespace, path, BIP32_MASTER_SEED_BYTES)

