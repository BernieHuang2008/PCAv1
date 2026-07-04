from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from pca_core.encoding import parse_upper_hex
from pca_core.errors import PCAAuthenticationError, PCAValidationError
from pca_core.generation import derive_bip32_master_seed
from pca_core.hkdf import derive_descendant_key, derive_path_key
from pca_core.jcs import canonicalize, loads_no_duplicates
from pca_core.revocation import (
    generate_emergency_private_key,
    raw_public_key_b64,
    sign_revocation_statement,
    verify_revocation_statement,
)
from pca_core.vault import decrypt_file_bytes, encrypt_file_bytes
from pca_core.xchacha20poly1305 import hchacha20


MASTER = bytes(range(64))
NAMESPACE = "PCA-v1/A980E2656D5D0349012434FF624506C9650187D1F4B897D20D0E0918B1E1186E"


class PCAReferenceTests(unittest.TestCase):
    def test_hierarchical_derivation_is_deterministic_and_namespace_scoped(self) -> None:
        path = "Identity/V1/Personal/Identity2026/Laptop"
        first = derive_path_key(MASTER, NAMESPACE, path, 32)
        second = derive_path_key(MASTER, NAMESPACE, path, 32)
        other_namespace = "PCA-v1/B980E2656D5D0349012434FF624506C9650187D1F4B897D20D0E0918B1E1186E"
        scoped = derive_path_key(MASTER, other_namespace, path, 32)
        self.assertEqual(first, second)
        self.assertNotEqual(first, scoped)

    def test_descendant_derivation_from_parent_matches_master_derivation(self) -> None:
        parent_path = "Encrypt/V1/Vault/Finance"
        target_path = "Encrypt/V1/Vault/Finance/2026/Q3"
        parent = derive_path_key(MASTER, NAMESPACE, parent_path, 64)
        from_master = derive_path_key(MASTER, NAMESPACE, target_path, 64)
        from_parent = derive_descendant_key(parent, NAMESPACE, parent_path, target_path, 64)
        self.assertEqual(from_master, from_parent)

    def test_descendant_derivation_rejects_unrelated_parent(self) -> None:
        parent_path = "Encrypt/V1/Vault/Finance"
        target_path = "Encrypt/V1/Vault/Legal/2026"
        parent = derive_path_key(MASTER, NAMESPACE, parent_path, 64)
        with self.assertRaises(PCAValidationError):
            derive_descendant_key(parent, NAMESPACE, parent_path, target_path, 64)

    def test_rejects_non_canonical_paths_and_lowercase_hex(self) -> None:
        with self.assertRaises(PCAValidationError):
            derive_path_key(MASTER, NAMESPACE, "Identity/V1/personal/Identity2026", 32)
        with self.assertRaises(PCAValidationError):
            parse_upper_hex("a0" * 32, 32, "File ID")

    def test_bip32_seed_is_exactly_64_bytes(self) -> None:
        seed = derive_bip32_master_seed(MASTER, NAMESPACE, "Mainnet")
        self.assertEqual(len(seed), 64)

    def test_hchacha20_known_vector(self) -> None:
        key = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        nonce = bytes.fromhex("000000090000004A0000000031415927")
        expected = bytes.fromhex("82413B4227B27BFED30E42508A877D73A0F9E4D58A74A853C12EC41326D3ECDC")
        self.assertEqual(hchacha20(key, nonce), expected)

    def test_vault_roundtrip_and_aad_authentication(self) -> None:
        plaintext = b"external secret that cannot be regenerated"
        encrypted = encrypt_file_bytes(MASTER, NAMESPACE, "Finance/2026/Q3", plaintext)
        decrypted = decrypt_file_bytes(MASTER, NAMESPACE, "Finance/2026/Q3", encrypted.file_id, encrypted.data)
        self.assertEqual(decrypted, plaintext)
        with self.assertRaises(PCAAuthenticationError):
            decrypt_file_bytes(MASTER, NAMESPACE, "Finance/2026/Q4", encrypted.file_id, encrypted.data)

    def test_jcs_canonical_order_and_duplicate_rejection(self) -> None:
        self.assertEqual(canonicalize({"b": 2, "a": 1}), '{"a":1,"b":2}')
        with self.assertRaises(PCAValidationError):
            loads_no_duplicates('{"a":1,"a":2}')

    def test_revocation_must_match_namespace_before_signature(self) -> None:
        emergency_key = generate_emergency_private_key()
        seed = emergency_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        statement = sign_revocation_statement(
            seed,
            NAMESPACE,
            "2026-07-03T10:00:00Z",
            "Master Secret Compromised",
        )
        tampered_namespace = dict(statement)
        tampered_namespace["namespace"] = "PCA-v1/B980E2656D5D0349012434FF624506C9650187D1F4B897D20D0E0918B1E1186E"
        check = verify_revocation_statement(tampered_namespace, NAMESPACE, raw_public_key_b64(emergency_key))
        self.assertTrue(check.ignored)
        self.assertFalse(check.revoked)

    def test_revocation_rejects_tampered_matching_namespace_statement(self) -> None:
        emergency_key = generate_emergency_private_key()
        seed = emergency_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        statement = sign_revocation_statement(
            seed,
            NAMESPACE,
            "2026-07-03T10:00:00Z",
            "Master Secret Compromised",
        )
        statement["reason"] = "Protocol Migration"
        with self.assertRaises(PCAAuthenticationError):
            verify_revocation_statement(statement, NAMESPACE, raw_public_key_b64(emergency_key))


if __name__ == "__main__":
    unittest.main()
