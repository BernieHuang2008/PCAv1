from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from pgpy import PGPKey, PGPUID
from pgpy.constants import EllipticCurveOID, HashAlgorithm, KeyFlags, PubKeyAlgorithm

from pca_cli import main as cli_main
from pca_core.crl import is_identifier_revoked, sign_crl, verify_crl
from pca_core.email_identity import (
    EXTERNAL_OPENPGP_PARENT_KEY_ORIGIN,
    sign_ephemeral_email,
    sign_external_openpgp_delayed_binding,
    sign_openpgp_delayed_binding,
    verify_ephemeral_email,
    verify_openpgp_delayed_binding,
)
from pca_core.encoding import parse_upper_hex
from pca_core.errors import PCAAuthenticationError, PCARevokedNamespaceError, PCAValidationError
from pca_core.generation import derive_bip32_master_seed
from pca_core.hkdf import derive_descendant_key, derive_path_key
from pca_core.infrastructure import EXAMPLE_IDENTITY_PCA, set_hardcoded_identity_pca
from pca_core.jcs import canonicalize, loads_no_duplicates
from pca_core.migration import sign_protocol_migration_statement, verify_protocol_migration_statement
from pca_core.revocation import (
    EXAMPLE_EMERGENCY_REVOCATION_PUBLIC_KEY,
    generate_emergency_private_key,
    raw_public_key_b64,
    require_namespace_not_revoked,
    set_hardcoded_emergency_revocation_public_key,
    sign_revocation_statement,
    verify_revocation_statement,
)
from pca_core.trust import EXAMPLE_NAMESPACE, set_hardcoded_namespace
from pca_core.vault import decrypt_file_bytes, encrypt_file_bytes


MASTER = bytes(range(64))
NAMESPACE = "PCA-v1/A980E2656D5D0349012434FF624506C9650187D1F4B897D20D0E0918B1E1186E"
REVOKED_ID = "A" * 64


def charlie_openpgp_key() -> PGPKey:
    key = PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
    key.add_uid(
        PGPUID.new("Charlie", email="charlie@example.com"),
        usage={KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA512],
    )
    return key


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

    def test_revocation_rejects_missing_required_fields(self) -> None:
        emergency_key = generate_emergency_private_key()
        seed = emergency_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        statement = sign_revocation_statement(
            seed,
            NAMESPACE,
            "2026-07-03T10:00:00Z",
            "Master Secret Compromised",
        )
        del statement["revoked_at"]
        with self.assertRaises(PCAValidationError):
            verify_revocation_statement(statement, NAMESPACE, raw_public_key_b64(emergency_key))

    def test_valid_revocation_blocks_subsequent_namespace_operations(self) -> None:
        emergency_key = generate_emergency_private_key()
        seed = emergency_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        statement = sign_revocation_statement(
            seed,
            NAMESPACE,
            "2026-07-03T10:00:00Z",
            "Master Secret Compromised",
        )
        with self.assertRaises(PCARevokedNamespaceError):
            require_namespace_not_revoked(statement, NAMESPACE, raw_public_key_b64(emergency_key))

    def test_hardcoded_emergency_revocation_public_key_overrides_argument(self) -> None:
        emergency_key = generate_emergency_private_key()
        other_key = generate_emergency_private_key()
        seed = emergency_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        statement = sign_revocation_statement(
            seed,
            NAMESPACE,
            "2026-07-03T10:00:00Z",
            "Master Secret Compromised",
        )
        try:
            set_hardcoded_emergency_revocation_public_key(raw_public_key_b64(emergency_key))
            check = verify_revocation_statement(statement, NAMESPACE)
            self.assertTrue(check.revoked)
            check = verify_revocation_statement(statement, NAMESPACE, raw_public_key_b64(other_key))
            self.assertTrue(check.revoked)
        finally:
            set_hardcoded_emergency_revocation_public_key(EXAMPLE_EMERGENCY_REVOCATION_PUBLIC_KEY)

    def test_example_emergency_revocation_public_key_skips_signature_verification(self) -> None:
        emergency_key = generate_emergency_private_key()
        seed = emergency_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        statement = sign_revocation_statement(
            seed,
            NAMESPACE,
            "2026-07-03T10:00:00Z",
            "Master Secret Compromised",
        )
        tampered = dict(statement)
        tampered["reason"] = "Testing only"
        check = verify_revocation_statement(
            tampered,
            NAMESPACE,
            hardcoded_emergency_revocation_public_key=EXAMPLE_EMERGENCY_REVOCATION_PUBLIC_KEY,
        )
        self.assertTrue(check.revoked)

    def test_hardcoded_namespace_overrides_argument_for_revocation(self) -> None:
        emergency_key = generate_emergency_private_key()
        seed = emergency_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        statement = sign_revocation_statement(
            seed,
            NAMESPACE,
            "2026-07-03T10:00:00Z",
            "Master Secret Compromised",
        )
        other_namespace = "PCA-v1/B980E2656D5D0349012434FF624506C9650187D1F4B897D20D0E0918B1E1186E"
        try:
            set_hardcoded_namespace(NAMESPACE)
            check = verify_revocation_statement(statement, other_namespace, raw_public_key_b64(emergency_key))
            self.assertTrue(check.revoked)
            check = verify_revocation_statement(statement, None, raw_public_key_b64(emergency_key))
            self.assertTrue(check.revoked)
        finally:
            set_hardcoded_namespace(EXAMPLE_NAMESPACE)

    def test_cli_namespace_commands_enforce_revocation_guard(self) -> None:
        emergency_key = generate_emergency_private_key()
        seed = emergency_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        statement = sign_revocation_statement(
            seed,
            NAMESPACE,
            "2026-07-03T10:00:00Z",
            "Master Secret Compromised",
        )
        email_sig = sign_ephemeral_email(MASTER, NAMESPACE, "Identity/V1/Personal/Identity2026", b"email")
        binding = sign_openpgp_delayed_binding(
            MASTER,
            NAMESPACE,
            "Identity/V1/Personal/Identity2026",
            email_sig,
            "2026-07-04T00:00:00Z",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            revocation_path = root / "revocation.json"
            email_path = root / "email.eml"
            email_sig_path = root / "email.sig.json"
            binding_path = root / "binding.asc.json"
            revoked_ids = root / "revoked.txt"
            revocation_path.write_text(json.dumps(statement), encoding="utf-8")
            email_path.write_bytes(b"email")
            email_sig_path.write_text(json.dumps(email_sig), encoding="utf-8")
            binding_path.write_text(json.dumps(binding), encoding="utf-8")
            revoked_ids.write_text(REVOKED_ID + "\n", encoding="utf-8")
            guard = [
                "--revocation-statement",
                str(revocation_path),
                "--emergency-public-key-b64",
                raw_public_key_b64(emergency_key),
            ]
            commands = [
                [
                    "identity",
                    "--master-hex",
                    MASTER.hex().upper(),
                    "--namespace",
                    NAMESPACE,
                    "--path",
                    "Identity/V1/Personal/Identity2026",
                ],
                [
                    "derive-node",
                    "--master-hex",
                    MASTER.hex().upper(),
                    "--namespace",
                    NAMESPACE,
                    "--path",
                    "Encrypt/V1/Generation/PasswordManager",
                ],
                [
                    "generation",
                    "--master-hex",
                    MASTER.hex().upper(),
                    "--namespace",
                    NAMESPACE,
                    "--path",
                    "Encrypt/V1/Generation/PasswordManager",
                ],
                ["bip32-seed", "--master-hex", MASTER.hex().upper(), "--namespace", NAMESPACE],
                [
                    "vault-encrypt",
                    "--master-hex",
                    MASTER.hex().upper(),
                    "--namespace",
                    NAMESPACE,
                    "--permission-path",
                    "Finance",
                    "--input",
                    str(email_path),
                    "--output",
                    str(root / "out.pca"),
                ],
                [
                    "vault-decrypt",
                    "--master-hex",
                    MASTER.hex().upper(),
                    "--namespace",
                    NAMESPACE,
                    "--permission-path",
                    "Finance",
                    "--file-id",
                    "A" * 64,
                    "--input",
                    str(email_path),
                    "--output",
                    str(root / "out.txt"),
                ],
                ["vault-permission", "--master-hex", MASTER.hex().upper(), "--namespace", NAMESPACE, "--permission-path", "Finance"],
                ["vault-file-key", "--master-hex", MASTER.hex().upper(), "--namespace", NAMESPACE, "--permission-path", "Finance"],
                [
                    "sign-revocation",
                    "--private-seed-hex",
                    seed.hex().upper(),
                    "--namespace",
                    NAMESPACE,
                    "--revoked-at",
                    "2026-07-04T00:00:00Z",
                    "--reason",
                    "Master Secret Compromised",
                ],
                [
                    "email-sign",
                    "--master-hex",
                    MASTER.hex().upper(),
                    "--namespace",
                    NAMESPACE,
                    "--parent-path",
                    "Identity/V1/Personal/Identity2026",
                    "--input",
                    str(email_path),
                ],
                ["email-verify", "--input", str(email_path), "--signature", str(email_sig_path)],
                [
                    "email-bind",
                    "--master-hex",
                    MASTER.hex().upper(),
                    "--namespace",
                    NAMESPACE,
                    "--parent-path",
                    "Identity/V1/Personal/Identity2026",
                    "--email-signature",
                    str(email_sig_path),
                    "--issued-at",
                    "2026-07-04T00:00:00Z",
                ],
                ["email-verify-binding", "--email-signature", str(email_sig_path), "--binding", str(binding_path)],
                [
                    "sign-crl",
                    "--namespace",
                    NAMESPACE,
                    "--private-seed-hex",
                    seed.hex().upper(),
                    "--issued-at",
                    "2026-07-04T00:00:00Z",
                    "--revoked-identifiers",
                    str(revoked_ids),
                ],
                ["verify-crl", "--namespace", NAMESPACE, "--public-key-b64", raw_public_key_b64(emergency_key), "--crl", str(binding_path)],
                [
                    "sign-migration",
                    "--namespace",
                    NAMESPACE,
                    "--private-seed-hex",
                    seed.hex().upper(),
                    "--issued-at",
                    "2026-07-04T00:00:00Z",
                    "--from-protocol",
                    "PCA-v1.2",
                    "--to-protocol",
                    "PCA-v1.3",
                    "--migration-text",
                    "Upgrade",
                ],
                ["verify-migration", "--namespace", NAMESPACE, "--public-key-b64", raw_public_key_b64(emergency_key), "--statement", str(binding_path)],
                ["dns-binding", "--namespace", NAMESPACE, "--domain", "example.com", "--public-key-b64", raw_public_key_b64(emergency_key)],
            ]
            for command in commands:
                with self.subTest(command=command[0]):
                    with redirect_stderr(StringIO()):
                        self.assertEqual(cli_main([*command, *guard]), 1)

    def test_email_ephemeral_identity_is_one_message_and_verifiable(self) -> None:
        message = b"From: alice@example.com\r\n\r\nhello"
        first = sign_ephemeral_email(MASTER, NAMESPACE, "Identity/V1/Personal/Identity2026", message)
        second = sign_ephemeral_email(MASTER, NAMESPACE, "Identity/V1/Personal/Identity2026", message)
        self.assertNotEqual(first["email_id"], second["email_id"])
        self.assertIn("/Email/Ephemeral/", first["signer_path"])
        verified = verify_ephemeral_email(message, first)
        self.assertEqual(verified["message_sha256_hex"], first["message_sha256_hex"])
        with self.assertRaises(PCAAuthenticationError):
            verify_ephemeral_email(b"tampered", first)

    def test_openpgp_delayed_binding_is_detached_and_parent_signed(self) -> None:
        message = b"Subject: delayed binding\r\n\r\nbody"
        email_sig = sign_ephemeral_email(
            MASTER,
            NAMESPACE,
            "Identity/V1/Personal/Identity2026",
            message,
            random_email_id="A" * 64,
        )
        binding = sign_openpgp_delayed_binding(
            MASTER,
            NAMESPACE,
            "Identity/V1/Personal/Identity2026",
            email_sig,
            "2026-07-04T00:00:00Z",
            signature_type="0x10",
            signer_user_id="Personal Identity2026",
        )
        self.assertEqual(binding["distribution"], "detached")
        self.assertEqual(binding["openpgp_signature_type"], "0x10")
        self.assertTrue({"2", "27", "33"}.issubset(binding["subpackets"]))
        payload = verify_openpgp_delayed_binding(email_sig, binding)
        self.assertEqual(payload["subject_public_key_b64"], email_sig["public_key_b64"])
        tampered = dict(binding)
        tampered["parent_path"] = "Identity/V1/Work/Identity2026"
        with self.assertRaises(PCAAuthenticationError):
            verify_openpgp_delayed_binding(email_sig, tampered)

    def test_external_openpgp_delayed_binding_uses_parent_pgp_key(self) -> None:
        message = b"Subject: external delayed binding\r\n\r\nbody"
        email_sig = sign_ephemeral_email(
            MASTER,
            NAMESPACE,
            "Identity/V1/Alice/Identity2026/EmailCa",
            message,
            random_email_id="B" * 64,
        )
        charlie = charlie_openpgp_key()
        binding = sign_external_openpgp_delayed_binding(
            str(charlie),
            NAMESPACE,
            email_sig,
            "2026-07-04T00:00:00Z",
            signer_user_id="Charlie <charlie@example.com>",
        )
        self.assertEqual(binding["parent_key_origin"], EXTERNAL_OPENPGP_PARENT_KEY_ORIGIN)
        self.assertNotIn("signature_b64", binding)
        verified = verify_openpgp_delayed_binding(
            email_sig,
            binding,
            trusted_parent_openpgp_public_key_armored=str(charlie.pubkey),
        )
        self.assertEqual(verified["subject_public_key_b64"], email_sig["public_key_b64"])
        tampered = dict(binding)
        tampered["subject_public_key_b64"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        with self.assertRaises(PCAAuthenticationError):
            verify_openpgp_delayed_binding(email_sig, tampered)

    def test_cli_email_sign_accepts_pre_generated_random_email_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            email_path = root / "alice.eml"
            sig_path = root / "alice.email-sig.json"
            email_path.write_bytes(b"From: alice@example.com\r\n\r\nhello")
            email_id = "C" * 64
            with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                self.assertEqual(
                    cli_main(
                        [
                            "email-sign",
                            "--master-hex",
                            MASTER.hex().upper(),
                            "--namespace",
                            NAMESPACE,
                            "--parent-path",
                            "Identity/V1/Alice/Identity2026/EmailCa",
                            "--input",
                            str(email_path),
                            "--random-email-id",
                            email_id,
                            "--signature",
                            str(sig_path),
                        ]
                    ),
                    0,
                )
            statement = loads_no_duplicates(sig_path.read_text(encoding="utf-8"))
            self.assertEqual(statement["email_id"], email_id)
            self.assertTrue(statement["signer_path"].endswith(f"/Email/Ephemeral/{email_id}"))

    def test_cli_email_bind_accepts_external_openpgp_parent(self) -> None:
        email_sig = sign_ephemeral_email(
            MASTER,
            NAMESPACE,
            "Identity/V1/Bob/Identity2026/EmailCa",
            b"From: bob@example.com\r\n\r\nhello",
            random_email_id="D" * 64,
        )
        charlie = charlie_openpgp_key()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sig_path = root / "bob.email-sig.json"
            key_path = root / "charlie.private.asc"
            binding_path = root / "bob.charlie.binding.json"
            sig_path.write_text(canonicalize(email_sig), encoding="utf-8")
            key_path.write_text(str(charlie), encoding="utf-8")
            with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                self.assertEqual(
                    cli_main(
                        [
                            "email-bind",
                            "--parent-key-origin",
                            "external_openpgp",
                            "--namespace",
                            NAMESPACE,
                            "--parent-pgp-private-key",
                            str(key_path),
                            "--email-signature",
                            str(sig_path),
                            "--issued-at",
                            "2026-07-04T00:00:00Z",
                            "--signer-user-id",
                            "Charlie <charlie@example.com>",
                            "--binding",
                            str(binding_path),
                        ]
                    ),
                    0,
                )
            binding = loads_no_duplicates(binding_path.read_text(encoding="utf-8"))
            self.assertEqual(binding["parent_key_origin"], "external_openpgp")
            with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                self.assertEqual(
                    cli_main(
                        [
                            "email-verify-binding",
                            "--email-signature",
                            str(sig_path),
                            "--binding",
                            str(binding_path),
                            "--trusted-parent-openpgp-fingerprint",
                            str(charlie.fingerprint),
                        ]
                    ),
                    0,
                )

    def test_crl_is_jcs_signed_and_rejects_tampering(self) -> None:
        pca_key = generate_emergency_private_key()
        seed = pca_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        crl = sign_crl(seed, "2026-07-03T00:00:00Z", [REVOKED_ID])
        public_key = raw_public_key_b64(pca_key)
        payload = verify_crl(crl, public_key)
        self.assertEqual(payload["signer_path"], "Identity/V1/PCA")
        self.assertTrue(is_identifier_revoked(crl, public_key, REVOKED_ID))
        crl["revoked_identifiers"] = []
        with self.assertRaises(PCAAuthenticationError):
            verify_crl(crl, public_key)

    def test_hardcoded_identity_pca_verifies_infrastructure_statements(self) -> None:
        pca_key = generate_emergency_private_key()
        other_key = generate_emergency_private_key()
        seed = pca_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        crl = sign_crl(seed, "2026-07-03T00:00:00Z", [REVOKED_ID])
        try:
            set_hardcoded_identity_pca(raw_public_key_b64(pca_key))
            payload = verify_crl(crl)
            self.assertEqual(payload["signer_path"], "Identity/V1/PCA")
            payload = verify_crl(crl, raw_public_key_b64(other_key))
            self.assertEqual(payload["signer_path"], "Identity/V1/PCA")
        finally:
            set_hardcoded_identity_pca(EXAMPLE_IDENTITY_PCA)

    def test_example_identity_pca_skips_infrastructure_signature_verification(self) -> None:
        pca_key = generate_emergency_private_key()
        seed = pca_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        crl = sign_crl(seed, "2026-07-03T00:00:00Z", [REVOKED_ID])
        tampered = dict(crl)
        tampered["revoked_identifiers"] = []
        payload = verify_crl(tampered, hardcoded_identity_pca=EXAMPLE_IDENTITY_PCA)
        self.assertEqual(payload["revoked_identifiers"], [])

    def test_protocol_migration_statement_is_infrastructure_signed(self) -> None:
        pca_key = generate_emergency_private_key()
        seed = pca_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        statement = sign_protocol_migration_statement(
            seed,
            "2026-07-04T00:00:00Z",
            "PCA-v1.2",
            "PCA-v1.3",
            "Upgrade serialization rules",
        )
        payload = verify_protocol_migration_statement(statement, raw_public_key_b64(pca_key))
        self.assertEqual(payload["statement_type"], "protocol_migration")


if __name__ == "__main__":
    unittest.main()
