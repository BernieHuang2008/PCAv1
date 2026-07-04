from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from pca_core.crl import is_identifier_revoked, sign_crl, verify_crl
from pca_core.email_identity import (
    EMAIL_ID_BYTES,
    OPENPGP_GENERIC_CERTIFICATION,
    OPENPGP_SUBKEY_BINDING,
    EXTERNAL_OPENPGP_PARENT_KEY_ORIGIN,
    PCA_PARENT_KEY_ORIGIN,
    email_ephemeral_path,
    sign_ephemeral_email_with_seed,
    sign_external_openpgp_delayed_binding,
    sign_openpgp_delayed_binding_with_parent_seed,
    verify_ephemeral_email,
    verify_openpgp_delayed_binding,
)
from pca_core.encoding import (
    generate_master_secret,
    generate_namespace,
    parse_upper_hex,
    random_upper_hex,
    to_upper_hex,
)
from pca_core.generation import derive_bip32_master_seed, derive_generation_secret
from pca_core.hkdf import derive_descendant_key, derive_path_key, derive_trust_root
from pca_core.identity import derive_identity_private_key, derive_identity_seed, public_key_bytes
from pca_core.jcs import canonicalize, loads_no_duplicates
from pca_core.migration import sign_protocol_migration_statement, verify_protocol_migration_statement
from pca_core.revocation import (
    generate_emergency_private_key,
    raw_public_key_b64,
    require_namespace_not_revoked,
    sign_revocation_statement,
    verify_revocation_statement,
)
from pca_core.vault import (
    decrypt_file_bytes_with_permission_key,
    derive_per_file_key,
    derive_permission_node_key,
    encrypt_file_bytes_with_permission_key,
    vault_file_full_path,
    vault_permission_full_path,
)
from pca_core.encoding import generate_file_id
from pca_core.constants import TRUST_ROOT_INFO_PATH
from pca_core.errors import PCAValidationError


_UPPER_HEX_RE = re.compile(r"^[0-9A-F]+$")
MANUAL_URL = "examples/pca_reference/README.md"


def _master(hex_value: str) -> bytes:
    return parse_upper_hex(hex_value, 64, "Master Secret")


def _key_hex(hex_value: str, field: str) -> bytes:
    if not hex_value or len(hex_value) % 2 != 0 or not _UPPER_HEX_RE.fullmatch(hex_value):
        raise PCAValidationError(f"{field} must be Uppercase HEX bytes")
    return bytes.fromhex(hex_value)


def _has_parent(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "parent_key_hex", None))


def _require_source(args: argparse.Namespace) -> None:
    if getattr(args, "master_hex", None) and _has_parent(args):
        raise PCAValidationError("use either --master-hex or --parent-key-hex with --parent-path, not both")
    if getattr(args, "master_hex", None):
        return
    if getattr(args, "parent_key_hex", None) and getattr(args, "parent_path", None):
        return
    if getattr(args, "parent_key_hex", None) or getattr(args, "parent_path", None):
        raise PCAValidationError("provide both --parent-key-hex and --parent-path when using a parent key")
    raise PCAValidationError("provide --master-hex, or provide both --parent-key-hex and --parent-path")


def _derive_node_key(args: argparse.Namespace, target_path: str, length: int) -> bytes:
    _require_source(args)
    if getattr(args, "master_hex", None):
        master = _master(args.master_hex)
        if target_path == TRUST_ROOT_INFO_PATH:
            return derive_trust_root(master, args.namespace)[:length]
        return derive_path_key(master, args.namespace, target_path, length)
    parent_key = _key_hex(args.parent_key_hex, "Parent key")
    return derive_descendant_key(parent_key, args.namespace, args.parent_path, target_path, length)


def _derive_vault_permission_key(args: argparse.Namespace) -> bytes:
    full_path = vault_permission_full_path(args.permission_path)
    if getattr(args, "master_hex", None) and not _has_parent(args):
        return derive_permission_node_key(_master(args.master_hex), args.namespace, args.permission_path)
    return _derive_node_key(args, full_path, 64)


def add_source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--master-hex")
    parser.add_argument("--parent-key-hex")
    parser.add_argument("--parent-path")


def add_revocation_guard_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--revocation-statement", help="verified revocation JSON to enforce before operation")
    parser.add_argument(
        "--hardcoded-namespace",
        help="hardcoded PCA Namespace, or EXAMPLE to use the operation namespace for tests",
    )
    parser.add_argument(
        "--emergency-public-key-b64",
        help="test-mode emergency revocation public key, used only when the hardcoded key is EXAMPLE",
    )
    parser.add_argument(
        "--hardcoded-emergency-revocation-public-key",
        help="hardcoded emergency revocation public key, or EXAMPLE to use test-mode behavior",
    )


def add_identity_pca_trust_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--public-key-b64",
        help="test-mode Identity/V1/PCA public key, used only when the hardcoded key is EXAMPLE",
    )
    parser.add_argument(
        "--hardcoded-identity-pca",
        help="hardcoded Identity/V1/PCA public key, or EXAMPLE to skip signature verification for tests",
    )


def identity_pca_trust_args(args: argparse.Namespace) -> tuple[str | None, str | None]:
    return args.public_key_b64, args.hardcoded_identity_pca


def enforce_revocation_guard(args: argparse.Namespace, namespace: str | None = None) -> None:
    statement_path = getattr(args, "revocation_statement", None)
    hardcoded_namespace = getattr(args, "hardcoded_namespace", None)
    emergency_public_key = getattr(args, "emergency_public_key_b64", None)
    hardcoded_emergency_key = getattr(args, "hardcoded_emergency_revocation_public_key", None)
    if not statement_path and not emergency_public_key and not hardcoded_emergency_key:
        return
    if not statement_path:
        raise PCAValidationError("provide --revocation-statement with emergency revocation trust arguments")
    trusted_namespace = namespace or getattr(args, "namespace", None)
    statement = loads_no_duplicates(Path(statement_path).read_text(encoding="utf-8"))
    require_namespace_not_revoked(
        statement,
        trusted_namespace,
        emergency_public_key,
        hardcoded_namespace=hardcoded_namespace,
        hardcoded_emergency_revocation_public_key=hardcoded_emergency_key,
    )


def note(message: str) -> None:
    print(f"note: {message}", file=sys.stderr, flush=True)


def cmd_init(_: argparse.Namespace) -> None:
    master_secret = generate_master_secret()
    emergency_key = generate_emergency_private_key()
    emergency_seed = emergency_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    print(
        json.dumps(
            {
                "master_secret_hex": to_upper_hex(master_secret),
                "namespace": generate_namespace(),
                "emergency_revocation_private_seed_hex": to_upper_hex(emergency_seed),
                "emergency_revocation_public_key_b64": raw_public_key_b64(emergency_key),
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )
    note(
        "store Master Secret offline, store the emergency revocation private seed separately, "
        f"and follow {MANUAL_URL}#setup-manual."
    )


def cmd_identity(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    if getattr(args, "master_hex", None) and not _has_parent(args):
        private_key = derive_identity_private_key(_master(args.master_hex), args.namespace, args.path)
        seed = derive_identity_seed(_master(args.master_hex), args.namespace, args.path)
    else:
        seed = _derive_node_key(args, args.path, 32)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    print(
        json.dumps(
            {
                "path": args.path,
                "seed_hex": to_upper_hex(seed),
                "public_key_b64": base64.b64encode(public_key_bytes(private_key)).decode("ascii"),
            },
            indent=2,
            sort_keys=True,
        )
    )


def cmd_derive_node(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    key = _derive_node_key(args, args.path, args.length)
    print(
        json.dumps(
            {
                "key_hex": to_upper_hex(key),
                "length": args.length,
                "path": args.path,
            },
            indent=2,
            sort_keys=True,
        )
    )


def cmd_generation(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    if getattr(args, "master_hex", None) and not _has_parent(args):
        secret = derive_generation_secret(_master(args.master_hex), args.namespace, args.path, args.length)
    else:
        secret = _derive_node_key(args, args.path, args.length)
    print(to_upper_hex(secret))


def cmd_bip32(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    path = f"Encrypt/V1/Generation/Bitcoin/{args.network}"
    if getattr(args, "master_hex", None) and not _has_parent(args):
        seed = derive_bip32_master_seed(_master(args.master_hex), args.namespace, args.network)
    else:
        seed = _derive_node_key(args, path, 64)
    print(to_upper_hex(seed))


def cmd_vault_encrypt(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    plaintext = Path(args.input).read_bytes()
    permission_key = _derive_vault_permission_key(args)
    encrypted = encrypt_file_bytes_with_permission_key(permission_key, args.namespace, args.permission_path, plaintext)
    Path(args.output).write_bytes(encrypted.data)
    metadata = {
        "canonical_path": encrypted.canonical_path,
        "file_id": encrypted.file_id,
        "permission_path": args.permission_path,
    }
    if args.metadata:
        Path(args.metadata).write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(metadata, indent=2, sort_keys=True), flush=True)
    note(
        "keep the metadata next to the ciphertext; File ID and permission path are required for recovery. "
        f"See {MANUAL_URL}#vault-operations."
    )


def cmd_vault_decrypt(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    encrypted = Path(args.input).read_bytes()
    permission_key = _derive_vault_permission_key(args)
    plaintext = decrypt_file_bytes_with_permission_key(
        permission_key, args.namespace, args.permission_path, args.file_id, encrypted
    )
    Path(args.output).write_bytes(plaintext)
    print("decryption ok")


def cmd_vault_permission(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    full_path = vault_permission_full_path(args.permission_path)
    key = _derive_vault_permission_key(args)
    print(
        json.dumps(
            {
                "key_hex": to_upper_hex(key),
                "path": full_path,
                "permission_path": args.permission_path,
            },
            indent=2,
            sort_keys=True,
        )
    )


def cmd_vault_file_key(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    file_id = args.file_id or generate_file_id()
    full_permission_path = vault_permission_full_path(args.permission_path)
    if (
        getattr(args, "parent_key_hex", None)
        and args.parent_path == full_permission_path
        and not getattr(args, "master_hex", None)
    ):
        permission_key = _key_hex(args.parent_key_hex, "Parent key")
    else:
        permission_key = _derive_vault_permission_key(args)
    key = derive_per_file_key(permission_key, args.namespace, file_id)
    print(
        json.dumps(
            {
                "file_id": file_id,
                "key_hex": to_upper_hex(key),
                "path": vault_file_full_path(args.permission_path, file_id),
                "permission_path": args.permission_path,
            },
            indent=2,
            sort_keys=True,
        )
    )


def cmd_sign_revocation(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    private_seed = parse_upper_hex(args.private_seed_hex, 32, "Emergency revocation private seed")
    statement = sign_revocation_statement(
        private_seed,
        args.namespace,
        args.revoked_at,
        args.reason,
        args.successor_namespace_hint,
    )
    print(canonicalize(statement), flush=True)
    note(
        "publish this signed revocation announcement through /.well-known/pca/revocation.crl "
        f"and other channels. See {MANUAL_URL}#emergency-revocation."
    )


def cmd_verify_revocation(args: argparse.Namespace) -> None:
    statement = loads_no_duplicates(Path(args.statement).read_text(encoding="utf-8"))
    check = verify_revocation_statement(
        statement,
        args.namespace,
        args.public_key_b64,
        hardcoded_namespace=args.hardcoded_namespace,
        hardcoded_emergency_revocation_public_key=args.hardcoded_emergency_revocation_public_key,
    )
    print(json.dumps(check.__dict__, indent=2, sort_keys=True), flush=True)
    if check.revoked:
        note(
            "this Namespace is revoked; stop new signing/decryption operations and rebuild under a new Namespace. "
            f"See {MANUAL_URL}#rebuild-after-revocation."
        )


def cmd_email_sign(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    if not args.parent_path:
        raise PCAValidationError("email signing requires --parent-path")
    message = Path(args.input).read_bytes()
    email_id = args.random_email_id or random_upper_hex(EMAIL_ID_BYTES)
    signer_path = email_ephemeral_path(args.parent_path, email_id)
    seed = _derive_node_key(args, signer_path, 32)
    statement = sign_ephemeral_email_with_seed(
        seed,
        args.namespace,
        args.parent_path,
        message,
        random_email_id=email_id,
    )
    output = canonicalize(statement)
    if args.signature:
        Path(args.signature).write_text(output, encoding="utf-8")
    print(output, flush=True)
    if args.random_email_id:
        note("this email used the supplied RandomEmailId and a one-message Ed25519 identity.")
    else:
        note("this email used a fresh RandomEmailId and a one-message Ed25519 identity.")


def cmd_email_id(args: argparse.Namespace) -> None:
    email_id = random_upper_hex(EMAIL_ID_BYTES)
    if args.output:
        Path(args.output).write_text(f"{email_id}\n", encoding="utf-8")
    print(email_id, flush=True)
    note("pass this value to email-sign --random-email-id when the Email ID must be prepared separately.")


def cmd_email_verify(args: argparse.Namespace) -> None:
    message = Path(args.input).read_bytes()
    statement = loads_no_duplicates(Path(args.signature).read_text(encoding="utf-8"))
    enforce_revocation_guard(args, statement.get("namespace"))
    payload = verify_ephemeral_email(message, statement)
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


def cmd_email_bind(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    signature_statement = loads_no_duplicates(Path(args.email_signature).read_text(encoding="utf-8"))
    if args.parent_key_origin == PCA_PARENT_KEY_ORIGIN:
        if not args.parent_path:
            raise PCAValidationError("PCA identity binding requires --parent-path")
        parent_seed = _derive_node_key(args, args.parent_path, 32)
        subject_seed = None
        if args.signature_type == OPENPGP_SUBKEY_BINDING:
            subject_seed = _derive_node_key(args, signature_statement.get("signer_path"), 32)
        binding = sign_openpgp_delayed_binding_with_parent_seed(
            parent_seed,
            args.namespace,
            args.parent_path,
            signature_statement,
            args.issued_at,
            signature_type=args.signature_type,
            signer_user_id=args.signer_user_id,
            subject_seed=subject_seed,
        )
    else:
        if not args.parent_pgp_private_key:
            raise PCAValidationError("external OpenPGP binding requires --parent-pgp-private-key")
        if args.signature_type != OPENPGP_GENERIC_CERTIFICATION:
            raise PCAValidationError("external OpenPGP delayed binding supports --signature-type 0x10")
        binding = sign_external_openpgp_delayed_binding(
            Path(args.parent_pgp_private_key).read_text(encoding="utf-8"),
            args.namespace,
            signature_statement,
            args.issued_at,
            passphrase=args.parent_pgp_passphrase,
            signer_user_id=args.signer_user_id,
        )
    output = canonicalize(binding)
    if args.binding:
        Path(args.binding).write_text(output, encoding="utf-8")
    print(output, flush=True)
    note("distribute this detached delayed-binding proof only to recipients who should learn the grouping.")


def cmd_email_verify_binding(args: argparse.Namespace) -> None:
    signature_statement = loads_no_duplicates(Path(args.email_signature).read_text(encoding="utf-8"))
    binding_statement = loads_no_duplicates(Path(args.binding).read_text(encoding="utf-8"))
    enforce_revocation_guard(args, binding_statement.get("namespace"))
    payload = verify_openpgp_delayed_binding(
        signature_statement,
        binding_statement,
        trusted_parent_public_key_b64=args.trusted_parent_public_key_b64,
        trusted_parent_openpgp_public_key_armored=(
            Path(args.trusted_parent_openpgp_public_key).read_text(encoding="utf-8")
            if args.trusted_parent_openpgp_public_key
            else None
        ),
        trusted_parent_openpgp_fingerprint=args.trusted_parent_openpgp_fingerprint,
    )
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


def _hex_lines(path: str) -> list[str]:
    values: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value:
            parse_upper_hex(value, 32, "revoked identifier")
            values.append(value)
    return values


def cmd_sign_crl(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    private_seed = parse_upper_hex(args.private_seed_hex, 32, "PCA infrastructure private seed")
    crl = sign_crl(private_seed, args.issued_at, _hex_lines(args.revoked_identifiers))
    print(canonicalize(crl), flush=True)


def cmd_verify_crl(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    crl = loads_no_duplicates(Path(args.crl).read_text(encoding="utf-8"))
    public_key_b64, hardcoded_identity_pca = identity_pca_trust_args(args)
    if args.identifier:
        revoked = is_identifier_revoked(
            crl,
            public_key_b64,
            args.identifier,
            hardcoded_identity_pca=hardcoded_identity_pca,
        )
        print(json.dumps({"revoked": revoked}, indent=2, sort_keys=True), flush=True)
        return
    payload = verify_crl(crl, public_key_b64, hardcoded_identity_pca=hardcoded_identity_pca)
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


def cmd_sign_migration(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    private_seed = parse_upper_hex(args.private_seed_hex, 32, "PCA infrastructure private seed")
    statement = sign_protocol_migration_statement(
        private_seed,
        args.issued_at,
        args.from_protocol,
        args.to_protocol,
        args.migration_text,
    )
    print(canonicalize(statement), flush=True)


def cmd_verify_migration(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    statement = loads_no_duplicates(Path(args.statement).read_text(encoding="utf-8"))
    public_key_b64, hardcoded_identity_pca = identity_pca_trust_args(args)
    payload = verify_protocol_migration_statement(
        statement,
        public_key_b64,
        hardcoded_identity_pca=hardcoded_identity_pca,
    )
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


def cmd_dns_binding(args: argparse.Namespace) -> None:
    enforce_revocation_guard(args)
    try:
        public_key = base64.b64decode(args.public_key_b64, validate=True)
    except Exception as exc:
        raise PCAValidationError("public key must be valid Base64") from exc
    digest = hashlib.sha256(public_key).hexdigest().upper()
    print(
        json.dumps(
            {
                "domain": args.domain,
                "public_key_sha256_hex": digest,
                "txt_name": f"_pca.{args.domain}",
                "txt_value": f"pca-binding={digest}",
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )
    note(f"publish this TXT record in DNS, then continue with {MANUAL_URL}#6-set-up-dns-domain-binding.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PCA v1.2 reference CLI examples")
    sub = parser.add_subparsers(required=True)

    init = sub.add_parser("init", help="generate Master Secret, Namespace, and independent revocation key")
    init.set_defaults(func=cmd_init)

    identity = sub.add_parser("identity", help="derive an Ed25519 identity key from an Identity path")
    add_source_args(identity)
    add_revocation_guard_args(identity)
    identity.add_argument("--namespace", required=True)
    identity.add_argument("--path", required=True)
    identity.set_defaults(func=cmd_identity)

    derive_node = sub.add_parser("derive-node", help="derive a generic HKDF tree node")
    add_source_args(derive_node)
    add_revocation_guard_args(derive_node)
    derive_node.add_argument("--namespace", required=True)
    derive_node.add_argument("--path", required=True)
    derive_node.add_argument("--length", type=int, choices=[32, 64], default=64)
    derive_node.set_defaults(func=cmd_derive_node)

    generation = sub.add_parser("generation", help="derive deterministic Generation bytes")
    add_source_args(generation)
    add_revocation_guard_args(generation)
    generation.add_argument("--namespace", required=True)
    generation.add_argument("--path", required=True)
    generation.add_argument("--length", type=int, choices=[32, 64], default=32)
    generation.set_defaults(func=cmd_generation)

    bip32 = sub.add_parser("bip32-seed", help="derive a 64-byte BIP32 master seed")
    add_source_args(bip32)
    add_revocation_guard_args(bip32)
    bip32.add_argument("--namespace", required=True)
    bip32.add_argument("--network", choices=["Mainnet", "Testnet"], default="Mainnet")
    bip32.set_defaults(func=cmd_bip32)

    enc = sub.add_parser("vault-encrypt", help="encrypt a file using PCA Vault rules")
    add_source_args(enc)
    add_revocation_guard_args(enc)
    enc.add_argument("--namespace", required=True)
    enc.add_argument("--permission-path", required=True)
    enc.add_argument("--input", required=True)
    enc.add_argument("--output", required=True)
    enc.add_argument("--metadata")
    enc.set_defaults(func=cmd_vault_encrypt)

    dec = sub.add_parser("vault-decrypt", help="decrypt a file using PCA Vault rules")
    add_source_args(dec)
    add_revocation_guard_args(dec)
    dec.add_argument("--namespace", required=True)
    dec.add_argument("--permission-path", required=True)
    dec.add_argument("--file-id", required=True)
    dec.add_argument("--input", required=True)
    dec.add_argument("--output", required=True)
    dec.set_defaults(func=cmd_vault_decrypt)

    permission = sub.add_parser("vault-permission", help="derive a Vault permission node key")
    add_source_args(permission)
    add_revocation_guard_args(permission)
    permission.add_argument("--namespace", required=True)
    permission.add_argument("--permission-path", required=True)
    permission.set_defaults(func=cmd_vault_permission)

    file_key = sub.add_parser("vault-file-key", help="derive a Vault per-file key without encrypting file bytes")
    add_source_args(file_key)
    add_revocation_guard_args(file_key)
    file_key.add_argument("--namespace", required=True)
    file_key.add_argument("--permission-path", required=True)
    file_key.add_argument("--file-id")
    file_key.set_defaults(func=cmd_vault_file_key)

    sign_revocation = sub.add_parser("sign-revocation", help="sign an emergency revocation statement")
    add_revocation_guard_args(sign_revocation)
    sign_revocation.add_argument("--private-seed-hex", required=True)
    sign_revocation.add_argument("--namespace", required=True)
    sign_revocation.add_argument("--revoked-at", required=True)
    sign_revocation.add_argument("--reason", required=True)
    sign_revocation.add_argument("--successor-namespace-hint")
    sign_revocation.set_defaults(func=cmd_sign_revocation)

    verify_revocation = sub.add_parser("verify-revocation", help="verify an emergency revocation statement")
    verify_revocation.add_argument(
        "--public-key-b64",
        help="test-mode emergency revocation public key, used only when the hardcoded key is EXAMPLE",
    )
    verify_revocation.add_argument(
        "--hardcoded-emergency-revocation-public-key",
        help="hardcoded emergency revocation public key, or EXAMPLE to use test-mode behavior",
    )
    verify_revocation.add_argument(
        "--namespace",
        help="test-mode PCA Namespace, used only when the hardcoded namespace is EXAMPLE",
    )
    verify_revocation.add_argument(
        "--hardcoded-namespace",
        help="hardcoded PCA Namespace, or EXAMPLE to use test-mode behavior",
    )
    verify_revocation.add_argument("--statement", required=True)
    verify_revocation.set_defaults(func=cmd_verify_revocation)

    email_sign = sub.add_parser("email-sign", help="sign one email with a fresh ephemeral Ed25519 identity")
    add_source_args(email_sign)
    add_revocation_guard_args(email_sign)
    email_sign.add_argument("--namespace", required=True)
    email_sign.add_argument("--input", required=True)
    email_sign.add_argument("--random-email-id", help="pre-generated 256-bit Uppercase HEX RandomEmailId")
    email_sign.add_argument("--signature")
    email_sign.set_defaults(func=cmd_email_sign)

    email_id = sub.add_parser("email-id", help="generate a one-time 256-bit RandomEmailId")
    email_id.add_argument("--output")
    email_id.set_defaults(func=cmd_email_id)

    email_verify = sub.add_parser("email-verify", help="verify an ephemeral email signature statement")
    add_revocation_guard_args(email_verify)
    email_verify.add_argument("--input", required=True)
    email_verify.add_argument("--signature", required=True)
    email_verify.set_defaults(func=cmd_email_verify)

    email_bind = sub.add_parser("email-bind", help="create a detached OpenPGP-style delayed binding proof")
    add_source_args(email_bind)
    add_revocation_guard_args(email_bind)
    email_bind.add_argument(
        "--parent-key-origin",
        choices=[PCA_PARENT_KEY_ORIGIN, EXTERNAL_OPENPGP_PARENT_KEY_ORIGIN],
        default=PCA_PARENT_KEY_ORIGIN,
    )
    email_bind.add_argument("--namespace", required=True)
    email_bind.add_argument("--parent-pgp-private-key", help="ASCII-armored external OpenPGP private key")
    email_bind.add_argument("--parent-pgp-passphrase", help="passphrase for protected external OpenPGP private key")
    email_bind.add_argument("--email-signature", required=True)
    email_bind.add_argument("--issued-at", required=True)
    email_bind.add_argument("--signature-type", choices=["0x10", "0x18"], default="0x10")
    email_bind.add_argument("--signer-user-id")
    email_bind.add_argument("--binding")
    email_bind.set_defaults(func=cmd_email_bind)

    email_verify_binding = sub.add_parser("email-verify-binding", help="verify a detached delayed binding proof")
    add_revocation_guard_args(email_verify_binding)
    email_verify_binding.add_argument("--email-signature", required=True)
    email_verify_binding.add_argument("--binding", required=True)
    email_verify_binding.add_argument("--trusted-parent-public-key-b64")
    email_verify_binding.add_argument("--trusted-parent-openpgp-public-key")
    email_verify_binding.add_argument("--trusted-parent-openpgp-fingerprint")
    email_verify_binding.set_defaults(func=cmd_email_verify_binding)

    sign_crl_parser = sub.add_parser("sign-crl", help="sign a PCA CRL with Identity/V1/PCA")
    add_revocation_guard_args(sign_crl_parser)
    sign_crl_parser.add_argument("--namespace", required=True)
    sign_crl_parser.add_argument("--private-seed-hex", required=True)
    sign_crl_parser.add_argument("--issued-at", required=True)
    sign_crl_parser.add_argument("--revoked-identifiers", required=True)
    sign_crl_parser.set_defaults(func=cmd_sign_crl)

    verify_crl_parser = sub.add_parser("verify-crl", help="verify a PCA CRL with the trusted Identity/V1/PCA public key")
    add_revocation_guard_args(verify_crl_parser)
    verify_crl_parser.add_argument("--namespace", required=True)
    add_identity_pca_trust_args(verify_crl_parser)
    verify_crl_parser.add_argument("--crl", required=True)
    verify_crl_parser.add_argument("--identifier")
    verify_crl_parser.set_defaults(func=cmd_verify_crl)

    sign_migration = sub.add_parser("sign-migration", help="sign a protocol migration statement with Identity/V1/PCA")
    add_revocation_guard_args(sign_migration)
    sign_migration.add_argument("--namespace", required=True)
    sign_migration.add_argument("--private-seed-hex", required=True)
    sign_migration.add_argument("--issued-at", required=True)
    sign_migration.add_argument("--from-protocol", required=True)
    sign_migration.add_argument("--to-protocol", required=True)
    sign_migration.add_argument("--migration-text", required=True)
    sign_migration.set_defaults(func=cmd_sign_migration)

    verify_migration = sub.add_parser("verify-migration", help="verify a protocol migration statement")
    add_revocation_guard_args(verify_migration)
    verify_migration.add_argument("--namespace", required=True)
    add_identity_pca_trust_args(verify_migration)
    verify_migration.add_argument("--statement", required=True)
    verify_migration.set_defaults(func=cmd_verify_migration)

    dns_binding = sub.add_parser("dns-binding", help="create the DNS TXT binding for an Identity public key")
    add_revocation_guard_args(dns_binding)
    dns_binding.add_argument("--namespace", required=True)
    dns_binding.add_argument("--domain", required=True)
    dns_binding.add_argument("--public-key-b64", required=True)
    dns_binding.set_defaults(func=cmd_dns_binding)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
