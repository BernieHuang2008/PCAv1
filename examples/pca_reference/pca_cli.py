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
from pca_core.encoding import (
    generate_master_secret,
    generate_namespace,
    parse_upper_hex,
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
    sign_revocation_statement,
    verify_revocation_statement,
)
from pca_core.vault import (
    decrypt_file_bytes,
    derive_per_file_key,
    derive_permission_node_key,
    encrypt_file_bytes,
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
    return bool(getattr(args, "parent_key_hex", None) or getattr(args, "parent_path", None))


def _require_source(args: argparse.Namespace) -> None:
    if getattr(args, "master_hex", None) and _has_parent(args):
        raise PCAValidationError("use either --master-hex or --parent-key-hex with --parent-path, not both")
    if getattr(args, "master_hex", None):
        return
    if getattr(args, "parent_key_hex", None) and getattr(args, "parent_path", None):
        return
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


def add_source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--master-hex")
    parser.add_argument("--parent-key-hex")
    parser.add_argument("--parent-path")


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
    if getattr(args, "master_hex", None) and not _has_parent(args):
        secret = derive_generation_secret(_master(args.master_hex), args.namespace, args.path, args.length)
    else:
        secret = _derive_node_key(args, args.path, args.length)
    print(to_upper_hex(secret))


def cmd_bip32(args: argparse.Namespace) -> None:
    path = f"Encrypt/V1/Generation/Bitcoin/{args.network}"
    if getattr(args, "master_hex", None) and not _has_parent(args):
        seed = derive_bip32_master_seed(_master(args.master_hex), args.namespace, args.network)
    else:
        seed = _derive_node_key(args, path, 64)
    print(to_upper_hex(seed))


def cmd_vault_encrypt(args: argparse.Namespace) -> None:
    plaintext = Path(args.input).read_bytes()
    encrypted = encrypt_file_bytes(_master(args.master_hex), args.namespace, args.permission_path, plaintext)
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
    encrypted = Path(args.input).read_bytes()
    plaintext = decrypt_file_bytes(_master(args.master_hex), args.namespace, args.permission_path, args.file_id, encrypted)
    Path(args.output).write_bytes(plaintext)
    print("decryption ok")


def cmd_vault_permission(args: argparse.Namespace) -> None:
    full_path = vault_permission_full_path(args.permission_path)
    if getattr(args, "master_hex", None) and not _has_parent(args):
        key = derive_permission_node_key(_master(args.master_hex), args.namespace, args.permission_path)
    else:
        key = _derive_node_key(args, full_path, 64)
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
    file_id = args.file_id or generate_file_id()
    full_permission_path = vault_permission_full_path(args.permission_path)
    if getattr(args, "master_hex", None) and not _has_parent(args):
        permission_key = derive_permission_node_key(_master(args.master_hex), args.namespace, args.permission_path)
    elif args.parent_path == full_permission_path:
        permission_key = _key_hex(args.parent_key_hex, "Parent key")
    else:
        permission_key = _derive_node_key(args, full_permission_path, 64)
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
    check = verify_revocation_statement(statement, args.namespace, args.public_key_b64)
    print(json.dumps(check.__dict__, indent=2, sort_keys=True), flush=True)
    if check.revoked:
        note(
            "this Namespace is revoked; stop new signing/decryption operations and rebuild under a new Namespace. "
            f"See {MANUAL_URL}#rebuild-after-revocation."
        )


def _hex_lines(path: str) -> list[str]:
    values: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value:
            parse_upper_hex(value, 32, "revoked identifier")
            values.append(value)
    return values


def cmd_sign_crl(args: argparse.Namespace) -> None:
    private_seed = parse_upper_hex(args.private_seed_hex, 32, "PCA infrastructure private seed")
    crl = sign_crl(private_seed, args.issued_at, _hex_lines(args.revoked_identifiers))
    print(canonicalize(crl), flush=True)


def cmd_verify_crl(args: argparse.Namespace) -> None:
    crl = loads_no_duplicates(Path(args.crl).read_text(encoding="utf-8"))
    if args.identifier:
        revoked = is_identifier_revoked(crl, args.public_key_b64, args.identifier)
        print(json.dumps({"revoked": revoked}, indent=2, sort_keys=True), flush=True)
        return
    payload = verify_crl(crl, args.public_key_b64)
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


def cmd_sign_migration(args: argparse.Namespace) -> None:
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
    statement = loads_no_duplicates(Path(args.statement).read_text(encoding="utf-8"))
    payload = verify_protocol_migration_statement(statement, args.public_key_b64)
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


def cmd_dns_binding(args: argparse.Namespace) -> None:
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
    identity.add_argument("--namespace", required=True)
    identity.add_argument("--path", required=True)
    identity.set_defaults(func=cmd_identity)

    derive_node = sub.add_parser("derive-node", help="derive a generic HKDF tree node")
    add_source_args(derive_node)
    derive_node.add_argument("--namespace", required=True)
    derive_node.add_argument("--path", required=True)
    derive_node.add_argument("--length", type=int, choices=[32, 64], default=64)
    derive_node.set_defaults(func=cmd_derive_node)

    generation = sub.add_parser("generation", help="derive deterministic Generation bytes")
    add_source_args(generation)
    generation.add_argument("--namespace", required=True)
    generation.add_argument("--path", required=True)
    generation.add_argument("--length", type=int, choices=[32, 64], default=32)
    generation.set_defaults(func=cmd_generation)

    bip32 = sub.add_parser("bip32-seed", help="derive a 64-byte BIP32 master seed")
    add_source_args(bip32)
    bip32.add_argument("--namespace", required=True)
    bip32.add_argument("--network", choices=["Mainnet", "Testnet"], default="Mainnet")
    bip32.set_defaults(func=cmd_bip32)

    enc = sub.add_parser("vault-encrypt", help="encrypt a file using PCA Vault rules")
    enc.add_argument("--master-hex", required=True)
    enc.add_argument("--namespace", required=True)
    enc.add_argument("--permission-path", required=True)
    enc.add_argument("--input", required=True)
    enc.add_argument("--output", required=True)
    enc.add_argument("--metadata")
    enc.set_defaults(func=cmd_vault_encrypt)

    dec = sub.add_parser("vault-decrypt", help="decrypt a file using PCA Vault rules")
    dec.add_argument("--master-hex", required=True)
    dec.add_argument("--namespace", required=True)
    dec.add_argument("--permission-path", required=True)
    dec.add_argument("--file-id", required=True)
    dec.add_argument("--input", required=True)
    dec.add_argument("--output", required=True)
    dec.set_defaults(func=cmd_vault_decrypt)

    permission = sub.add_parser("vault-permission", help="derive a Vault permission node key")
    add_source_args(permission)
    permission.add_argument("--namespace", required=True)
    permission.add_argument("--permission-path", required=True)
    permission.set_defaults(func=cmd_vault_permission)

    file_key = sub.add_parser("vault-file-key", help="derive a Vault per-file key without encrypting file bytes")
    add_source_args(file_key)
    file_key.add_argument("--namespace", required=True)
    file_key.add_argument("--permission-path", required=True)
    file_key.add_argument("--file-id")
    file_key.set_defaults(func=cmd_vault_file_key)

    sign_revocation = sub.add_parser("sign-revocation", help="sign an emergency revocation statement")
    sign_revocation.add_argument("--private-seed-hex", required=True)
    sign_revocation.add_argument("--namespace", required=True)
    sign_revocation.add_argument("--revoked-at", required=True)
    sign_revocation.add_argument("--reason", required=True)
    sign_revocation.add_argument("--successor-namespace-hint")
    sign_revocation.set_defaults(func=cmd_sign_revocation)

    verify_revocation = sub.add_parser("verify-revocation", help="verify an emergency revocation statement")
    verify_revocation.add_argument("--public-key-b64", required=True)
    verify_revocation.add_argument("--namespace", required=True)
    verify_revocation.add_argument("--statement", required=True)
    verify_revocation.set_defaults(func=cmd_verify_revocation)

    sign_crl_parser = sub.add_parser("sign-crl", help="sign a PCA CRL with Identity/V1/PCA")
    sign_crl_parser.add_argument("--private-seed-hex", required=True)
    sign_crl_parser.add_argument("--issued-at", required=True)
    sign_crl_parser.add_argument("--revoked-identifiers", required=True)
    sign_crl_parser.set_defaults(func=cmd_sign_crl)

    verify_crl_parser = sub.add_parser("verify-crl", help="verify a PCA CRL with the trusted Identity/V1/PCA public key")
    verify_crl_parser.add_argument("--public-key-b64", required=True)
    verify_crl_parser.add_argument("--crl", required=True)
    verify_crl_parser.add_argument("--identifier")
    verify_crl_parser.set_defaults(func=cmd_verify_crl)

    sign_migration = sub.add_parser("sign-migration", help="sign a protocol migration statement with Identity/V1/PCA")
    sign_migration.add_argument("--private-seed-hex", required=True)
    sign_migration.add_argument("--issued-at", required=True)
    sign_migration.add_argument("--from-protocol", required=True)
    sign_migration.add_argument("--to-protocol", required=True)
    sign_migration.add_argument("--migration-text", required=True)
    sign_migration.set_defaults(func=cmd_sign_migration)

    verify_migration = sub.add_parser("verify-migration", help="verify a protocol migration statement")
    verify_migration.add_argument("--public-key-b64", required=True)
    verify_migration.add_argument("--statement", required=True)
    verify_migration.set_defaults(func=cmd_verify_migration)

    dns_binding = sub.add_parser("dns-binding", help="create the DNS TXT binding for an Identity public key")
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
