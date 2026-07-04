from __future__ import annotations

import base64
import hashlib
import warnings
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from pgpy import PGPKey, PGPSignature, PGPUID
from pgpy.constants import EllipticCurveOID, HashAlgorithm, KeyFlags, PubKeyAlgorithm, SignatureType
from pgpy.packet.fields import ECPoint, ECPointFormat, MPI

from .constants import ED25519_SEED_BYTES, ED25519_SIGNATURE_BYTES
from .encoding import (
    canonical_path_bytes,
    ensure_bytes_length,
    random_upper_hex,
    validate_identity_path,
    validate_iso8601_z,
    validate_namespace,
)
from .errors import PCAAuthenticationError, PCAValidationError
from .identity import derive_identity_seed, public_key_bytes
from .jcs import canonicalize_bytes

EMAIL_ID_BYTES = 32
EMAIL_SIGNATURE_TYPE = "pca_email_ephemeral_signature"
DELAYED_BINDING_TYPE = "openpgp_delayed_binding_certification"
OPENPGP_GENERIC_CERTIFICATION = "0x10"
OPENPGP_SUBKEY_BINDING = "0x18"
OPENPGP_ALLOWED_SIGNATURE_TYPES = {OPENPGP_GENERIC_CERTIFICATION, OPENPGP_SUBKEY_BINDING}
PCA_PARENT_KEY_ORIGIN = "pca_identity"
EXTERNAL_OPENPGP_PARENT_KEY_ORIGIN = "external_openpgp"


def _decode_b64(value: str, expected: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise PCAValidationError(f"{field} must be Base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise PCAValidationError(f"{field} must be valid Base64") from exc
    return ensure_bytes_length(decoded, expected, field)


def _raw_public_key_b64(private_key: ed25519.Ed25519PrivateKey) -> str:
    return base64.b64encode(public_key_bytes(private_key)).decode("ascii")


def _fingerprint_hex(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest().upper()


def _message_hash_hex(message: bytes) -> str:
    if not isinstance(message, bytes):
        raise PCAValidationError("email message must be bytes")
    return hashlib.sha256(message).hexdigest().upper()


def _datetime_from_iso_z(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _fill_pgp_ed25519_key(key: PGPKey, seed: bytes) -> None:
    ensure_bytes_length(seed, ED25519_SEED_BYTES, "Ed25519 private seed")
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    material = key._key.keymaterial
    material.p = ECPoint.from_values(material.oid.key_size, ECPointFormat.Native, public_key)
    material.s = MPI(material.bytes_to_int(seed))
    material._compute_chksum()
    key._key.update_hlen()


def _pgp_key_from_seed(seed: bytes, user_id: str, *, created: datetime | None = None, usage: set[KeyFlags]) -> PGPKey:
    key = PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519, created=created)
    _fill_pgp_ed25519_key(key, seed)
    key.add_uid(PGPUID.new(user_id), usage=usage, hashes=[HashAlgorithm.SHA512])
    return key


def _parse_pgp_key(armored: str, field: str) -> PGPKey:
    if not isinstance(armored, str) or "BEGIN PGP PUBLIC KEY BLOCK" not in armored:
        raise PCAValidationError(f"{field} must be an ASCII-armored OpenPGP public key")
    key, _ = PGPKey.from_blob(armored)
    return key


def _parse_pgp_private_key(armored: str, field: str) -> PGPKey:
    if not isinstance(armored, str) or "BEGIN PGP PRIVATE KEY BLOCK" not in armored:
        raise PCAValidationError(f"{field} must be an ASCII-armored OpenPGP private key")
    key, _ = PGPKey.from_blob(armored)
    if key.is_public:
        raise PCAValidationError(f"{field} must contain private key material")
    return key


def _parse_pgp_signature(armored: str) -> PGPSignature:
    if not isinstance(armored, str) or "BEGIN PGP SIGNATURE" not in armored:
        raise PCAValidationError("OpenPGP certification signature must be ASCII-armored")
    signature = PGPSignature.from_blob(armored)
    return signature


def _pgp_fingerprint(key: PGPKey) -> str:
    return str(key.fingerprint).replace(" ", "").upper()


def _certify_subject_uid(
    parent_pgp: PGPKey,
    subject_pgp: PGPKey,
    *,
    passphrase: str | None = None,
) -> PGPSignature:
    if not subject_pgp.userids:
        raise PCAValidationError("email OpenPGP public key must contain an ephemeral User ID")
    if parent_pgp.is_protected:
        if passphrase is None:
            raise PCAValidationError("parent OpenPGP private key is protected; provide a passphrase")
        with parent_pgp.unlock(passphrase):
            return parent_pgp.certify(
                subject_pgp.userids[0],
                level=SignatureType.Generic_Cert,
                hash=HashAlgorithm.SHA512,
            )
    return parent_pgp.certify(
        subject_pgp.userids[0],
        level=SignatureType.Generic_Cert,
        hash=HashAlgorithm.SHA512,
    )


def validate_email_parent_path(parent_path: str) -> str:
    path = validate_identity_path(parent_path)
    if "/Email/" in path or path.endswith("/Email"):
        raise PCAValidationError("email parent path must be the long-term parent identity, not an email child")
    if len(path.split("/")) < 4:
        raise PCAValidationError("email parent path must include Persona and IdentityNode")
    return path


def email_ephemeral_path(parent_path: str, random_email_id: str) -> str:
    parent = validate_email_parent_path(parent_path)
    if len(random_email_id) != EMAIL_ID_BYTES * 2 or not all(c in "0123456789ABCDEF" for c in random_email_id):
        raise PCAValidationError("RandomEmailId must be 256-bit Uppercase HEX")
    return f"{parent}/Email/Ephemeral/{random_email_id}"


def _sign_ephemeral_email_with_seed(
    seed: bytes,
    namespace: str,
    email_id: str,
    signer_path: str,
    message: bytes,
) -> dict[str, Any]:
    ensure_bytes_length(seed, ED25519_SEED_BYTES, "Ed25519 private seed")
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    signature = private_key.sign(message)
    public_key_raw = public_key_bytes(private_key)
    pgp_key = _pgp_key_from_seed(
        seed,
        f"PCA Ephemeral Email {email_id}",
        usage={KeyFlags.Sign},
    )
    return {
        "email_id": email_id,
        "message_sha256_hex": _message_hash_hex(message),
        "namespace": namespace,
        "openpgp_public_key_armored": str(pgp_key.pubkey),
        "public_key_b64": base64.b64encode(public_key_raw).decode("ascii"),
        "public_key_fingerprint_sha256_hex": _fingerprint_hex(public_key_raw),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "signer_path": signer_path,
        "statement_type": EMAIL_SIGNATURE_TYPE,
        "version": 1,
    }


def sign_ephemeral_email(
    master_secret: bytes,
    namespace: str,
    parent_identity_path: str,
    message: bytes,
    *,
    random_email_id: str | None = None,
) -> dict[str, Any]:
    validate_namespace(namespace)
    email_id = random_email_id or random_upper_hex(EMAIL_ID_BYTES)
    signer_path = email_ephemeral_path(parent_identity_path, email_id)
    seed = derive_identity_seed(master_secret, namespace, signer_path)
    return _sign_ephemeral_email_with_seed(seed, namespace, email_id, signer_path, message)


def sign_ephemeral_email_with_seed(
    seed: bytes,
    namespace: str,
    parent_identity_path: str,
    message: bytes,
    *,
    random_email_id: str | None = None,
) -> dict[str, Any]:
    validate_namespace(namespace)
    email_id = random_email_id or random_upper_hex(EMAIL_ID_BYTES)
    signer_path = email_ephemeral_path(parent_identity_path, email_id)
    return _sign_ephemeral_email_with_seed(seed, namespace, email_id, signer_path, message)


def verify_ephemeral_email(message: bytes, signature_statement: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(signature_statement, dict):
        raise PCAValidationError("email signature statement must be a JSON object")
    if signature_statement.get("version") != 1:
        raise PCAValidationError("email signature version must be 1")
    if signature_statement.get("statement_type") != EMAIL_SIGNATURE_TYPE:
        raise PCAValidationError("email signature statement_type is invalid")
    validate_namespace(signature_statement.get("namespace"))
    signer_path = validate_identity_path(signature_statement.get("signer_path"))
    email_id = signature_statement.get("email_id")
    parent_path = signer_path.rsplit("/Email/Ephemeral/", 1)[0] if "/Email/Ephemeral/" in signer_path else ""
    if email_ephemeral_path(parent_path, email_id) != signer_path:
        raise PCAValidationError("email signer path must contain the RandomEmailId")
    if signature_statement.get("message_sha256_hex") != _message_hash_hex(message):
        raise PCAAuthenticationError("email message hash does not match signature statement")
    public_key_raw = _decode_b64(signature_statement.get("public_key_b64"), ED25519_SEED_BYTES, "email public key")
    if signature_statement.get("public_key_fingerprint_sha256_hex") != _fingerprint_hex(public_key_raw):
        raise PCAAuthenticationError("email public key fingerprint mismatch")
    pgp_key = _parse_pgp_key(signature_statement.get("openpgp_public_key_armored"), "email OpenPGP public key")
    if not pgp_key.userids:
        raise PCAValidationError("email OpenPGP public key must contain an ephemeral User ID")
    signature = _decode_b64(signature_statement.get("signature_b64"), ED25519_SIGNATURE_BYTES, "email signature")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, message)
    except InvalidSignature as exc:
        raise PCAAuthenticationError("email signature is invalid") from exc
    return signature_statement


def sign_openpgp_delayed_binding(
    master_secret: bytes,
    namespace: str,
    parent_identity_path: str,
    email_signature_statement: dict[str, Any],
    issued_at: str,
    *,
    signature_type: str = OPENPGP_GENERIC_CERTIFICATION,
    signer_user_id: str | None = None,
) -> dict[str, Any]:
    parent_path = validate_email_parent_path(parent_identity_path)
    parent_seed = derive_identity_seed(master_secret, namespace, parent_path)
    subject_seed = None
    if signature_type == OPENPGP_SUBKEY_BINDING:
        ephemeral_path = validate_identity_path(email_signature_statement.get("signer_path"))
        subject_seed = derive_identity_seed(master_secret, namespace, ephemeral_path)
    return sign_openpgp_delayed_binding_with_parent_seed(
        parent_seed,
        namespace,
        parent_path,
        email_signature_statement,
        issued_at,
        signature_type=signature_type,
        signer_user_id=signer_user_id,
        subject_seed=subject_seed,
    )


def sign_openpgp_delayed_binding_with_parent_seed(
    parent_seed: bytes,
    namespace: str,
    parent_identity_path: str,
    email_signature_statement: dict[str, Any],
    issued_at: str,
    *,
    signature_type: str = OPENPGP_GENERIC_CERTIFICATION,
    signer_user_id: str | None = None,
    subject_seed: bytes | None = None,
) -> dict[str, Any]:
    validate_namespace(namespace)
    parent_path = validate_email_parent_path(parent_identity_path)
    ensure_bytes_length(parent_seed, ED25519_SEED_BYTES, "parent Ed25519 private seed")
    validate_iso8601_z(issued_at, "issued_at")
    if signature_type not in OPENPGP_ALLOWED_SIGNATURE_TYPES:
        raise PCAValidationError("signature_type must be 0x10 or 0x18")
    if email_signature_statement.get("namespace") != namespace:
        raise PCAValidationError("email signature namespace must match binding namespace")
    ephemeral_public = _decode_b64(
        email_signature_statement.get("public_key_b64"), ED25519_SEED_BYTES, "email public key"
    )
    parent_private = ed25519.Ed25519PrivateKey.from_private_bytes(parent_seed)
    parent_public = public_key_bytes(parent_private)
    parent_pgp = _pgp_key_from_seed(
        parent_seed,
        signer_user_id or parent_path,
        created=_datetime_from_iso_z(issued_at),
        usage={KeyFlags.Certify},
    )
    subject_pgp = _parse_pgp_key(
        email_signature_statement.get("openpgp_public_key_armored"),
        "email OpenPGP public key",
    )
    payload: dict[str, Any] = {
        "distribution": "detached",
        "ephemeral_path": validate_identity_path(email_signature_statement.get("signer_path")),
        "issuer_fingerprint_sha256_hex": _fingerprint_hex(parent_public),
        "issued_at": issued_at,
        "key_flags": ["certify"],
        "namespace": namespace,
        "openpgp_signature_type": signature_type,
        "openpgp_subject_public_key_armored": str(subject_pgp),
        "parent_key_origin": PCA_PARENT_KEY_ORIGIN,
        "parent_path": parent_path,
        "parent_openpgp_public_key_armored": str(parent_pgp.pubkey),
        "parent_public_key_b64": base64.b64encode(parent_public).decode("ascii"),
        "statement_type": DELAYED_BINDING_TYPE,
        "subject_fingerprint_sha256_hex": _fingerprint_hex(ephemeral_public),
        "subject_public_key_b64": base64.b64encode(ephemeral_public).decode("ascii"),
        "subpackets": {
            "2": "Signature Creation Time",
            "27": "Key Flags",
            "33": "Issuer Fingerprint",
        },
        "version": 1,
    }
    if signer_user_id:
        payload["signer_user_id"] = signer_user_id
    if signature_type == OPENPGP_GENERIC_CERTIFICATION:
        certification = _certify_subject_uid(parent_pgp, subject_pgp)
        payload["openpgp_certification_signature_armored"] = str(certification)
    else:
        if subject_seed is None:
            raise PCAValidationError("OpenPGP subkey binding requires the ephemeral subject seed")
        ensure_bytes_length(subject_seed, ED25519_SEED_BYTES, "subject Ed25519 private seed")
        subject_subkey = _pgp_key_from_seed(
            subject_seed,
            f"PCA Ephemeral Email Subkey {email_signature_statement.get('email_id')}",
            created=_datetime_from_iso_z(issued_at),
            usage={KeyFlags.Sign},
        )
        parent_pgp.add_subkey(subject_subkey, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA512])
        payload["openpgp_bound_subkey_public_key_armored"] = str(parent_pgp.pubkey)
    signature = parent_private.sign(canonicalize_bytes(payload))
    signed = dict(payload)
    signed["signature_b64"] = base64.b64encode(signature).decode("ascii")
    return signed


def sign_external_openpgp_delayed_binding(
    parent_private_key_armored: str,
    namespace: str,
    email_signature_statement: dict[str, Any],
    issued_at: str,
    *,
    passphrase: str | None = None,
    signer_user_id: str | None = None,
) -> dict[str, Any]:
    validate_namespace(namespace)
    validate_iso8601_z(issued_at, "issued_at")
    if email_signature_statement.get("namespace") != namespace:
        raise PCAValidationError("email signature namespace must match binding namespace")
    ephemeral_public = _decode_b64(
        email_signature_statement.get("public_key_b64"), ED25519_SEED_BYTES, "email public key"
    )
    parent_pgp = _parse_pgp_private_key(parent_private_key_armored, "parent OpenPGP private key")
    subject_pgp = _parse_pgp_key(
        email_signature_statement.get("openpgp_public_key_armored"),
        "email OpenPGP public key",
    )
    certification = _certify_subject_uid(parent_pgp, subject_pgp, passphrase=passphrase)
    payload: dict[str, Any] = {
        "distribution": "detached",
        "ephemeral_path": validate_identity_path(email_signature_statement.get("signer_path")),
        "issued_at": issued_at,
        "key_flags": ["certify"],
        "namespace": namespace,
        "openpgp_certification_signature_armored": str(certification),
        "openpgp_signature_type": OPENPGP_GENERIC_CERTIFICATION,
        "openpgp_subject_public_key_armored": str(subject_pgp),
        "parent_key_origin": EXTERNAL_OPENPGP_PARENT_KEY_ORIGIN,
        "parent_openpgp_fingerprint": _pgp_fingerprint(parent_pgp),
        "parent_openpgp_public_key_armored": str(parent_pgp.pubkey),
        "statement_type": DELAYED_BINDING_TYPE,
        "subject_fingerprint_sha256_hex": _fingerprint_hex(ephemeral_public),
        "subject_public_key_b64": base64.b64encode(ephemeral_public).decode("ascii"),
        "subpackets": {
            "2": "Signature Creation Time",
            "27": "Key Flags",
            "33": "Issuer Fingerprint",
        },
        "version": 1,
    }
    if signer_user_id:
        payload["signer_user_id"] = signer_user_id
    return payload


def verify_openpgp_delayed_binding(
    email_signature_statement: dict[str, Any],
    binding_statement: dict[str, Any],
    *,
    trusted_parent_public_key_b64: str | None = None,
    trusted_parent_openpgp_public_key_armored: str | None = None,
    trusted_parent_openpgp_fingerprint: str | None = None,
) -> dict[str, Any]:
    if not isinstance(binding_statement, dict):
        raise PCAValidationError("binding statement must be a JSON object")
    payload = dict(binding_statement)
    signature_b64 = payload.pop("signature_b64", None)
    if payload.get("version") != 1:
        raise PCAValidationError("binding version must be 1")
    if payload.get("statement_type") != DELAYED_BINDING_TYPE:
        raise PCAValidationError("binding statement_type is invalid")
    validate_namespace(payload.get("namespace"))
    validate_identity_path(payload.get("ephemeral_path"))
    validate_iso8601_z(payload.get("issued_at"), "issued_at")
    if payload.get("openpgp_signature_type") not in OPENPGP_ALLOWED_SIGNATURE_TYPES:
        raise PCAValidationError("binding signature type must be 0x10 or 0x18")
    if payload.get("distribution") != "detached":
        raise PCAValidationError("delayed binding proof must be detached, not a central list")
    subpackets = payload.get("subpackets")
    if not isinstance(subpackets, dict) or not {"2", "27", "33"}.issubset(subpackets):
        raise PCAValidationError("binding proof must contain OpenPGP creation time, key flags, and issuer fingerprint")
    if "certify" not in payload.get("key_flags", []):
        raise PCAValidationError("binding key flags must include certify")

    subject_public = _decode_b64(payload.get("subject_public_key_b64"), ED25519_SEED_BYTES, "subject public key")
    if payload.get("subject_fingerprint_sha256_hex") != _fingerprint_hex(subject_public):
        raise PCAAuthenticationError("binding subject fingerprint mismatch")
    if payload.get("subject_public_key_b64") != email_signature_statement.get("public_key_b64"):
        raise PCAAuthenticationError("binding subject does not match email signature public key")
    if payload.get("ephemeral_path") != email_signature_statement.get("signer_path"):
        raise PCAAuthenticationError("binding subject path does not match email signature path")
    parent_key_origin = payload.get("parent_key_origin", PCA_PARENT_KEY_ORIGIN)
    if parent_key_origin not in {PCA_PARENT_KEY_ORIGIN, EXTERNAL_OPENPGP_PARENT_KEY_ORIGIN}:
        raise PCAValidationError("binding parent_key_origin is invalid")
    if parent_key_origin == EXTERNAL_OPENPGP_PARENT_KEY_ORIGIN and payload.get("openpgp_signature_type") != OPENPGP_GENERIC_CERTIFICATION:
        raise PCAValidationError("external OpenPGP delayed binding supports signature type 0x10")
    if parent_key_origin == PCA_PARENT_KEY_ORIGIN:
        validate_email_parent_path(payload.get("parent_path"))
        if signature_b64 is None:
            raise PCAValidationError("PCA binding statement signature is required")
        parent_public = _decode_b64(payload.get("parent_public_key_b64"), ED25519_SEED_BYTES, "parent public key")
        if trusted_parent_public_key_b64 is not None:
            trusted_parent = _decode_b64(trusted_parent_public_key_b64, ED25519_SEED_BYTES, "trusted parent public key")
            if trusted_parent != parent_public:
                raise PCAAuthenticationError("binding parent key does not match trusted parent key")
        if payload.get("issuer_fingerprint_sha256_hex") != _fingerprint_hex(parent_public):
            raise PCAAuthenticationError("binding issuer fingerprint mismatch")
    elif trusted_parent_public_key_b64 is not None:
        raise PCAValidationError("trusted_parent_public_key_b64 applies only to PCA identity bindings")
    parent_pgp = _parse_pgp_key(payload.get("parent_openpgp_public_key_armored"), "parent OpenPGP public key")
    if trusted_parent_openpgp_public_key_armored is not None:
        trusted_parent_pgp = _parse_pgp_key(
            trusted_parent_openpgp_public_key_armored,
            "trusted parent OpenPGP public key",
        )
        if _pgp_fingerprint(trusted_parent_pgp) != _pgp_fingerprint(parent_pgp):
            raise PCAAuthenticationError("binding parent OpenPGP key does not match trusted parent key")
    if trusted_parent_openpgp_fingerprint is not None:
        trusted_fingerprint = trusted_parent_openpgp_fingerprint.replace(" ", "").upper()
        if trusted_fingerprint != _pgp_fingerprint(parent_pgp):
            raise PCAAuthenticationError("binding parent OpenPGP fingerprint does not match trusted parent key")
    if payload.get("parent_openpgp_fingerprint") is not None:
        if payload.get("parent_openpgp_fingerprint") != _pgp_fingerprint(parent_pgp):
            raise PCAAuthenticationError("binding parent OpenPGP fingerprint mismatch")
    subject_pgp = _parse_pgp_key(
        payload.get("openpgp_subject_public_key_armored"),
        "subject OpenPGP public key",
    )
    if payload.get("openpgp_signature_type") == OPENPGP_GENERIC_CERTIFICATION:
        certification = _parse_pgp_signature(payload.get("openpgp_certification_signature_armored"))
        if certification.type != SignatureType.Generic_Cert:
            raise PCAValidationError("OpenPGP certification signature must be type 0x10")
        if not subject_pgp.userids:
            raise PCAValidationError("subject OpenPGP public key must contain a User ID")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            verified = parent_pgp.verify(subject_pgp.userids[0], certification)
        if not verified:
            raise PCAAuthenticationError("OpenPGP certification signature is invalid")
    else:
        bound_parent = _parse_pgp_key(
            payload.get("openpgp_bound_subkey_public_key_armored"),
            "OpenPGP bound subkey public key",
        )
        found_subkey_binding = any(
            signature.type == SignatureType.Subkey_Binding
            for subkey in bound_parent.subkeys.values()
            for signature in subkey._signatures
        )
        if not found_subkey_binding:
            raise PCAAuthenticationError("OpenPGP subkey binding signature is missing")

    if parent_key_origin == PCA_PARENT_KEY_ORIGIN:
        signature = _decode_b64(signature_b64, ED25519_SIGNATURE_BYTES, "binding signature")
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(parent_public).verify(signature, canonicalize_bytes(payload))
        except InvalidSignature as exc:
            raise PCAAuthenticationError("binding signature is invalid") from exc
    return binding_statement
