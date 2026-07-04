# PCA v1.2 Reference Manual and Examples

This directory is a reference implementation and setup manual for the PCA v1.2 draft.
It is intended to show how a compatible implementation can derive keys, separate protocol logic from UI/CLI code, and guide an operator through the manual steps that cannot be automated safely, such as offline Master Secret storage, DNS publication, and emergency revocation broadcast.

The examples are deliberately conservative:

- `pca_core/` contains protocol logic only.
- `pca_cli.py` contains CLI argument parsing, file IO, display, and operator hints only.
- `ui/` contains a local developer UI that drives the same CLI commands.
- `tests/` captures protocol invariants that future examples should preserve.

## Status and Scope

This code is reference-oriented. It demonstrates PCA-compatible logic, but it is not a complete production wallet, certificate authority, email client, DNS publisher, HSM integration, or backup system.

The implementation follows these core PCA rules:

- Master Secret is 512-bit random data.
- Namespace is used as the HKDF salt.
- HKDF is HKDF-SHA-512.
- Canonical Info Path is ASCII and stable.
- Identity, Generation, and Vault responsibilities stay separated.
- Identity uses Ed25519.
- Vault uses XChaCha20-Poly1305 through PyNaCl/libsodium, not a manual cipher implementation.
- Email uses one-message Ed25519 identities and PGPy-generated OpenPGP certification material for delayed binding.
- Signed JSON uses RFC 8785 JCS through the `rfc8785` package before signing.
- Revocation verification checks Namespace first, then signature.
- CRL and protocol migration examples use JCS + Ed25519 infrastructure signatures with `signer_path` fixed to `Identity/V1/PCA`.

One explicit reference choice is made in `pca_core/constants.py`: PCAv1.2 states that `TrustRootKey` is derived from Master Secret through HKDF, but the draft does not assign a literal info path for that exact edge. This implementation fixes it as:

```text
PCA/V1/TrustRoot
```

If the normative document later assigns a different value, update `TRUST_ROOT_INFO_PATH` in one place and regenerate test vectors.

Recommended PCAv1.2 protocol change: add an explicit normative row for this edge, for example:

```text
TrustRootKey = HKDF-SHA-512(
  IKM  = Master Secret,
  salt = Namespace ID,
  info = "PCA/V1/TrustRoot",
  L    = 64
)
```

Then state that `PCA/V1/TrustRoot` is a reserved Canonical Info Path, MUST NOT be used for Identity, Generation, Vault, CRL, migration, or application-defined nodes, and MUST remain stable for the lifetime of the `PCA-v1/<NamespaceID>` format family.

## Requirements

Use the bundled Python runtime in this Codex workspace:

```powershell
python3 --version
```

All commands below assume the repository root as the working directory.

```powershell
cd PCAv1
```

Install the declared standard crypto and canonicalization dependencies:

```powershell
python3 -m pip install -r examples\pca_reference\requirements.txt
```

Run tests:

```powershell
Push-Location examples\pca_reference
python3 -B -m unittest discover tests
Pop-Location
```

## Setup Manual

This section describes how to establish a complete PCA system with the example code plus required manual operations.

### 1. Initialize the PCA Root

Run:

```powershell
python3 examples\pca_reference\pca_cli.py init
```

The output contains:

- `master_secret_hex`
- `namespace`
- `emergency_revocation_private_seed_hex`
- `emergency_revocation_public_key_b64`

The CLI writes machine-readable JSON to stdout and human operator notes to stderr.

### 2. Store the Master Secret Offline

The Master Secret is the only permanent root secret in PCA. Do not store it in the online project directory, source control, cloud notes, chat logs, screenshots, or command history.

Recommended manual actions:

- Write or engrave the 512-bit `master_secret_hex` onto durable offline media.
- Store at least two geographically separated copies.
- Consider splitting the secret with a reviewed Shamir / SLIP-0039 style process if your operational model requires threshold recovery.
- Never publish the Master Secret or use it as a login password.
- Prefer deriving day-to-day keys from an intermediate parent node when possible.

### 3. Store the Emergency Revocation Key Separately

The emergency revocation key is independent of the Master Secret. It is not derived from Master Secret and must be stored separately.

Manual actions:

- Store `emergency_revocation_private_seed_hex` in a different physical location than the Master Secret.
- Store `emergency_revocation_public_key_b64` in your verifier configuration, application bundle, or trusted distribution package.
- Do not use the emergency revocation key for ordinary protocol upgrades.
- Use it only when the current Namespace must be declared dead.

### 4. Record the Namespace

The `namespace` value is public metadata, but it is cryptographically important. Every HKDF operation in this PCA instance uses the same Namespace as salt.

Manual actions:

- Record the Namespace next to your public configuration.
- Include it in verifier configuration.
- Do not change it for ordinary software upgrades.
- If the Master Secret is compromised, revoke the old Namespace and rebuild under a new Namespace.

### 5. Derive Infrastructure and Personal Identity Nodes

Derive a PCA infrastructure identity:

```powershell
python3 examples\pca_reference\pca_cli.py identity --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Identity/V1/PCA
```

Derive a personal identity:

```powershell
python3 examples\pca_reference\pca_cli.py identity --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Identity/V1/Personal/Identity2026
```

Derive a device or purpose identity:

```powershell
python3 examples\pca_reference\pca_cli.py identity --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Identity/V1/Personal/Identity2026/Laptop
```

Manual actions:

- Treat private seeds as sensitive.
- Publish only public keys that should be externally visible.
- Establish trust anchors out-of-band for external verifiers.
- Do not require public exposure of `IdentityRoot` for external identity verification.

### 6. Set Up DNS Domain Binding

DNS binding is optional external discovery. It must not replace mathematical signature verification or out-of-band trust establishment.

First derive the identity public key:

```powershell
python3 examples\pca_reference\pca_cli.py identity --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Identity/V1/Personal/Identity2026
```

Then create the DNS binding text:

```powershell
python3 examples\pca_reference\pca_cli.py dns-binding --namespace <NAMESPACE> --domain example.com --public-key-b64 <PUBLIC_KEY_B64>
```

Publish the returned TXT record:

```text
_pca.example.com. 3600 IN TXT "pca-binding=<SHA256_PUBLIC_KEY_HEX>"
```

Manual DNS steps:

- Open your DNS provider control panel.
- Create a TXT record named `_pca`.
- Set its value to `pca-binding=<SHA256_PUBLIC_KEY_HEX>`.
- Keep TTL moderate during setup, such as 300 or 3600 seconds.
- After DNS propagation, verifiers may use the record as an auxiliary discovery signal only.

Important: DNS is not an internal authorization source for PCA. Do not use DNS TXT records as CRL signer authorization, Vault authorization, software update authorization, or protocol migration authorization.

### 7. Set Up Well-Known Revocation Hosting

Choose a domain that you control and prepare this public path:

```text
https://<your-domain.com>/.well-known/pca/revocation.crl
```

Manual hosting steps:

- Create the directory `.well-known/pca/` on your web host.
- Ensure it is served over HTTPS.
- Ensure files are served as UTF-8 JSON.
- Keep backups of previously published revocation material.
- If you publish through a CDN, understand its cache invalidation process before an emergency.

The example can sign and verify CRL JSON using RFC 8785 JCS and Ed25519. Do not treat HTTPS hosting itself as authorization.

## Day-to-Day Operations

### Derive a Generic Node

From Master Secret:

```powershell
python3 examples\pca_reference\pca_cli.py derive-node --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Encrypt/V1/Vault/Finance --length 64
```

From an already-derived parent:

```powershell
python3 examples\pca_reference\pca_cli.py derive-node --parent-key-hex <PARENT_KEY_HEX> --parent-path Encrypt/V1/Vault/Finance --namespace <NAMESPACE> --path Encrypt/V1/Vault/Finance/2026/Q3 --length 64
```

The target path must be equal to or below the supplied parent path. `PCA/V1/TrustRoot` is treated as the parent of protocol branch roots.

### Generation Secrets

Derive a password manager seed:

```powershell
python3 examples\pca_reference\pca_cli.py generation --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Encrypt/V1/Generation/PasswordManager --length 32
```

Derive a BIP32 master seed:

```powershell
python3 examples\pca_reference\pca_cli.py bip32-seed --master-hex <MASTER_HEX> --namespace <NAMESPACE> --network Mainnet
```

Generation keys do not establish public trust. They are deterministic secrets.

## Email Operations

Sign one email with a fresh ephemeral identity:

```powershell
python3 examples\pca_reference\pca_cli.py email-sign --master-hex <MASTER_HEX> --namespace <NAMESPACE> --parent-path Identity/V1/Personal/Identity2026 --input message.eml --signature message.email-sig.json
```

Verify the email signature:

```powershell
python3 examples\pca_reference\pca_cli.py email-verify --input message.eml --signature message.email-sig.json
```

Create a detached delayed-binding proof:

```powershell
python3 examples\pca_reference\pca_cli.py email-bind --master-hex <MASTER_HEX> --namespace <NAMESPACE> --parent-path Identity/V1/Personal/Identity2026 --email-signature message.email-sig.json --issued-at 2026-07-04T00:00:00Z --binding message.binding.asc.json
```

Verify the delayed-binding proof:

```powershell
python3 examples\pca_reference\pca_cli.py email-verify-binding --email-signature message.email-sig.json --binding message.binding.asc.json --trusted-parent-public-key-b64 <PARENT_PUBLIC_KEY_B64>
```

Email signing creates a new 256-bit `RandomEmailId` by default and signs the message with `Identity/V1/<Persona>/<IdentityNode>/Email/Ephemeral/<RandomEmailId>`. Delayed binding is distributed as a detached proof. It includes OpenPGP public key armor and either a `0x10` generic certification signature or, when requested with `--signature-type 0x18`, a bound-subkey OpenPGP public key block.

## Vault Operations

Encrypt a file:

```powershell
python3 examples\pca_reference\pca_cli.py vault-encrypt --master-hex <MASTER_HEX> --namespace <NAMESPACE> --permission-path Finance/2026/Q3 --input secret.txt --output secret.pca --metadata secret.pca.json
```

Decrypt a file:

```powershell
python3 examples\pca_reference\pca_cli.py vault-decrypt --master-hex <MASTER_HEX> --namespace <NAMESPACE> --permission-path Finance/2026/Q3 --file-id <FILE_ID> --input secret.pca --output secret.txt
```

Manual actions:

- Keep ciphertext and metadata together.
- Back up Vault ciphertext; it cannot be recreated from Master Secret.
- The key can be recovered, but the encrypted external secret cannot be recovered if the ciphertext is lost.
- Preserve `permission_path` and `file_id`; they are required to recompute the file key.

## Emergency Revocation

Use revocation only when the current Namespace must be declared dead, such as after Master Secret compromise.

Sign a revocation announcement:

```powershell
python3 examples\pca_reference\pca_cli.py sign-revocation --private-seed-hex <EMERGENCY_PRIVATE_SEED_HEX> --namespace <NAMESPACE> --revoked-at 2026-07-04T00:00:00Z --reason "Master Secret Compromised"
```

With successor hint:

```powershell
python3 examples\pca_reference\pca_cli.py sign-revocation --private-seed-hex <EMERGENCY_PRIVATE_SEED_HEX> --namespace <OLD_NAMESPACE> --revoked-at 2026-07-04T00:00:00Z --reason "Master Secret Compromised" --successor-namespace-hint <NEW_NAMESPACE>
```

Manual publication steps:

- Save stdout exactly as UTF-8 JSON.
- Publish it at `https://<your-domain.com>/.well-known/pca/revocation.crl` if this domain is your revocation publication point.
- Publish the same announcement through additional channels: personal website, signed email, social profile, PGP keyserver note, public timestamping service, or other channels your verifiers monitor.
- Do not present `successor_namespace_hint` as a trust anchor.
- Tell verifiers that new Namespace trust must be established out-of-band.

Verify a revocation announcement:

```powershell
python3 examples\pca_reference\pca_cli.py verify-revocation --public-key-b64 <EMERGENCY_PUBLIC_KEY_B64> --namespace <NAMESPACE> --statement revocation.json
```

Verification order:

1. Check the statement `namespace` against the local trusted Namespace.
2. Ignore the statement immediately if the Namespace differs.
3. Verify the Ed25519 signature over canonicalized JSON without the `signature` field.
4. If valid, reject subsequent operations under that Namespace.

## CRL Operations

Create a text file containing one revoked SHA-256 identifier per line, using 64-character Uppercase HEX.

Sign a CRL with the PCA infrastructure identity:

```powershell
python3 examples\pca_reference\pca_cli.py sign-crl --namespace <NAMESPACE> --private-seed-hex <PCA_INFRA_PRIVATE_SEED_HEX> --issued-at 2026-07-04T00:00:00Z --revoked-identifiers revoked-identifiers.txt
```

Verify a CRL with the trusted `Identity/V1/PCA` public key:

```powershell
python3 examples\pca_reference\pca_cli.py verify-crl --namespace <NAMESPACE> --public-key-b64 <PCA_INFRA_PUBLIC_KEY_B64> --crl revocation.crl
```

Check one identifier:

```powershell
python3 examples\pca_reference\pca_cli.py verify-crl --namespace <NAMESPACE> --public-key-b64 <PCA_INFRA_PUBLIC_KEY_B64> --crl revocation.crl --identifier <SHA256_IDENTIFIER_HEX>
```

The reference CRL implementation accepts `signer_path = Identity/V1/PCA` only. It does not query DNS and does not treat the well-known HTTPS URL as authorization.

## Protocol Migration Statements

Sign a protocol migration statement with the PCA infrastructure identity:

```powershell
python3 examples\pca_reference\pca_cli.py sign-migration --namespace <NAMESPACE> --private-seed-hex <PCA_INFRA_PRIVATE_SEED_HEX> --issued-at 2026-07-04T00:00:00Z --from-protocol PCA-v1.2 --to-protocol PCA-v1.3 --migration-text "Upgrade serialization rules"
```

Verify it with the trusted `Identity/V1/PCA` public key:

```powershell
python3 examples\pca_reference\pca_cli.py verify-migration --namespace <NAMESPACE> --public-key-b64 <PCA_INFRA_PUBLIC_KEY_B64> --statement migration.json
```

Protocol migration statements are not emergency revocation statements and do not revive, override, or narrow a revoked Namespace.

## Rebuild After Revocation

Once a Namespace is validly revoked, treat it as permanently dead.

Manual rebuild steps:

- Generate a new Master Secret.
- Generate a new independent emergency revocation key.
- Use a new Namespace.
- Re-derive new identity roots and branch keys.
- Re-publish DNS bindings for new public identity keys.
- Distribute new trust anchors out-of-band.
- Do not automatically trust the new Namespace just because the old revocation announcement contains `successor_namespace_hint`.

## UI

Run the local UI:

```powershell
python3 examples\pca_reference\ui\server.py 8765
```

Open:

```text
http://127.0.0.1:8765/
```

UI behavior:

- Preset trunk nodes are gray.
- Successful generation marks nodes green.
- Dynamic nodes are created from branch-specific forms.
- The right-side PCACLI panel shows the exact CLI command executed by each UI action.
- The Derivation Source panel supports Master Secret, selected generated parent node, or manual parent key/path.

## File Outline

`pca_core/constants.py`

Defines byte lengths, namespace prefix, and `TRUST_ROOT_INFO_PATH`.

`pca_core/encoding.py`

Validates Namespace IDs, Uppercase HEX fields, Canonical Info Paths, Identity paths, Generation paths, Vault permission paths, File IDs, and UTC timestamps.

`pca_core/hkdf.py`

Implements HKDF-SHA-512 and hierarchical derivation. `derive_path_key` starts from Master Secret. `derive_descendant_key` starts from an arbitrary parent key/path pair.

`pca_core/identity.py`

Derives Ed25519 private seeds from `Identity/V1/...` paths and exposes signing and public-key helpers.

`pca_core/email_identity.py`

Creates one-message email identities, verifies email signatures, and produces detached OpenPGP delayed-binding proofs.

`pca_core/generation.py`

Derives deterministic Generation secrets from `Encrypt/V1/Generation/...` paths. The BIP32 helper returns exactly 64 bytes.

`pca_core/xchacha20poly1305.py`

Wraps PyNaCl/libsodium XChaCha20-Poly1305. No cipher rounds are implemented by hand.

`pca_core/vault.py`

Implements Vault file encryption. Each file gets a 256-bit File ID, a fresh 192-bit nonce, a per-file key, and full-path AAD.

`pca_core/jcs.py`

Provides RFC 8785 JCS canonical JSON serialization for signed PCA structures.

`pca_core/revocation.py`

Signs and verifies emergency revocation statements.

`pca_core/crl.py`

Signs and verifies CRL JSON with the trusted `Identity/V1/PCA` public key.

`pca_core/migration.py`

Signs and verifies protocol migration statements with the trusted `Identity/V1/PCA` public key.

`pca_cli.py`

Provides command-line access to the reference implementation. Operator hints are printed to stderr so stdout remains machine-readable.

`ui/server.py`

Serves the local tree UI and maps UI actions to concrete `pca_cli.py` subprocess calls.

`ui/static/`

Contains the browser UI.

`tests/`

Contains focused tests for deterministic derivation, parent derivation, path validation, Vault authentication, JCS behavior, email identity, delayed binding, revocation validation order, CLI revocation enforcement, CRL signatures, and protocol migration signatures.

## Operational Checklist

Before using a PCA Namespace:

- Master Secret generated with `init`.
- Master Secret stored offline.
- Emergency revocation private seed stored separately.
- Emergency revocation public key configured in verifiers.
- Namespace recorded.
- Infrastructure and public identities derived.
- Public identity keys distributed through trusted channels.
- Optional DNS binding published.
- Optional well-known revocation path prepared.
- Optional CRL signing and verification drill completed.
- Optional protocol migration verification drill completed.
- Vault ciphertext backup strategy established.
- Revocation drill tested with non-production data.

## Common Mistakes to Avoid

- Do not store Master Secret in Git.
- Do not store emergency revocation private seed with Master Secret.
- Do not derive the emergency revocation key from Master Secret.
- Do not use DNS as internal authorization.
- Do not change a Canonical Info Path after it has meaning.
- Do not use Generation keys for public identity trust.
- Do not assume Vault ciphertext can be regenerated.
- Do not trust a successor Namespace automatically.
