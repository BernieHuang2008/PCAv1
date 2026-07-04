MASTER_SECRET_BYTES = 64
NAMESPACE_ID_BYTES = 32
ED25519_SEED_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
XCHACHA20_KEY_BYTES = 32
XCHACHA20_NONCE_BYTES = 24
BIP32_MASTER_SEED_BYTES = 64
HKDF_SHA512_BYTES = 64
SHA256_BYTES = 32
FILE_ID_BYTES = 32

NAMESPACE_PREFIX = "PCA-v1"

# PCAv1.2 specifies that TrustRootKey is derived from Master Secret through
# HKDF-SHA-512 but does not spell out the info path for this exact edge.
# This reference implementation fixes a single stable value for that edge.
TRUST_ROOT_INFO_PATH = "PCA/V1/TrustRoot"

