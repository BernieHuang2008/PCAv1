from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_EmergencyRevocationKey_private() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def derive_EmergencyRevocationKey_public(
    private_key: ed25519.Ed25519PrivateKey,
) -> ed25519.Ed25519PublicKey:
    return private_key.public_key()


def generate_EmergencyRevocationKey_pair() -> dict:
    """
    Generate a new Emergency Revocation Key pair (private and public keys).
    Returns:
        {
            "private_key": PrivateKey in HEX,
            "public_key": PublicKey in HEX
        }
    """
    private_key = generate_EmergencyRevocationKey_private()
    public_key = derive_EmergencyRevocationKey_public(private_key)

    return {
        "private_key": private_key.private_bytes_raw().hex().upper(),
        "public_key": public_key.public_bytes_raw().hex().upper(),
    }


# Tests
if __name__ == "__main__":
    key_pair = generate_EmergencyRevocationKey_pair()
    print("Emergency Revocation Key Pair:")
    print("Private Key:", key_pair["private_key"])
    print("Public  Key:", key_pair["public_key"])
