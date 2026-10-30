from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from examples.pca_lib.bychapter.c5s1 import check_Namespace_isvalid
from examples.pca_lib.bychapter.c7s2 import check_uppercase_HEX_isvalid


def derive_branch_root(master_secret: str, namespace: str, branch: str):
    """
    Derive the Branch Root Node using HKDF.
    NOTE: This function is intended for demonstrating how to derive the Branch Root node from the Master Secret.
          In practice, please don't use this function since it CAN'T guarantee the destroy process.
          USE the code in c8s2.py instead.

    HKDF Parameters:
      IKM  = TrustRoot
      salt = Namespace ID
      info = "PCA/V1/{branch}"

    Parameters:
        @param master_secret: Master Secret in HEX
        @param namespace: Namespace ID with prefix
        @param branch: Branch Name among {"Identity", "Generation", "Vault"}

    Returns:
        @return: Branch Root Private Key in HEX
    """
    assert check_uppercase_HEX_isvalid(
        master_secret, 128
    ), "Params: master_secret is not align with [PCAv1.2 Chapter 7 Section 2]"
    assert check_Namespace_isvalid(
        namespace
    ), "Params: namespace is not align with [PCAv1.2 Chapter 5 Section 1]"
    assert branch in {
        "Identity",
        "Generation",
        "Vault",
    }, "Params: invalid branch name. Branch shall be one of {'Identity', 'Generation', 'Vault'}"

    trustroot_private_key = HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=namespace.encode("UTF-8"),
        info=b"PCA/V1/TrustRoot",
        backend=default_backend(),
    ).derive(bytes.fromhex(master_secret))

    branchroot_private_key = HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=namespace.encode("UTF-8"),
        info="PCA/V1/{}".format(branch).encode("UTF-8"),
        backend=default_backend(),
    ).derive(bytes.fromhex(trustroot_private_key))

    res = branchroot_private_key.hex().upper()

    del trustroot_private_key  # Destroy the TrustRoot Private Key to ensure security
    del branchroot_private_key  # Destroy the Branch Root Private Key to ensure security

    return res
