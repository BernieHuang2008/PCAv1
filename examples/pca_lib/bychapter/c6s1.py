from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from examples.pca_lib.bychapter.c5s1 import check_Namespace_isvalid
from examples.pca_lib.bychapter.c6s2 import check_CanonicalInfoPath_isvalid
from examples.pca_lib.bychapter.c7s2 import check_uppercase_HEX_isvalid


def HKDF_derive_child(parent_key_hex: str, namespace: str, canonical_info_path: str):
    """
    Derive a DIRECT child node from parent node using HKDF.
    HKDF Parameters:
      IKM  = Parent Key
      salt = Namespace ID
      info = Canonical Info Path

    Assumptions:
        - Parent Key is the direct parent of the child node to be derived.

    Parameters:
        @param parent_key_hex: Parent Private Key in HEX
        @param namespace: Namespace ID with prefix
        @param canonical_info_path: Canonical Info Path

    Returns:
        @return: Child Private Key in HEX
    """
    # assume Parent Key is the direct parent of the child node to be derived.
    assert check_uppercase_HEX_isvalid(
        parent_key_hex, 128
    ), "Params: parent_key_hex is not align with [PCAv1.2 Chapter 7 Section 2]"
    assert check_Namespace_isvalid(
        namespace
    ), "Params: namespace is not align with [PCAv1.2 Chapter 5 Section 1]"
    assert check_CanonicalInfoPath_isvalid(
        canonical_info_path
    ), "Params: canonical_info_path is not align with [PCAv1.2 Chapter 6 Section 2]"

    child_private_key = HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=namespace.encode("UTF-8"),
        info=canonical_info_path.encode("UTF-8"),
        backend=default_backend(),
    ).derive(bytes.fromhex(parent_key_hex))

    return child_private_key.hex().upper()


if __name__ == "__main__":
    # Example usage
    parent_key_hex = "3FCFD300B9CEAC79D9232A31E48627648F46F3688B857A85985F6FB7123E9AF1D06F8FF258AC6D263B7E409247BF2E5EF9DF0B5599881F847E259EEEB3FFBFEB"  # Example parent key in HEX
    namespace = "PCA-v1/EDF915864C4A104211F8AB58121587941A1605493FE7B4A924D4A77A9727C544"  # Example namespace
    canonical_info_path = "example/path/to/child"  # Example canonical info path

    child_key_hex = HKDF_derive_child(parent_key_hex, namespace, canonical_info_path)
    print("Derived Child Key (HEX):", child_key_hex)
