from secrets import token_hex

from examples.pca_lib.bychapter.c7s2 import check_uppercase_HEX_isvalid


def generate_Namespace() -> str:
    """
    Generate a 256-bit Namespace & prefix added for use in PCAv1.
    Refers to PCAv1.2 Chapter 5 Section 1
    """

    return "PCA-v1/" + token_hex(32).upper()  # 32 bytes = 256 bits


def check_Namespace_isvalid(namespace: str) -> bool:
    """
    Check if the given Namespace is valid.
    Refers to PCAv1.2 Chapter 5 Section 1
    """

    chk1 = namespace.startswith("PCA-v1/")
    chk2 = check_uppercase_HEX_isvalid(namespace[7:], 64)

    return chk1 and chk2


# Tests
if __name__ == "__main__":
    print("Namespace:", generate_Namespace())
