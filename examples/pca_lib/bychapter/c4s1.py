from secrets import token_hex


def generate_MasterSecret() -> str:
    """
    Generate a 512-bit Master Secret for use in PCAv1.
    Refers to PCAv1.2 Chapter 4 Section 4.1
    """

    return token_hex(64).upper()  # 64 bytes = 512 bits


# Tests
if __name__ == "__main__":
    print("Master Secret:", generate_MasterSecret())
