import re


def check_uppercase_HEX_isvalid(hex_str: str, length: int | None = None) -> bool:
    """
    Check if the given string is a valid uppercase HEX string.
    Refers to PCAv1.2 Chapter 7 Section 2
    """
    assert length is None or length > 0, "Length must be a positive integer or None"

    chk1 = re.fullmatch(r"[A-F0-9]+", hex_str) is not None

    chk2 = (len(hex_str) == length) if length is not None else True

    return chk1 and chk2
