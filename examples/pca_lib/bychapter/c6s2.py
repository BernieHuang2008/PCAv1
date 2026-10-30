import re


def check_CanonicalInfoPath_isvalid(canonical_info_path: str) -> bool:
    """
    Check if the given Canonical Info Path is valid.
    Refers to PCAv1.2 Chapter 6 Section 1
    """

    chk1 = re.fullmatch(r"[A-Za-z0-9/-]+", canonical_info_path) is not None

    return chk1
