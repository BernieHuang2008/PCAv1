from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC


from examples.pca_lib.bychapter.c5s1 import check_Namespace_isvalid
from examples.pca_lib.bychapter.c6s2 import check_CanonicalInfoPath_isvalid
from examples.pca_lib.bychapter.c7s2 import check_uppercase_HEX_isvalid


def HKDF_extract(salt: bytes, input_key_material: bytes) -> bytes:
    """
    HKDF-Extract(salt, IKM) -> PRK
    """
    if salt is None or len(salt) == 0:
        salt = bytes([0] * hashes.SHA512().digest_size)
    hmac = HMAC(salt, input_key_material, hashes.SHA512())
    return hmac.finalize()


def HKDF_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand(PRK, info, L) -> OKM
    """
    hash_len = hashes.SHA512().digest_size
    if length > 255 * hash_len:
        raise ValueError(
            "Cannot expand to more than 255 * HashLen bytes using the specified hash function"
        )

    okm = b""
    previous_block = b""
    for block_index in range(1, (length + hash_len - 1) // hash_len + 1):
        hmac = HMAC(prk, previous_block + info + bytes([block_index]), hashes.SHA512())
        previous_block = hmac.finalize()
        okm += previous_block

    return okm[:length]


def HKDF_stream_block(
    parent_key_hex: str, namespace: str, canonical_info_path: str, block_index: int
) -> bytes:
    """
    Derive a specific block from the HKDF stream.
    """
    assert check_uppercase_HEX_isvalid(
        parent_key_hex, 128
    ), "Params: parent_key_hex is not align with [PCAv1.2 Chapter 7 Section 2]"
    assert check_Namespace_isvalid(
        namespace
    ), "Params: namespace is not align with [PCAv1.2 Chapter 5 Section 1]"
    assert check_CanonicalInfoPath_isvalid(
        canonical_info_path
    ), "Params: CanonicalInfoPath is not align with [PCAv1.2 Chapter 6 Section 2]"
    assert block_index >= 0, "Block index must starts from 0"

    prk = HKDF_extract(
        salt=namespace.encode("UTF-8"), input_key_material=bytes.fromhex(parent_key_hex)
    )
    return HKDF_expand(
        prk=prk,
        info=(canonical_info_path + "/Block" + str(block_index)).encode("UTF-8"),
        length=256,
    )


def HKDF_stream_iterator(parent_key_hex: str, namespace: str, canonical_info_path: str):
    """
    Generate an iterator for the HKDF stream.
    """
    block_index = 0
    while True:
        yield HKDF_stream_block(
            parent_key_hex, namespace, canonical_info_path, block_index
        )
        block_index += 1
