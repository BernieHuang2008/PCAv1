import time
import json
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ed25519


from examples.pca_lib.bychapter.c6s2 import check_CanonicalInfoPath_isvalid
from examples.pca_lib.bychapter.c7s2 import check_uppercase_HEX_isvalid
from examples.pca_lib.bychapter.c7s3 import check_JCS_isvalid, serialize_JSON_to_JCS_bytes
from examples.pca_lib.bychapter.c9s4s1 import HARDCODED_IDENTITY_PCA_PUBKEY


def check_purpose_isvalid(purpose: str) -> bool:
    """
    Check if the given purpose is valid.
    Refers to PCAv1.2 Chapter 7 Section 3
    """
    PCA_purposed = [
        "PCA/CRL",
        "PCA/PubkeyTrust"
    ]

    head = purpose.split("/")[0]

    chk1 = head in ["PCA", "Custom"]

    if head == "PCA":
        chk2 = purpose in PCA_purposed
    else:
        chk2 = True

    return chk1 and chk2


def assert_trust_chain_node(node: dict):
    # fmt: off

    assert node.keys() == {"signed_at", "valid_until", "purpose", "to_path", "to_pubkey", "signer_path", "sign_algo", "signature"}, "Params: node not align with [PCAv1.2 Chapter 7 Section 3]"

    assert                                  node["signed_at"]       <= int(time.time()), "Params: signed_at must be a past timestamp."
    assert                                  node["valid_until"]     > int(time.time()), "Params: valid_until must be a future timestamp."
    assert check_purpose_isvalid(           node["purpose"]         ), "Params: purpose is not align with [PCAv1.2 Chapter 7 Section 3]"
    assert check_CanonicalInfoPath_isvalid( node["to_path"]         ), "Params: to_path is not align with [PCAv1.2 Chapter 6 Section 2]"
    assert check_uppercase_HEX_isvalid(     node["to_pubkey"]       , 64), "Params: to_pubkey is not align with [PCAv1.2 Chapter 7 Section 2]"
    assert check_CanonicalInfoPath_isvalid( node["signer_path"]     ), "Params: signer_path is not align with [PCAv1.2 Chapter 6 Section 2]"
    assert                                  node["sign_algo"]       == "SHA-256", "Params: sign_algo must be 'SHA-256'."
    # ASSUME                                node["signature"]       at least shall have dummy data.
    
    # fmt: on


def sign_trust_chain_node(node: dict, signer_node_privkey: str) -> dict:
    assert_trust_chain_node(node)
    assert check_uppercase_HEX_isvalid(signer_node_privkey, 128), "Params: signer_node_privkey is not align with [PCAv1.2 Chapter 6 Section 1]"

    node_copy = node.copy()
    del node_copy["signature"]

    sign_msg = sha256(serialize_JSON_to_JCS_bytes(node_copy)).digest()

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signer_node_privkey[:64]))
    signature = private_key.sign(sign_msg)
    signature_hex = signature.hex().upper()
    del private_key

    node["signature"] = signature_hex
    return signature_hex


def check_trust_chain_node(node: dict, signer_pubkey: str) -> bool:
    assert_trust_chain_node(node)
    assert check_uppercase_HEX_isvalid(signer_pubkey, 64), "Params: signer_pubkey is not align with [PCAv1.2 Chapter 7 Section 2]"

    node_copy = node.copy()

    signature_hex = node_copy["signature"]
    del node_copy["signature"]

    sign_msg = sha256(serialize_JSON_to_JCS_bytes(node_copy)).digest()

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer_pubkey))
        public_key.verify(bytes.fromhex(signature_hex), sign_msg)
    except Exception:
        return False

    return True


def check_trust_chain_isvalid(trust_chain: str, purpose_checker: function) -> bool:
    """
    trust_chain: str
        The trust chain (in JSONL format) to be checked.
    purpose_checker: function
        A function that checks the purpose of the trust chain.
    """
    # Split the trust chain into individual nodes
    nodes = trust_chain.strip().split("\n")
    if len(nodes) == 0:
        raise ValueError("Trust chain is empty.")

    purposes = []
    for i in range(len(nodes)):
        node = nodes[i]

        # JCS format. for performance reasons, this step MAY be skipped.
        assert check_JCS_isvalid(node), f"Trust chain node {i} is not valid JCS."
        node_json = json.loads(node)

        # time. (signed_at & valid_until)
        assert node_json["signed_at"] <= int(time.time()), f"Trust chain node {i} has signed_at in the future."
        assert node_json["valid_until"] > int(time.time()), f"Trust chain node {i} has expired."

        # hash algo. (hash_algo) allows other hash_algo in the future, so we won't use assertion here.
        if node_json["hash_algo"] != "SHA-256":
            raise ValueError(f"Trust chain node {i} has invalid hash_algo: {node_json['hash_algo']}. Expected 'SHA-256'.")

        # purpose. (purpose)
        assert check_purpose_isvalid(node_json["purpose"]), f"Trust chain node {i} has invalid purpose."
        purposes.append(node_json["purpose"])   # give to purpose_checker at the end

        if i == 0:
            # first node: signed directly by `Identity/V1/PCA``
            assert node_json["signer_path"] == "Identity/V1/PCA", f"Trust chain node {i} has invalid signer_path."
            assert node_json["signer_pubkey"] == HARDCODED_IDENTITY_PCA_PUBKEY, f"Trust chain node {i} has invalid signer_pubkey."
            assert check_trust_chain_node(node_json, HARDCODED_IDENTITY_PCA_PUBKEY), f"Trust chain node {i} has invalid signature."
        else:
            # subsequent nodes: signed by the previous node
            prev_node_json = json.loads(nodes[i - 1])
            assert node_json["signer_path"] == prev_node_json["to_path"], f"Trust chain node {i} has invalid signer_path."
            assert node_json["signer_pubkey"] == prev_node_json["to_pubkey"], f"Trust chain node {i} has invalid signer_pubkey."
            assert check_trust_chain_node(node_json, prev_node_json["to_pubkey"]), f"Trust chain node {i} has invalid signature."

    # purpose_checker. (purpose_checker)
    assert purpose_checker(purposes), "Trust chain purposes sequence do not satisfy the purpose_checker."

    return True



if __name__=='__main__':
    pass
