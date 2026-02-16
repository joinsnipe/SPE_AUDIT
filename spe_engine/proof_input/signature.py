"""
Proof Input Signature — Sign and verify the proof input manifest.

This module wraps the low-level Ed25519 operations to work with
the higher-level proof input structure. The signing flow:

1. Canonicalize proof input (excluding "signature" field)
2. Sign the canonical bytes with Ed25519
3. Attach the signature block to the proof input
4. The signature block contains: algorithm, public_key, signature_value
"""

from typing import Dict, Optional

from spe_engine.proof_input.canonical import canonicalize_proof_input
from spe_engine.crypto.signature import sign_bytes, verify_signature


def sign_proof_input(
    proof_input: dict,
    private_key_b64: str,
) -> Dict[str, str]:
    """
    Sign a proof input manifest.
    
    Args:
        proof_input: The proof input dictionary (signature field is ignored)
        private_key_b64: Base64-encoded Ed25519 private key seed
        
    Returns:
        Signature block dict with algorithm, public_key, signature_value
    """
    canonical = canonicalize_proof_input(proof_input)
    return sign_bytes(canonical, private_key_b64)


def verify_proof_input_signature(
    proof_input: dict,
    expected_pubkey_b64: Optional[str] = None,
) -> str:
    """
    Verify the signature on a proof input manifest.
    
    Args:
        proof_input: The proof input dict (must contain "signature" block)
        expected_pubkey_b64: Optional expected public key
        
    Returns:
        "VALID", "INVALID", "UNKNOWN", or "PUBKEY_MISMATCH"
    """
    sig_block = proof_input.get("signature")
    if not sig_block:
        return "UNKNOWN"

    canonical = canonicalize_proof_input(proof_input)
    return verify_signature(canonical, sig_block, expected_pubkey_b64)
