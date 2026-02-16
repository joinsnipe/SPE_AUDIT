"""
Proof Input Hashing.

Computes the SHA-256 hash of the canonical proof input manifest.
This hash is recorded in the ForensicCapsule as proof_input_hash,
binding the manifest to the capsule.
"""

import hashlib


def hash_proof_input(canonical_bytes: bytes) -> str:
    """
    SHA-256 hex digest of the canonical proof input bytes.
    
    The canonical bytes MUST be produced by canonicalize_proof_input()
    to ensure the signature field is excluded.
    """
    return hashlib.sha256(canonical_bytes).hexdigest()
