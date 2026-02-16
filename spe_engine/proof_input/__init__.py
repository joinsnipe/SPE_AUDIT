"""
SPE Engine Proof Input — Canonicalization, hashing, and signing
of the proof input manifest.
"""

from spe_engine.proof_input.canonical import canonicalize_proof_input
from spe_engine.proof_input.hash import hash_proof_input
from spe_engine.proof_input.signature import sign_proof_input, verify_proof_input_signature

__all__ = [
    "canonicalize_proof_input",
    "hash_proof_input",
    "sign_proof_input",
    "verify_proof_input_signature",
]
