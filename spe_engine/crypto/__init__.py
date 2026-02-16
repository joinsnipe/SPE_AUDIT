"""
SPE Engine Crypto — SHA-256 hashing and Ed25519 signing.
"""

from spe_engine.crypto.hash import sha256_hex, sha256_file_hex
from spe_engine.crypto.signature import sign_bytes, verify_signature, nacl_available

__all__ = [
    "sha256_hex",
    "sha256_file_hex",
    "sign_bytes",
    "verify_signature",
    "nacl_available",
]
