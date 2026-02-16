"""
SHA-256 Hashing Utilities.

All content fingerprinting in SPE uses SHA-256, which provides:
  - 256-bit collision resistance
  - Deterministic output for identical input
  - One-way function (cannot reverse hash to content)
"""

import hashlib


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file_hex(file_path: str) -> str:
    """
    Compute SHA-256 hex digest of a file.
    
    Reads in 1MB chunks for memory efficiency with large files.
    """
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
