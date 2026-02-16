"""
SPE Engine — Stateless Proof Engine
====================================

Cryptographic integrity engine for certifying AI outputs,
digital documents, and arbitrary binary objects.

Core Capabilities (Production-Validated):
  - AI Output Certification (text, hash, file)
  - Ed25519 Digital Signatures (optional)
  - Append-Only Hash-Chain Ledger (SQLite)
  - Temporal Violation of Context Detection (TVOC)
  - Offline Hermetic Verification
"""

__version__ = "2.6.7"

from spe_engine.api import generate_proof, verify_proof
from spe_engine.core.capsule import ForensicCapsule
from spe_engine.core.ledger import AttestationLedger
from spe_engine.crypto.signature import sign_bytes, verify_signature

__all__ = [
    "generate_proof",
    "verify_proof",
    "ForensicCapsule",
    "AttestationLedger",
    "sign_bytes",
    "verify_signature",
]
