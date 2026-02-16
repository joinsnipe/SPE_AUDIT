"""
SPE Engine Core — Capsule, Ledger, Context, Merkle, Temporal.
"""

from spe_engine.core.capsule import ForensicCapsule
from spe_engine.core.ledger import AttestationLedger
from spe_engine.core.context import ContextItem, canonicalize_context, serialize_canonical_context
from spe_engine.core.merkle import compute_context_merkle_root
from spe_engine.core.temporal import apply_temporal_gating

__all__ = [
    "ForensicCapsule",
    "AttestationLedger",
    "ContextItem",
    "canonicalize_context",
    "serialize_canonical_context",
    "compute_context_merkle_root",
    "apply_temporal_gating",
]
