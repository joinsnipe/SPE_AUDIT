"""
Merkle Root — Computes the context_merkle_root for the ForensicCapsule.

The context_merkle_root certifies the exact set of documents that were
available to an AI model during output generation. Any change to the
context (different documents, altered content) produces a different root.

Current implementation: SHA-256 of serialized context.
Future: Full binary Merkle tree for partial proofs.
"""

import hashlib


def compute_context_merkle_root(serialized_context: bytes) -> str:
    """
    Compute the Merkle root of the serialized context.
    
    MVP: Simple SHA-256 hash of the canonical context bytes.
    This is cryptographically sufficient for proving context integrity.
    
    Future versions may implement a full binary Merkle tree to support
    partial disclosure proofs (proving a specific document was in the
    context without revealing all documents).
    """
    return hashlib.sha256(serialized_context).hexdigest()
