"""
Proof Input Canonicalization.

The proof input manifest contains metadata about the certification:
  - schema_version
  - hash_algorithm
  - hash_value (the output hash)
  - t_run
  - context

CRITICAL RULE: The "signature" field is EXCLUDED from canonicalization.
This ensures that the signature signs the content without including
itself — a standard cryptographic practice.
"""

import json
from copy import deepcopy
from typing import Any, Dict


def canonicalize_proof_input(proof_input: Dict[str, Any]) -> bytes:
    """
    Produce deterministic bytes from a proof input manifest.
    
    The "signature" field is always excluded from the canonical form.
    This allows the signature to be computed over the manifest content
    without creating a circular dependency.
    
    Returns:
        Deterministic JSON bytes suitable for hashing or signing
    """
    obj = deepcopy(proof_input)
    obj.pop("signature", None)

    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
