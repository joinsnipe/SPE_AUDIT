"""
ForensicCapsule — The core attestation record for AI output certification.

Each capsule captures:
  - WHAT was certified (output_hash)
  - WHEN it was certified (t_run, t_target)  
  - WHICH model produced it (model_id)
  - WHAT prompt was used (hash_prompt)
  - WHAT context was available (context_merkle_root)
  - UNDER what policy (gate_policy_id)
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


def _canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    """Deterministic JSON serialization for reproducible hashing."""
    return json.dumps(
        obj,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_hash(h: str, alg: str = "sha256") -> str:
    h = h.strip().lower()
    if ":" in h:
        return h
    return f"{alg}:{h}"


@dataclass(frozen=True)
class ForensicCapsule:
    """
    Immutable attestation record.
    
    Required fields capture the complete certification context:
      - t_target: The declared target time (e.g., year of AI knowledge cutoff)
      - gate_policy_id: Gating policy applied ("strict", "open")
      - context_merkle_root: Hash of context documents used by the AI
      - model_id: AI model identifier (e.g., "gpt-4", "claude-3")
      - hash_prompt: SHA-256 hash of the prompt sent to the AI
      - t_run: Unix timestamp when the certification was generated
      - output_hash: SHA-256 hash of the AI output being certified
    """
    # Required
    t_target: int
    gate_policy_id: str
    context_merkle_root: str
    model_id: str
    hash_prompt: str
    t_run: int
    output_hash: str

    # Optional (recommended for production)
    artifact_type: Optional[str] = None    # "ai-output" | "image" | "pdf" | "video"
    mode: Optional[str] = None             # "text" | "hash-only" | "file"
    hash_alg: Optional[str] = None         # "sha256"

    # Optional (advanced)
    snapshot_hash: Optional[str] = None
    index_snapshot_hash: Optional[str] = None
    normalization_params_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d.get("output_hash"):
            d["output_hash"] = normalize_hash(
                d["output_hash"], d.get("hash_alg") or "sha256"
            )
        return {k: v for k, v in d.items() if v is not None}

    def canonical_bytes(self) -> bytes:
        """Deterministic byte representation for hashing."""
        return _canonical_json_bytes(self.to_dict())

    def capsule_hash(self) -> str:
        """SHA-256 hash of the capsule's canonical form."""
        return sha256_hex(self.canonical_bytes())

    def write_json(self, path: str) -> None:
        """Write capsule to a JSON file."""
        data = self.to_dict()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
