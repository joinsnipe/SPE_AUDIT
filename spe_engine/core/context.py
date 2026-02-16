"""
ContextItem — Represents a piece of contextual information
available to an AI model at attestation time.

In RAG (Retrieval-Augmented Generation) workflows, each document
retrieved and fed to the LLM becomes a ContextItem. The collection
of ContextItems is then hashed into the context_merkle_root,
certifying exactly WHICH information the AI had access to.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class ContextItem:
    """
    A single piece of context available at attestation time.
    
    Attributes:
        doc_id: Unique identifier for the document
        content_hash: SHA-256 hash of the document content
        timestamp: Unix timestamp of the document's creation/retrieval
        source_id: Identifier of the source system (e.g., "rag-index-v2")
    """
    doc_id: str
    content_hash: str
    timestamp: int
    source_id: str


def canonicalize_context(items: List[ContextItem]) -> List[Dict[str, Any]]:
    """
    Sort context items deterministically for reproducible hashing.
    
    Sort order: (doc_id, timestamp, source_id) — ensures the same
    set of context items always produces the same canonical form.
    """
    sorted_items = sorted(items, key=lambda x: (x.doc_id, x.timestamp, x.source_id))
    return [asdict(item) for item in sorted_items]


def serialize_canonical_context(canonical: List[Dict[str, Any]]) -> bytes:
    """
    Serialize canonical context to deterministic JSON bytes.
    
    Uses sorted keys and minimal separators to ensure
    byte-identical output across implementations.
    """
    return json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
