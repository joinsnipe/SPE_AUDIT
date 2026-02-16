"""
Temporal Gating — Filters context items by temporal boundary.

In AI certification, temporal gating ensures that the attestation
only considers information that was available at or before the
declared target time (t_target). This is critical for proving
that an AI did NOT have access to future information.

Example: If t_target = 2025, only documents with timestamp <= 2025
are included in the context, even if the RAG index contained
documents from 2026.
"""

from typing import List
from spe_engine.core.context import ContextItem


def apply_temporal_gating(
    items: List[ContextItem], t_target: int
) -> List[ContextItem]:
    """
    Filter context items to include only those at or before t_target.
    
    This ensures the certified context reflects only what was
    temporally available, preventing future-information leakage.
    """
    return [item for item in items if item.timestamp <= t_target]
