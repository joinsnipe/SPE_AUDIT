"""
SPE Engine TVOC — Temporal Violation of Context detection.

TVOC is a novel forensic signal specific to AI output certification.
It detects when an AI model produces information that references
temporal events beyond its declared knowledge boundary.

Example:
    If t_target = 2025 and the AI output mentions "In 2027, the EU...",
    this is a Strong TVOC — the AI referenced a future year without
    having post-target context available.
"""

from spe_engine.tvoc.detector import detect_tvoc_strong
from spe_engine.tvoc.extract import extract_years

__all__ = ["detect_tvoc_strong", "extract_years"]
