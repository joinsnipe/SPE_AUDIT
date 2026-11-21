"""
TVOC Detection — Temporal Violation of Context.

Detects when an AI output mentions years that are strictly greater
than the declared t_target, AND the context had no post-target information.

A "Strong TVOC" is a definitive forensic signal that the AI model
produced temporally impossible information — it referenced events
from a future period without having access to any post-target context.

This is particularly valuable for:
  - Legal evidence: Proving AI-generated content was not manipulated
  - Compliance: Demonstrating AI model behavior consistency
  - Forensics: Detecting anomalous or fabricated AI outputs
"""

from typing import Any, Dict
from spe_engine.tvoc.extract import extract_years


def detect_tvoc_strong(
    output_text: str,
    t_target: int,
    context_has_post_target: bool,
) -> Dict[str, Any]:
    """
    Detect Strong TVOC (Temporal Violation of Context).
    
    A Strong TVOC occurs when:
    - Output mentions a year strictly greater than t_target
    - Context had NO post-target information
    
    This means the AI "hallucinated" temporal information beyond
    its declared knowledge boundary.
    
    Args:
        output_text: The AI model's output text
        t_target: The declared target year
        context_has_post_target: Whether context contained post-target info
        
    Returns:
        Dict with:
          - 'tvoc': "STRONG" or "NONE"
          - 'violating_years': List of years that violate the boundary
          - 't_target': The declared target for reference
    """
    years = extract_years(output_text)
    violating_years = [y for y in years if y > t_target]

    if violating_years and not context_has_post_target:
        return {
            "tvoc": "STRONG",
            "violating_years": violating_years,
            "t_target": t_target,
        }

    return {"tvoc": "NONE", "violating_years": [], "t_target": t_target}
