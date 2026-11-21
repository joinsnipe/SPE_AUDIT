"""
Year extraction from text for TVOC detection.

MVP implementation: Extracts explicit 4-digit year mentions
in the format 19XX or 20XX using regex.

Future enhancements may include:
  - Relative time expressions ("next year", "last decade")
  - Date ranges ("2025-2030")
  - Natural language temporal references
"""

import re
from typing import List

YEAR_REGEX = re.compile(r"\b(19|20)\d{2}\b")


def extract_years(text: str) -> List[int]:
    """
    Extract explicit year mentions from text.
    
    Finds all 4-digit numbers starting with 19 or 20 at word boundaries.
    
    Returns:
        List of years as integers (may contain duplicates)
    """
    return [int(m.group(0)) for m in YEAR_REGEX.finditer(text)]
