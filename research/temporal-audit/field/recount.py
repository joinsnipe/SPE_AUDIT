"""Recount anonymized per-response observations from the archived prompt-only pilot."""
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent

def count(rows):
    totals = Counter()
    for row in rows:
        totals["attempted"] += 1
        if row["http_status"] == 429:
            totals["http_429"] += 1
            continue
        if row["http_status"] != "text_returned":
            raise ValueError("Unknown response status")
        totals["texts"] += 1
        # The archived pilot passed the expected event class into this rule.
        keyword = row["prompt_class"] == "POST" and len(row["keyword_hits"]) >= 2
        # The public SPE detector was replayed with no dated retrieval context.
        year = any(year > 2023 for year in row["explicit_years"])
        if keyword != row["logged_keyword_alarm"] or year != row["replayed_year_alarm"]:
            raise ValueError("Per-response flag mismatch: " + row["response_id"])
        totals["keyword_alarms"] += int(keyword)
        totals["year_alarms"] += int(year)
    return dict(sorted(totals.items()))

if __name__ == "__main__":
    data = json.loads((HERE / "pilot_observations.json").read_text(encoding="utf-8"))
    print(json.dumps(count(data["observations"]), sort_keys=True))
