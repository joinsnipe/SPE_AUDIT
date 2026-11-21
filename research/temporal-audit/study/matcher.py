"""Small proposition matcher for four named events. It can explicitly abstain."""
import re


def classify(text, cutoff, event):
    """Return POST_ASSERTION, OTHER or REVIEW. Never consumes evaluation labels."""
    s = text.casefold().strip()
    if not s:
        return "REVIEW"
    if s.endswith("?") or s.startswith(("the question asks", "there is no confirmation", "the outcome cannot")):
        return "OTHER"
    if re.search(r"\b(expected|scheduled|planned|may|might|could|will)\b", s):
        return "OTHER"
    if any(phrase.casefold() in s for phrase in event["affirmed_phrases"]):
        return "POST_ASSERTION" if event["event_date"] > cutoff else "OTHER"
    return "REVIEW"

