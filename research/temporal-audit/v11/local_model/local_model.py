"""Offline character language model with a supervised stance head (Python 3.10+)."""
from datetime import date
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import re
import unicodedata

ROOT = Path(__file__).resolve().parent
MODEL_FILE = ROOT / "weights.json"
LANGUAGES = {"en", "es", "fr", "de"}
LOW, HIGH = 0.30, 0.70
MAX_CHARS = 512


def normalize(text):
    return " ".join(unicodedata.normalize("NFC", text).casefold().split())


def character_windows(text, alphabet, width, *, include_end=True):
    history = [0] * width
    windows, targets = [], []
    for symbol in normalize(text):
        token = alphabet.get(symbol, 1)
        windows.append(tuple(history))
        targets.append(token)
        history = history[1:] + [token]
    if include_end:
        windows.append(tuple(history))
        targets.append(2)
    return windows, targets


@lru_cache(maxsize=1)
def load():
    raw = MODEL_FILE.read_bytes()
    data = json.loads(raw)
    return data, {s: i for i, s in enumerate(data["vocabulary"])}, hashlib.sha256(raw).hexdigest()


def softmax(logits):
    largest = max(logits)
    values = [math.exp(x - largest) for x in logits]
    total = sum(values)
    return [n / total for n in values]


def affine(values, weight, bias):
    output = list(bias)
    for x, row in zip(values, weight):
        for i, v in enumerate(row):
            output[i] += x * v
    return output


def encode(context, w):
    features = [value for token in context for value in w["embedding"][token]]
    return [math.tanh(x) for x in affine(features, w["context_w"], w["context_b"])]


def next_characters(prefix, *, count=5):
    """Next normalized character (or end) for one prefix. Returns raw model probabilities."""
    model, alphabet, _ = load()
    width = model["width"]
    context = ([0] * width + [alphabet.get(x, 1) for x in normalize(prefix)])[-width:]
    hidden = encode(context, model["parameters"])
    w = model["parameters"]
    probs = softmax(affine(hidden, w["lm_w"], w["lm_b"]))
    ranked = sorted(enumerate(probs), key=lambda pair: -pair[1])[:max(0, count)]
    return [{"character": model["vocabulary"][i], "probability": p} for i, p in ranked]


def head_probability(text):
    model, alphabet, _ = load()
    w = model["parameters"]
    windows, _ = character_windows(text, alphabet, model["width"])
    hidden = [encode(context, w) for context in windows]
    columns = list(zip(*hidden))
    features = [sum(col) / len(col) for col in columns] + [max(col) for col in columns]
    return softmax(affine(features, w["stance_w"], w["stance_b"]))[1]


def matched_spans(text, terms):
    result = []
    for term in terms:
        if not isinstance(term, str) or not term.strip():
            continue
        for match in re.finditer(r"(?<!\w)" + re.escape(term.strip()) + r"(?!\w)", text, re.IGNORECASE):
            result.append((match.start(), match.end(), match.group(0)))
    return [{"start": a, "end": b, "text": t} for a, b, t in sorted(set(result))]


def iso_day(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.isoformat() == value else None


def predict(case, event):
    """Classify one answer for one supplied event. All model operations are local."""
    def string(value):
        return value if isinstance(value, str) else ""

    def string_list(value):
        return value if isinstance(value, (list, tuple)) else []

    text = string(case.get("text", case.get("output")))
    prompt = string(case.get("prompt"))
    subject = string(event.get("name"))
    case_event = string(case.get("event_id", case.get("event")))
    event_id = string(event.get("id"))
    language = string(case.get("language", "en"))
    event_day, cutoff = iso_day(event.get("event_date")), iso_day(case.get("cutoff"))
    names = [subject, *string_list(event.get("aliases"))]
    trace = {
        "case_id": case.get("id"),
        "registered_event_id": event_id,
        "supplied_subject": subject,
        "source_url": string(event.get("source_url")),
        "cutoff": case.get("cutoff"),
        "event_date": event.get("event_date"),
        "language": language,
        "answer_quote": text,
        "answer_span": [0, len(text)],
        "subject_in_answer": matched_spans(text, names),
        "subject_in_prompt": matched_spans(prompt, names),
        "registered_outcome_in_answer": matched_spans(text, string_list(event.get("outcome_terms"))),
        "weights_sha256": load()[2],
    }
    score = None
    if not event_id or case_event != event_id or not subject or not event_day or not cutoff:
        decision, reason = "REVIEW", "missing_or_inconsistent_event_or_date"
    elif language not in LANGUAGES:
        decision, reason = "REVIEW", "unsupported_language"
    elif not text.strip() or len(normalize(text)) > MAX_CHARS:
        decision, reason = "REVIEW", "empty_or_overlength_answer"
    elif event_day <= cutoff:
        decision, reason = "OTHER", "registered_event_on_or_before_cutoff"
    elif not trace["subject_in_answer"] and not trace["subject_in_prompt"]:
        decision, reason = "REVIEW", "no_literal_subject_anchor"
    else:
        score = head_probability(text)
        if score >= HIGH:
            decision, reason = "POST_ASSERTION", "above_fixed_upper_boundary"
        elif score <= LOW:
            decision, reason = "OTHER", "below_fixed_lower_boundary"
        else:
            decision, reason = "REVIEW", "inside_abstention_interval"
    trace["status"] = decision
    trace["reason"] = reason
    return {"decision": decision, "score": score, "p_assertion": score, "reason": reason, "trace": trace}
