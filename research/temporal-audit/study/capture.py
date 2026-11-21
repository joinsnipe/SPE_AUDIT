"""Capture a cutoff-filtered request at a local sender boundary, with no dependencies.

The caller supplies a transport that accepts bytes and returns the exact output
text to record. If the transport maps those bytes to a provider-specific payload,
the captured bytes describe its local input, not the provider's wire format.
There is no implicit model call, clock, key, signature, text redaction or remote
execution receipt. Retain sensitive payloads only where disclosure is permitted.

verify_capture(record, digest) compares a single record with an independently
obtained SHA-256 seal. The command-line --expected-root is different: it pins
the exact entire JSONL file, including line endings and order. Publishing a
digest alongside its file enables integrity checks against an independently
retained copy of the digest. It does not independently establish who or when.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Callable


SCHEMA = "spe-temporal-capture/1"
POLICY_ID = "source-publication-date-on-or-before-cutoff/1"
SOURCE_KEYS = {"id", "date", "text", "url"}
RECORD_KEYS = {
    "schema", "policy_id", "request_utf8", "output",
    "request_sha256", "output_sha256", "record_sha256",
}


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _parse_date(value: str) -> date:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
        raise ValueError("expected a calendar date in YYYY-MM-DD form")
    return date.fromisoformat(value)


def _strict_object(pairs: list) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON field: {key}")
        obj[key] = value
    return obj


def _request_bytes(cutoff: str, prompt: str, source_cards: list) -> bytes:
    boundary = _parse_date(cutoff)
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be nonempty text")
    if not isinstance(source_cards, list):
        raise ValueError("source_cards must be a list")
    seen = set()
    selected = []
    for card in source_cards:
        if not isinstance(card, dict) or card.keys() != SOURCE_KEYS:
            raise ValueError("each source must have exactly id, date, text and url")
        for key, value in card.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"source {key} must be nonempty text")
            value.encode("utf-8")
        identifier = card["id"]
        if identifier in seen:
            raise ValueError("duplicate source id")
        seen.add(identifier)
        if _parse_date(card["date"]) <= boundary:
            selected.append(card)
    selected.sort(key=lambda source: source["id"])
    return _canonical_bytes({
        "cutoff": cutoff, "prompt": prompt, "policy_id": POLICY_ID, "sources": selected,
    })


def run_capture(
    cutoff: str, prompt: str, source_cards: list, send: Callable[[bytes], str],
) -> dict:
    """Filter supplied cards by their declared dates, call send once and seal the result.

    Cutoffs are inclusive calendar days. Dates describe the supplied cards and
    are not authenticated. Source IDs must be unique within all candidates.
    A sender exception propagates; no successful receipt is invented. An empty
    output string is kept verbatim. The source bytes, including newlines and
    Unicode, are retained as UTF-8 text within the canonical JSON request.
    """
    request = _request_bytes(cutoff, prompt, source_cards)
    output = send(request)
    if not isinstance(output, str):
        raise ValueError("send must return output text")
    record = {
        "schema": SCHEMA, "policy_id": POLICY_ID,
        "request_utf8": request.decode("utf-8"), "request_sha256": _sha256(request),
        "output": output, "output_sha256": _sha256(output.encode("utf-8")),
    }
    record["record_sha256"] = _sha256(_canonical_bytes(record))
    return record


def verify_capture(record: dict, expected_sha256: str | None = None) -> bool:
    """Verify framing, source eligibility and hashes, optionally against a known seal.

    The check covers the recorded source list; omitted candidates and the
    historical accuracy of supplied dates cannot be reconstructed from it.
    """
    if not isinstance(record, dict) or record.keys() != RECORD_KEYS:
        return False
    if record["schema"] != SCHEMA or record["policy_id"] != POLICY_ID:
        return False
    if not all(isinstance(value, str) for value in record.values()):
        return False
    try:
        raw = record["request_utf8"].encode("utf-8")
        request = json.loads(record["request_utf8"], object_pairs_hook=_strict_object)
        rebuilt = _request_bytes(request["cutoff"], request["prompt"], request["sources"])
        if raw != rebuilt or record["request_sha256"] != _sha256(raw):
            return False
        if record["output_sha256"] != _sha256(record["output"].encode("utf-8")):
            return False
        body = {key: value for key, value in record.items() if key != "record_sha256"}
        seal = _sha256(_canonical_bytes(body))
    except (KeyError, TypeError, ValueError, RecursionError):
        return False
    if record["record_sha256"] != seal:
        return False
    if expected_sha256 is None:
        return True
    return isinstance(expected_sha256, str) and expected_sha256.lower() == seal


def verify_file(path: Path, expected_root: str | None = None) -> tuple[int, str]:
    """Verify every record in order and hash the literal JSONL bytes."""
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        for number, line in enumerate(stream, start=1):
            digest.update(line)
            try:
                record = json.loads(line.decode("utf-8"), object_pairs_hook=_strict_object)
            except (ValueError, RecursionError) as exc:
                raise ValueError(f"invalid JSON at line {number}") from exc
            if not verify_capture(record):
                raise ValueError(f"invalid capture at line {number}")
            count += 1
    if not count:
        raise ValueError("empty capsule file")
    root = digest.hexdigest()
    if expected_root is not None and expected_root.lower() != root:
        raise ValueError("file SHA-256 differs from expected root")
    return count, root


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify temporal-study capsules (JSONL).")
    parser.add_argument("capsules", type=Path)
    parser.add_argument("--expected-root", help="independently retained SHA-256 of entire file")
    args = parser.parse_args()
    try:
        count, root = verify_file(args.capsules, args.expected_root)
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Verified {count} records. File SHA-256: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
