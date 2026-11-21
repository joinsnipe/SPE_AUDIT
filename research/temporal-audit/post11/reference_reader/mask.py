"""Prepare masked, allowlisted inputs. The mapping is kept separate from the protocol."""
import argparse
from datetime import date
import hashlib
import hmac
import json
from pathlib import Path
import secrets

FIELDS = {"key", "event", "event_date", "cutoff", "question", "answer", "source", "language"}


def canonical(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def unique(items, name):
    vals = {}
    for x in items:
        k = x.get("id")
        if not isinstance(k, str) or not k or k in vals:
            raise ValueError("invalid or duplicate " + name)
        vals[k] = x
    return vals


def check(rows):
    if not isinstance(rows, list) or not rows:
        raise ValueError("empty or invalid worksheet")
    seen = set()
    for r in rows:
        if set(r) != FIELDS or any(not isinstance(v, str) for v in r.values()):
            raise ValueError("unexpected field or type in masked worksheet")
        key = r["key"]
        if len(key) != 16 or any(c not in "0123456789abcdef" for c in key) or key in seen:
            raise ValueError("invalid or duplicated masked key")
        if any(date.fromisoformat(r[k]).isoformat() != r[k] for k in ("cutoff", "event_date")):
            raise ValueError("expected ISO day precision")
        if not r["event"].strip() or not r["answer"].strip() or not r["question"].strip():
            raise ValueError("missing text")
        if len(r["answer"]) > 1800 or len(r["question"]) > 2000 or len(r["event"]) > 200:
            raise ValueError("outside pre-registered context size")
        seen.add(key)
    return rows


def prepare(cases, events, salt):
    named = unique(events, "event ID")
    ordered, mapping = [], {}
    for cid, c in unique(cases, "case ID").items():
        event = named[c.get("event_id", c.get("event"))]
        k = hmac.new(salt, cid.encode(), hashlib.sha256).hexdigest()[:16]
        mapping[k] = cid
        ordered.append({"key": k, "event": event["name"], "event_date": event["event_date"], "cutoff": c["cutoff"],
                        "question": c["prompt"], "answer": c.get("text", c.get("output")), "source": event.get("source_url", ""),
                        "language": c.get("language", "en")})
    return sorted(check(ordered), key=lambda r: r["key"]), mapping


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for option in ("cases", "events", "out", "mapping"):
        p.add_argument("--"+option, required=True, type=Path)
    a = p.parse_args()
    if a.out.exists() or a.mapping.exists() or a.out.resolve() == a.mapping.resolve():
        p.error("new and distinct output paths required")
    salt = secrets.token_bytes(32)
    rows, mapping = prepare(json.loads(a.cases.read_bytes()), json.loads(a.events.read_bytes()), salt)
    a.mapping.write_bytes(canonical({"map": mapping, "salt_hex": salt.hex()}))
    a.out.write_bytes(canonical(rows))
