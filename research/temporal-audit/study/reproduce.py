"""Regenerate the paper's results, tables and local evidence records (Python 3.10+)."""
import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

from capture import run_capture, verify_file
from matcher import classify

ROOT = Path(__file__).resolve().parent
VENDOR = ROOT / "vendor"
sys.path.insert(0, str(VENDOR))
from spe_engine.tvoc.detector import detect_tvoc_strong

POS = "POST_ASSERTION"
NEG = "OTHER"
METHODS = ("year_rule", "dated_matcher")


def read_data(name):
    return json.loads((ROOT / "data" / name).read_text(encoding="utf-8"))


def dump_json(path, data):
    serialized = json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    path.write_text(serialized, encoding="utf-8", newline="\n")


def pins():
    expected = {
        "spe_engine/tvoc/detector.py": "b13ce4b5fc224e0f4a6c040fe03446b10a28608f",
        "spe_engine/tvoc/extract.py": "cafcb5d4159c6e2a4a0b73593e2af9efe453c812",
    }
    for name, blob_id in expected.items():
        data = (VENDOR / name).read_bytes()
        header = f"blob {len(data)}\0".encode()
        if hashlib.sha1(header + data).hexdigest() != blob_id:
            raise ValueError(f"upstream file changed: {name}")
    frozen = {
        ROOT / "matcher.py": "a79045f6c8dd59aba75ed65982e48609a4e44622d981570618d6c5af7046ee8e",
        ROOT / "data/challenge.json": "c308ddbbab195d97662840196e9543f31af11b2b6372aa5f3f65eb66d7ffe2fb",
        ROOT / "data/challenge_labels.json": "247096b67b489b0fe33bdb1cff2c3dc3a8dadd78e5bd99cf4eaa6a4ff4d5b466",
    }
    for path, digest in frozen.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"frozen input changed: {path.name}")


def score(rows, method):
    result = dict(tp=0, fp=0, tn=0, fn=0, review_positive=0, review_negative=0)
    for row in rows:
        predicted, gold = row[method], row["label"]
        if predicted == "REVIEW":
            cell = "review_positive" if gold == POS else "review_negative"
        elif predicted == POS:
            cell = "tp" if gold == POS else "fp"
        else:
            cell = "fn" if gold == POS else "tn"
        result[cell] += 1
    tp, fp, tn, fn, rp, rn = result.values()
    result["n"] = len(rows)
    result["covered"] = tp + fp + tn + fn
    result["positive_total"] = tp + fn + rp
    result["negative_total"] = tn + fp + rn
    return result


def extract_latest(payload):
    """A transparent local consumer, without a language model or network call."""
    request = json.loads(payload)
    sources = request["sources"]
    return max(sources, key=lambda card: (card["date"], card["id"]))["text"] if sources else "No eligible source."


def build(destination):
    pins()
    destination.mkdir(parents=True, exist_ok=True)
    events = {event["id"]: event for event in read_data("events.json")}
    records, predictions, demonstrations = [], [], []
    for split, file in (("constructed", "cases.json"), ("challenge", "challenge.json")):
        for case in read_data(file):
            event = events[case["event"]]
            # Replay an authored output. This callback is deliberately independent of request content.
            capture = run_capture(case["cutoff"], case["prompt"], event["sources"], lambda _, case=case: case["output"])
            request = json.loads(capture["request_utf8"])
            if any(card["date"] > case["cutoff"] for card in request["sources"]):
                raise ValueError("postdated source admitted")
            alarm = detect_tvoc_strong(capture["output"], int(case["cutoff"][:4]), False)
            marker = {"id": case["id"], "split": split, "event": case["event"], "cutoff": case["cutoff"],
                      "year_rule": POS if alarm["tvoc"] == "STRONG" else NEG,
                      "dated_matcher": classify(capture["output"], case["cutoff"], event),
                      "record_line": len(records) + 1, "record_sha256": capture["record_sha256"]}
            records.append(capture)
            predictions.append(marker)

    # Labels are read only after all predictions have been fixed.
    primary = read_data("labels.json")
    challenge = read_data("challenge_labels.json")
    labels = {**primary, **challenge}
    ids = [r["id"] for r in predictions]
    if len(ids) != len(set(ids)) or set(ids) != set(labels) or set(primary) & set(challenge):
        raise ValueError("case and label ids do not match one-to-one")
    for row in predictions:
        row.update(labels[row["id"]])
        if row["label"] not in (POS, NEG):
            raise ValueError("unexpected label")

    for event in events.values():
        prompt = "What is the latest supplied report about this mission?"
        early, late = event["sources"]
        for condition, cutoff, cards in (
            ("before", early["date"], [early, late]),
            ("after", late["date"], [early, late]),
            ("after_without_outcome", late["date"], [early]),
        ):
            record = run_capture(cutoff, prompt, cards, extract_latest)
            if record["output"] != (late if condition == "after" else early)["text"]:
                raise ValueError("source intervention did not select the expected report")
            demonstrations.append({"event": event["id"], "condition": condition, "record_line": len(records) + 1,
                                   "record_sha256": record["record_sha256"], "output": record["output"]})
            records.append(record)

    capsules = destination / "capsules.jsonl"
    with capsules.open("w", encoding="utf-8", newline="\n") as out:
        for row in records:
            out.write(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n")
    n, digest = verify_file(capsules)
    with (destination / "predictions.csv").open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(predictions[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(predictions)
    result = {}
    for split in ("constructed", "challenge"):
        subset = [r for r in predictions if r["split"] == split]
        result[split] = {method: score(subset, method) for method in METHODS}
    groups = {}
    for group in sorted(set(row["cutoff_group"] for row in predictions)):
        subset = [r for r in predictions if r["cutoff_group"] == group]
        groups[group] = {m: score(subset, m) for m in METHODS}
    dump_json(destination / "summary.json", {"splits": result, "cutoff_groups": groups, "record_count": n,
                                           "capsules_sha256": digest, "interventions": len(demonstrations)})
    dump_json(destination / "interventions.json", demonstrations)
    print(json.dumps(result, indent=2))
    print(f"{n} verified records. SHA-256 {digest}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "results")
    build(parser.parse_args().out)

