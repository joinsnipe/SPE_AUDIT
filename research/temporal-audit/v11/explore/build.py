"""Rebuild the offline dataset, downloadable CSV and unchanged brand asset."""
import csv
import hashlib
import json
import shutil
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
STUDY = ROOT / "study"
V11 = ROOT / "v11"
SITE = HERE / "site"
sys.path.insert(0, str(STUDY))
from capture import verify_capture, run_capture
from reproduce import extract_latest


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def build():
    events = read(STUDY / "data/events.json")
    raw = (STUDY / "results/capsules.jsonl").read_bytes()
    capsules = [json.loads(line) for line in raw.splitlines()]
    assert len(capsules) == 124 and all(verify_capture(row) for row in capsules)
    missions = {e["id"]: e for e in events}
    baselines = {}
    for item in read(STUDY / "results/interventions.json"):
        e = missions[item["event"]]
        record = capsules[item["record_line"] - 1]
        req = json.loads(record["request_utf8"])
        cards = [c for c in e["sources"] if c["id"] != e["outcome_card"]] if item["condition"] == "after_without_outcome" else e["sources"]
        assert item["record_sha256"] == record["record_sha256"]
        assert run_capture(req["cutoff"], req["prompt"], cards, extract_latest) == record
        baselines.setdefault(e["id"], {})[item["condition"]] = {"line": item["record_line"], "record": record}
    cases = {}
    for path in (STUDY / "data/cases.json", STUDY / "data/challenge.json", V11 / "holdout/cases.json"):
        cases.update({item["id"]: item for item in read(path)})
    answers = {r["key"]: r["decision"] for r in read(V11 / "reader/answers.json")}
    with (V11 / "results/decisions.csv").open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        case = cases[row["id"]]
        row.update(cutoff=case["cutoff"], prompt=case["prompt"], text=case.get("output", case.get("text")))
        key = hashlib.sha256(("spe-1.1-reader|" + row["id"]).encode()).hexdigest()[:10]
        row["reader"] = answers[key] if row["group"] == "new_challenge" else ""
    assert len(cases) == len(rows) == len({r["id"] for r in rows}) == 160
    assert sum(bool(r["reader"]) for r in rows) == 48
    SITE.mkdir(exist_ok=True)
    with (SITE / "cases.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    data = {"events": events, "baselines": baselines, "rows": rows, "capsuleRoot": hashlib.sha256(raw).hexdigest()}
    (SITE / "data.js").write_text("window.SPE_DATA = " + json.dumps(data, ensure_ascii=False, separators=(",", ":")) + ";\n", encoding="utf-8")
    shutil.copyfile(ROOT / "assets/logo.png", SITE / "logo.png")
    with zipfile.ZipFile(HERE / "offline.zip", "w") as package:
        for file in sorted(SITE.iterdir()):
            info = zipfile.ZipInfo("spe-audit-explore/" + file.name, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            package.writestr(info, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)


if __name__ == "__main__":
    build()
