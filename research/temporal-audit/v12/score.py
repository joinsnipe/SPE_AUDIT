"""Verify the frozen inputs and raw model outputs, then join to the published labels."""
import argparse
import base64
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path
from zipfile import ZipFile
from paired import ARMS, DECISIONS, ENGINE_HASH, HERE, MODEL_HASH, MODEL_ID, STUDY, decision, load_cases, plan, requests

METHODS = ("year_rule", "dated_matcher", *ARMS)


def csv_bytes(rows, fields=None):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields or list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


def read_completions(path):
    frozen = (HERE / "plan.json").read_bytes()
    if plan() != frozen:
        raise ValueError("the current request generator differs from the frozen plan")
    expected = {"runtime.json", "plan.sha256"}
    outputs = {}
    with ZipFile(path) as archive:
        if archive.read("plan.sha256").decode().strip() != hashlib.sha256(frozen).hexdigest():
            raise ValueError("wrong research plan in receipt archive")
        identity = json.loads(archive.read("runtime.json"))
        if (identity["executable_sha256"], identity["model_sha256"], identity["model_id"]) != (ENGINE_HASH, MODEL_HASH, MODEL_ID):
            raise ValueError("wrong runtime identity")
        for case_id, split, arm, request in requests():
            name = f"{case_id}/{arm}.json"
            expected.add(name)
            item = json.loads(archive.read(name))
            if (item["id"], item["split"], item["arm"], item["request_sha256"]) != (case_id, split, arm, hashlib.sha256(request).hexdigest()):
                raise ValueError(f"wrong request binding: {name}")
            if item.get("response_b64"):
                raw = base64.b64decode(item["response_b64"], validate=True)
                if item["http_status"] == 200:
                    if json.loads(raw).get("prompt") != json.loads(request)["prompt"]:
                        raise ValueError(f"runtime echoed a different prompt: {name}")
                    try:
                        raw_decision = decision(raw)
                    except (ValueError, KeyError):
                        raw_decision = "ERROR"
                else:
                    raw_decision = "ERROR"
            else:
                raw_decision = "ERROR"
            if raw_decision != item["decision"]:
                raise ValueError(f"recorded decision disagrees with raw response: {name}")
            outputs[case_id, arm] = raw_decision
        if set(archive.namelist()) != expected or len(archive.namelist()) != len(expected):
            raise ValueError("unexpected, duplicate or missing zip members")
    return outputs


def summarize(rows, method):
    counts = Counter((row["reference"], row[method]) for row in rows)
    pos, other, review = DECISIONS
    true_alert = counts[pos, pos]
    false_alert = counts[other, pos]
    alerts = true_alert + false_alert
    referred = counts[pos, review] + counts[other, review]
    errors = counts[pos, "ERROR"] + counts[other, "ERROR"]
    return dict(rows=len(rows), positives=sum(row["reference"] == pos for row in rows),
                controls=sum(row["reference"] == other for row in rows), true_alerts=true_alert,
                false_alerts=false_alert, alerts=alerts, referred=referred, transport_or_validation_errors=errors,
                human_queue=referred + errors, decided=len(rows) - referred - errors,
                correct_decided=true_alert + counts[other, other])


def outputs(archive):
    model = read_completions(archive)
    original = (STUDY / "results/predictions.csv").read_bytes()
    if hashlib.sha256(original).hexdigest() != "5c6189acb2da3f2cc85dc3626e7761bdc38dbb798f86e809229d2cf995a10cf0":
        raise ValueError("original reference or historical method decisions changed")
    old = list(csv.DictReader(original.decode("utf-8").splitlines()))
    cases = load_cases()
    if len(old) != len(cases):
        raise ValueError("wrong number of archived predictions")
    rows = []
    for prior, (key, split, packet, _) in zip(old, cases):
        if (prior["id"], prior["split"], prior["cutoff"]) != (key, split, packet["cutoff"]):
            raise ValueError("misaligned evaluation rows")
        rows.append(dict(id=key, split=split, event=prior["event"], cutoff=packet["cutoff"], reference=prior["label"],
                         year_rule=prior["year_rule"], dated_matcher=prior["dated_matcher"],
                         **{arm: model[key, arm] for arm in ARMS}))
    groups = defaultdict(list)
    for row in rows:
        groups[row["split"], "all"].append(row)
        groups[row["split"], row["event"]].append(row)
    metrics = [dict(split=split, event=event, method=method, **summarize(group, method))
               for (split, event), group in groups.items() for method in METHODS]
    changes = Counter((r["split"], r["reference"], r[ARMS[0]], r[ARMS[1]]) for r in rows)
    transitions = [dict(split=s, reference=ref, eligible_only=old, plus_event_date=new, rows=n)
                   for (s, ref, old, new), n in sorted(changes.items())]
    return {"paired_decisions.csv": csv_bytes(rows), "metrics.csv": csv_bytes(metrics),
            "transitions.csv": csv_bytes(transitions)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--archive", type=Path, default=HERE / "receipts.zip")
    ap.add_argument("--out", type=Path, help="Write a fresh set of tables. Default checks distributed tables.")
    args = ap.parse_args()
    for name, content in outputs(args.archive).items():
        if args.out:
            args.out.mkdir(parents=True, exist_ok=True)
            (args.out / name).write_bytes(content)
        elif (HERE / name).read_bytes() != content:
            raise ValueError("regenerated table differs: " + name)
    print("Verified 224 planned readouts and 112 same-row comparisons.")
