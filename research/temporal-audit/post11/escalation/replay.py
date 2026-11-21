"""Recount research routing policies on archived signals. No human decisions are simulated."""
import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
V11 = HERE.parents[1] / "v11"
sys.path.insert(0, str(V11 / "reader"))
from worksheet import build

ALERT, OTHER, ABSTAIN = "POST_ASSERTION", "OTHER", "REVIEW"
PENDING = "PENDING_REVIEW"
POLICIES = ("rule", "cascade", "agreement", "individual_dispute")

def disposition(policy, rule, reading):
    """Gold labels, case identity and domain are unavailable to this function."""
    if policy not in POLICIES or any(x not in (ALERT, OTHER, ABSTAIN) for x in (rule, reading)):
        raise ValueError("Unknown policy or signal")
    if policy == "individual_dispute":
        return PENDING
    if policy == "agreement":
        return rule if rule == reading and rule != ABSTAIN else PENDING
    signal = reading if policy == "cascade" and rule == ABSTAIN else rule
    return PENDING if signal == ABSTAIN else signal

def run(out):
    out.mkdir(parents=True, exist_ok=True)
    _, ids = build()
    answers = json.loads((V11 / "reader/answers.json").read_text(encoding="utf8"))
    reading = {ids[r["key"]]: r["decision"] for r in answers}
    with (V11 / "results/predictions.jsonl").open(encoding="utf8") as stream:
        signals = {r["id"]: r["choices"]["proposition"] for line in stream
                   if (r := json.loads(line))["group"] == "new_challenge"}
    if len(signals) != 48 or set(signals) != set(reading) or len(reading) != len(answers):
        raise ValueError("Incomplete or duplicate case signals")
    rows = []
    for case in sorted(signals):
        r, s = signals[case], reading[case]
        rows.append(dict(case=case, rule_signal=r, archived_reader_signal=s,
                         **{p: disposition(p, r, s) for p in POLICIES}))
    # The disposition table has already been computed when references are opened for scoring.
    references = json.loads((V11 / "holdout/labels.json").read_text(encoding="utf8"))
    if set(references) != set(signals):
        raise ValueError("Incomplete scoring references")
    with (out / "routes.csv").open("w", encoding="utf8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    summary = {}
    for p in POLICIES:
        counts = Counter((references[r["case"]], r[p]) for r in rows)
        pending = sum(r[p] == PENDING for r in rows)
        ambiguous_closed = counts["INDETERMINATE", OTHER] + counts["INDETERMINATE", ALERT]
        summary[p] = dict(n=len(rows), pending=pending, automatic=len(rows)-pending,
                          true_alert=counts[ALERT, ALERT], false_alert=counts[OTHER, ALERT],
                          false_clear=counts[ALERT, OTHER], ambiguous_auto=ambiguous_closed,
                          ambiguous_pending=counts["INDETERMINATE", PENDING],
                          administrative_loss=12*counts[OTHER, ALERT]+25*counts[ALERT, OTHER]
                          +14*ambiguous_closed+pending)
    (out / "summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf8")
    return summary

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HERE)
    print(json.dumps(run(parser.parse_args().out),indent=2))
