"""Unblind only a sealed run, score all input cases, or compare two repetitions."""
import argparse
from collections import Counter
from pathlib import Path
from protocol import DECISIONS, read, verify_run, write


def score(plan, run, gold_path, mapping_path):
    manifest, records = verify_run(plan, run)
    gold, mapping = read(gold_path), read(mapping_path)["map"]
    if set(mapping) != set(records) or set(gold) != set(mapping.values()) or len(set(mapping.values())) != len(mapping):
        raise ValueError("mapping or gold has missing, duplicate or extra IDs")
    matrix = Counter()
    for key, r in records.items():
        g = gold[mapping[key]]
        g = g.get("label", g.get("gold")) if isinstance(g, dict) else g
        if g == "INDETERMINATE":g = "REVIEW"
        if g not in DECISIONS:raise ValueError("unsupported reference label")
        pred = r["output"]["decision"] if r["status"]=="ok" else "ERROR"
        matrix[g,pred] += 1
    total=len(records)
    exact=sum(matrix[c,c] for c in DECISIONS)
    determinate=sum(n for (g,_),n in matrix.items() if g!="REVIEW")
    covered=sum(n for (g,p),n in matrix.items() if g!="REVIEW" and p in ("POST_ASSERTION","OTHER"))
    correct=sum(matrix[c,c] for c in ("POST_ASSERTION","OTHER"))
    return {"kind":manifest["kind"],"purpose":manifest["purpose"],"n":total,"agreement_all":exact,"agreement_rate":exact/total,
            "determinate":determinate,"covered_determinate":covered,"correct_covered_determinate":correct,
            "accuracy_covered_determinate":correct/covered if covered else None,
            "confusion":{g:{p:matrix[g,p] for p in [*DECISIONS,"ERROR"]} for g in DECISIONS}}


def compare(plan, first, second):
    _,a=verify_run(plan, first);_,b=verify_run(plan, second)
    d={"n":len(a),"both_valid":0,"identical_decision":0,"identical_structured_output":0,"identical_response_bytes":0}
    invalid=[]
    for k,x in a.items():
        y=b[k]
        p=first/"cases"/k/"response.raw";q=second/"cases"/k/"response.raw"
        d["identical_response_bytes"]+=int(p.exists() and q.exists() and p.read_bytes()==q.read_bytes())
        if x["status"]==y["status"]=="ok":
            d["both_valid"]+=1
            d["identical_decision"]+=x["output"]["decision"]==y["output"]["decision"]
            d["identical_structured_output"]+=x["output"]==y["output"]
        else:invalid.append(k)
    return dict(d,invalid_in_either=invalid)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);sp=p.add_subparsers(dest="mode",required=True)
    a=sp.add_parser("score");a.add_argument("--gold",required=True,type=Path);a.add_argument("--mapping",required=True,type=Path)
    b=sp.add_parser("compare");b.add_argument("--second",required=True,type=Path)
    for s in (a,b):
        for n in ("plan","run","out"):s.add_argument("--"+n,required=True,type=Path)
    args=p.parse_args()
    if args.out.exists():p.error("use a new score path")
    result=score(args.plan,args.run,args.gold,args.mapping) if args.mode=="score" else compare(args.plan,args.run,args.second)
    write(args.out,result)
