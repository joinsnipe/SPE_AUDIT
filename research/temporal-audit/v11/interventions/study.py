"""Matched local intervention study and private prospective registration, using Python 3.10+."""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "study"))
from capture import run_capture, verify_capture
from local_endpoint import GENERIC, NONE, PREFIX, TOKEN

PUBLIC_SEED = "SPE Audit | local controlled intervention | 2026-11-21 | v1"
PROMPT = "Return the ticket value recorded in the fictional archive card, if available."
CUTOFF = "2026-01-10"
MODES = ("reader", "generic", "side")
ARMS = ("present", "absent", "decoy")
ROLES = ("target", "decoy", "future")
N = 40
SCHEMA = "spe-local-marker-study/1"
RESULTS = ("captures.jsonl", "pairs.json", "metrics.json")


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pretty(value):
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)+"\n").encode("utf-8")


def derived(seed, label):
    return hmac.digest(seed.encode(), label.encode(), "sha256")


def token_for(pair, role):
    return "SPE-" + derived(PUBLIC_SEED, f"ticket/{pair}/{role}")[:16].hex()


def public_design():
    return [{"pair": p, **{r:token_for(p,r) for r in ROLES}} for p in range(1,N+1)]


def schedule():
    cells = [(row, mode, arm) for row in range(1,N+1) for mode in MODES for arm in ARMS]
    return sorted(cells, key=lambda c:derived(PUBLIC_SEED,"order/{}/{}/{}".format(*c)))


def cards(pair, arm):
    def card(key, day, text):
        return {"id":key, "date":day, "text":text, "url":"https://example.invalid/fiction/"+key}
    records = [card("archive-note","2026-01-01","An invented archive for this local exercise."),
               card("future-ticket","2026-01-11",PREFIX+pair["future"])]
    if arm == "present":
        records.append(card("ticket-original","2026-01-08",PREFIX+pair["target"]))
    elif arm == "decoy":
        records.append(card("ticket-alternative","2026-01-08",PREFIX+pair["decoy"]))
    elif arm != "absent":
        raise ValueError("unknown condition")
    return records


def process_call(raw, mode, side):
    env = os.environ.copy()
    env.pop("SPE_FIXTURE_SIDE_VALUE",None)
    if mode == "side":
        env["SPE_FIXTURE_SIDE_VALUE"] = side
    completed = subprocess.run([sys.executable,"-I","-B",str(HERE/"local_endpoint.py"),mode],
                               input=raw, capture_output=True, env=env, check=True, timeout=15)
    return completed.stdout.decode("utf-8")


def trial(pair, mode, arm):
    def send(raw):
        return process_call(raw, mode, pair["target"] if mode == "side" else None)
    return {"pair":pair["pair"],"mode":mode,"condition":arm,
            "capture":run_capture(CUTOFF,PROMPT,cards(pair,arm),send)}


def outcomes(rows, design):
    pairs = {p["pair"]:p for p in design}
    by_cell = {}
    counts = {(m,a):Counter() for m in MODES for a in ARMS}
    for row in rows:
        key = (row["pair"],row["mode"],row["condition"])
        if key in by_cell: raise ValueError("duplicate condition for a pair")
        pair,mode,arm = key
        if pair not in pairs or mode not in MODES or arm not in ARMS:
            raise ValueError("unknown study cell")
        record = row["capture"]
        if not verify_capture(record):
            raise ValueError("invalid local capture")
        req = json.loads(record["request_utf8"])
        source = pairs[pair]
        expected = sorted((c for c in cards(source,arm) if c["date"]<=CUTOFF), key=lambda c:c["id"])
        if req["prompt"]!=PROMPT or req["cutoff"]!=CUTOFF or req["sources"]!=expected:
            raise ValueError("captured request disagrees with assigned condition")
        output = record["output"]
        match = next((r for r in ROLES if output==source[r]), None)
        if match is None:
            match = "generic" if output==GENERIC else "unavailable" if output==NONE else "other"
        by_cell[key] = match
        counts[(mode,arm)][match] += 1
    if set(by_cell) != {(p,m,a) for p in pairs for m in MODES for a in ARMS}:
        raise ValueError("matched cells are incomplete")
    conditions = []
    differences = []
    for mode in MODES:
        for arm in ARMS:
            tally = counts[mode,arm]
            conditions.append({"mode":mode,"condition":arm,"n":sum(tally.values()),
                               **{k:tally[k] for k in (*ROLES,"generic","unavailable","other")}})
        for control in ("absent","decoy"):
            discord = Counter((by_cell[p,mode,"present"]=="target",by_cell[p,mode,control]=="target")
                             for p in pairs)
            differences.append({"mode":mode,"contrast":"present minus "+control,"pairs":len(pairs),
                                "present_only":discord[True,False],"control_only":discord[False,True],
                                "both":discord[True,True],"neither":discord[False,False],
                                "target_rate_difference":(discord[True,False]-discord[False,True])/len(pairs)})
    return {"schema":SCHEMA,"seed":PUBLIC_SEED,"pairs":len(pairs),"local_calls":len(rows),
            "prompt":PROMPT,"cutoff":CUTOFF,"target_match":"entire output equals assigned case-sensitive value",
            "conditions":conditions,"paired_differences":differences}


def run(out):
    design = public_design()
    rows = [trial(design[p-1],m,a) for p,m,a in schedule()]
    metrics = outcomes(rows,design)
    out.mkdir(parents=True,exist_ok=True)
    (out/"pairs.json").write_bytes(pretty(design))
    (out/"captures.jsonl").write_bytes(b"".join(json_bytes(r)+b"\n" for r in rows))
    (out/"metrics.json").write_bytes(pretty(metrics))
    return metrics


def verify(out):
    design=json.loads((out/"pairs.json").read_bytes())
    if design!=public_design():
        raise ValueError("public design disagrees with the published seed")
    rows=[json.loads(x) for x in (out/"captures.jsonl").read_bytes().splitlines()]
    if [(r["pair"],r["mode"],r["condition"]) for r in rows]!=schedule():
        raise ValueError("execution order disagrees with the assignment")
    summary=outcomes(rows,design)
    if (out/"metrics.json").read_bytes()!=pretty(summary):
        raise ValueError("metrics disagree with the paired decisions")
    return summary


def commit_row(row):
    return sha(b"spe-private-marker-plan-v1\x00"+json_bytes(row))


def commitments(plan):
    if type(plan) is not list or not 1<=len(plan)<=10000:
        raise ValueError("expect 1 to 10,000 private synthetic pairs")
    all_tickets=set(); commitments=[]
    for i,row in enumerate(plan,1):
        if type(row) is not dict or set(row)!={"pair","salt","order",*ROLES} or type(row["pair"]) is not int or row["pair"]!=i:
            raise ValueError("unexpected private record or order")
        if not isinstance(row["salt"],str) or not re.fullmatch(r"[0-9a-f]{64}",row["salt"]):
            raise ValueError("expected a 256-bit commitment salt")
        if type(row["order"]) is not list or sorted(row["order"])!=sorted(ARMS):
            raise ValueError("expected each of the three arms once")
        for role in ROLES:
            v=row[role]
            if not isinstance(v,str) or not TOKEN.fullmatch(v) or v in all_tickets:
                raise ValueError("invalid or duplicated private ticket")
            all_tickets.add(v)
        commitments.append({"pair":i,"sha256":commit_row(row)})
    return {"schema":"spe-private-marker-plan-v1","pairs":len(plan),"prompt":PROMPT,"cutoff":CUTOFF,
            "roles":list(ROLES),"conditions":list(ARMS),"commitments":commitments}


def register(folder, n):
    if not 1<=n<=10000: raise ValueError("pair count outside 1 to 10,000")
    rng = secrets.SystemRandom()
    plan = [{"pair":i, "salt":secrets.token_hex(32), "order":rng.sample(ARMS,len(ARMS)), **{r:"SPE-"+secrets.token_hex(16) for r in ROLES}}
            for i in range(1,n+1)]
    public=commitments(plan)
    folder.mkdir(mode=0o700,parents=False,exist_ok=False)
    private=folder/"private.json"
    with os.fdopen(os.open(private,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"wb") as f:
        f.write(pretty(plan))
    (folder/"commitments.json").write_bytes(pretty(public))
    return sha(pretty(public))


def check_plan(folder):
    private=json.loads((folder/"private.json").read_bytes())
    public=(folder/"commitments.json").read_bytes()
    if pretty(commitments(private))!=public: raise ValueError("private plan fails the public commitment")
    return sha(public)


def main():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest="command",required=True)
    for key in ("run","verify"):
        cmd=sub.add_parser(key); cmd.add_argument("--out",type=Path,default=HERE/"results")
    reg=sub.add_parser("register");reg.add_argument("new_private_directory",type=Path);reg.add_argument("--pairs",type=int,default=N)
    check=sub.add_parser("check-plan");check.add_argument("private_directory",type=Path)
    args=p.parse_args()
    try:
        if args.command in ("run","verify"):
            metrics=(run if args.command=="run" else verify)(args.out)
            print(f"{metrics['local_calls']} local calls, {metrics['pairs']} complete matched cases")
        elif args.command=="register": print(register(args.new_private_directory,args.pairs))
        else: print(check_plan(args.private_directory))
    except (ValueError,KeyError,IndexError,TypeError,OSError,subprocess.SubprocessError) as exc:
        p.exit(1,f"Study failed: {exc}\n")


if __name__=="__main__":
    main()
