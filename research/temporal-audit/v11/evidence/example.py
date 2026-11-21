"""Generate or verify the intraday SPE Audit teaching dossier. Raw data and outputs are public fixtures."""

import argparse
import hashlib
import hmac
import json
from pathlib import Path

from evidence import (
    civil_interval, decide, digest_hex, inclusion_proof, load_json,
    merkle_root, verify_inclusion, verify_snapshot,
)

HERE = Path(__file__).resolve().parent
POLICY = ["publication","effective"]
PROMPT = "What status does the latest eligible bulletin declare?"
SENDER = "local-bulletin-reader-v1"
SNAPSHOT_SHA = "7f86bf76d137b34bd3cf1c906f9c6d913c4e17ee8732b4ad1a5b630e67cddf18"


def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def same(a,b):
    return hmac.compare_digest(canonical(a),canonical(b))


def fixtures():
    """Synthetic two-version bulletin, procedure and an unresolved publication hour."""
    early="2026-06-01T09:00:00+02:00"; revised="2026-06-01T12:25:00+02:00"
    day=civil_interval("2026-06-01","+02:00")
    rows=[]
    for key,version,published,text in (
        ("bulletin",1,early,"Status: scheduled."),
        ("bulletin",2,revised,"Status: approved."),
        ("procedure",1,early,"The bulletin states the current status."),
        ("undated-hour",1,day,"A bulletin update is expected."),
    ):
        rows.append({"id":key,"version":version,"text":text,"text_sha256":checksum(text.encode()),
                     "times":{"event":None,"publication":published,"effective":early,
                              "ingestion":None,"capture":None}})
    return rows


def prepare(rows,cutoff):
    ids=set(); decisions={}; admitted=[]
    for row in sorted(rows,key=lambda x:(x["id"],x["version"])):
        if set(row)!={"id","version","text","text_sha256","times"} or not isinstance(row["id"],str) or not row["id"] or type(row["version"]) is not int or row["version"]<1:
            raise ValueError("invalid versioned card")
        key=(row["id"],row["version"])
        if key in ids: raise ValueError("duplicate source version")
        ids.add(key)
        if checksum(row["text"].encode("utf-8"))!=digest_hex(row["text_sha256"]):
            raise ValueError("snapshot text hash mismatch")
        decision=decide(row["times"],cutoff,POLICY)
        decisions[json.dumps(key,separators=(",",":"))]=decision
        if decision["decision"]=="eligible": admitted.append(row)
    if not admitted: raise ValueError("this demonstration requires at least one admitted source")
    leaves=[canonical(row) for row in admitted]
    request=canonical({"schema":"spe-intraday-request-v1","prompt":PROMPT,"required_fields":POLICY,
                       "cutoff":cutoff,"selected_root":merkle_root(leaves),"sources":admitted})
    return decisions,leaves,request


def local_sender(raw):
    request=json.loads(raw.decode("utf-8"))
    bulletin=[r for r in request["sources"] if r["id"]=="bulletin"]
    return max(bulletin,key=lambda r:r["version"])["text"] if bulletin else "Unknown."


def run(rows,cutoff,sender=local_sender):
    decisions,leaves,request=prepare(rows,cutoff)
    result=sender(request)
    if not isinstance(result,str): raise ValueError("sender must return UTF-8 text")
    receipt={"decisions":decisions,"cutoff":cutoff,"request_utf8":request.decode(),
             "request_sha256":checksum(request),"output":result,"output_sha256":checksum(result.encode()),
             "sender":SENDER,"selected_root":merkle_root(leaves),
             "disclosed_leaf_utf8":leaves[0].decode(),"proof":inclusion_proof(leaves,0)}
    return receipt


def create():
    entry=verify_snapshot(HERE/"snapshots"/"manifest.json",SNAPSHOT_SHA)
    rows=fixtures()
    base=run(rows,"2026-06-01T12:00:00+02:00")
    later=run(rows,"2026-06-01T13:00:00+02:00")
    changed=base["disclosed_leaf_utf8"].encode()+b" "
    try:
        verify_inclusion(changed,base["proof"],base["selected_root"])
    except ValueError:
        rejected=True
    else:
        rejected=False
    return {"schema":"spe-intraday-dossier-v1","source_pool":rows,"before":base,"after":later,
            "mutated_disclosure_rejected":rejected,"pinned_snapshot_sha256":entry["sha256"]}


def verify(dossier,expected_sha256):
    if not hmac.compare_digest(checksum(canonical(dossier)),digest_hex(expected_sha256)):
        raise ValueError("expected dossier digest mismatch")
    if dossier["schema"]!="spe-intraday-dossier-v1": raise ValueError("unexpected dossier version")
    entry=verify_snapshot(HERE/"snapshots"/"manifest.json",SNAPSHOT_SHA)
    if not hmac.compare_digest(dossier["pinned_snapshot_sha256"],entry["sha256"]):
        raise ValueError("documentary fixture hash mismatch")
    for field in ("before","after"):
        item=dossier[field]
        statuses,leaves,request=prepare(dossier["source_pool"],item["cutoff"])
        if not same(item["decisions"],statuses) or request!=item["request_utf8"].encode():
            raise ValueError("recorded admission or exact submitted request disagrees")
        if checksum(request)!=item["request_sha256"] or merkle_root(leaves)!=item["selected_root"]:
            raise ValueError("request checksum or selected root mismatch")
        if item["sender"]!=SENDER or checksum(item["output"].encode())!=item["output_sha256"]:
            raise ValueError("sender identity label or recorded output digest disagrees")
        if item["output"]!=local_sender(request):
            raise ValueError("local deterministic replay disagrees with recorded output")
        leaf=item["disclosed_leaf_utf8"].encode()
        verify_inclusion(leaf,item["proof"],item["selected_root"])
        if leaf!=leaves[item["proof"]["index"]]: raise ValueError("disclosed row disagrees with the request")
    early,late=dossier["before"],dossier["after"]
    if early["output"]!="Status: scheduled." or late["output"]!="Status: approved.":
        raise ValueError("expected demonstration counterfactual did not occur")
    try:
        verify_inclusion(early["disclosed_leaf_utf8"].encode()+b" ",early["proof"],early["selected_root"])
    except ValueError:
        if dossier["mutated_disclosure_rejected"] is True:
            return True
    raise ValueError("mutated disclosure was not rejected as reported")


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group()
    group.add_argument("--out",type=Path,help="write the demonstration JSON");group.add_argument("--verify",type=Path)
    ap.add_argument("--expected-sha256",help="pinned SHA-256 of canonical dossier JSON")
    args=ap.parse_args()
    try:
        if args.verify:
            if not args.expected_sha256: ap.error("--verify requires --expected-sha256")
            verify(load_json(args.verify),args.expected_sha256)
            print("Verified both local requests, selected roots, outputs, snapshot and counterexample.")
        else:
            if args.expected_sha256: ap.error("--expected-sha256 is used with --verify")
            data=create(); digest=checksum(canonical(data)); verify(data,digest)
            if args.out:
                args.out.write_bytes((json.dumps(data,indent=2,ensure_ascii=False)+"\n").encode())
                print(digest)
            else:
                print(json.dumps({"before":data["before"]["output"],"after":data["after"]["output"],
                                  "before_selected_root":data["before"]["selected_root"],
                                  "after_selected_root":data["after"]["selected_root"],
                                  "mutation_rejected":data["mutated_disclosure_rejected"],
                                  "canonical_dossier_sha256":digest},indent=2))
    except (ValueError,TypeError,KeyError,IndexError,AttributeError,OSError) as exc: ap.exit(1,f"Verification failed: {exc}\n")


if __name__=="__main__":
    main()
