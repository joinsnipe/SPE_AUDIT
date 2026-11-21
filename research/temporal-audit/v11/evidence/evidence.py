"""SPE Audit evidence supplement 1.1. Standard library, Python 3.10+."""

import argparse
import hashlib
import hmac
import json
import re
from datetime import date, datetime, time, timezone
from pathlib import Path

FIELDS = ("event", "publication", "effective", "ingestion", "capture")
INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])")
HEX = re.compile(r"[0-9a-f]{64}")
TREE = "spe-ordered-merkle-sha256-v1"
PREFIX = TREE.encode("ascii") + b"\x00"


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path):
    return json.loads(Path(path).read_bytes().decode("utf-8"), object_pairs_hook=strict_pairs)


def digest_hex(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("expected lowercase SHA-256 hexadecimal")
    return value


def instant(value):
    """Parse a known numeric offset, with microsecond resolution, into UTC."""
    if not isinstance(value, str) or not INSTANT.fullmatch(value) or value.endswith("-00:00"):
        raise ValueError("expected YYYY-MM-DDTHH:MM:SS[.ffffff]Z or a known numeric offset")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise ValueError("invalid calendar instant or UTC conversion outside year range") from exc


def span(value):
    """Supported representations are an instant or {earliest, latest}, inclusive."""
    if isinstance(value, str):
        point = instant(value)
        return point, point
    if type(value) is not dict or set(value) != {"earliest", "latest"}:
        raise ValueError("expected a timestamp or an explicit closed interval")
    lo, hi = instant(value["earliest"]), instant(value["latest"])
    if lo > hi:
        raise ValueError("reversed interval")
    return lo, hi


def civil_interval(day, offset, hour=None):
    """Expand a local civil day or hour at a known fixed offset into a closed interval."""
    if not isinstance(day, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", day):
        raise ValueError("expected YYYY-MM-DD")
    if hour is not None and (type(hour) is not int or not 0 <= hour <= 23):
        raise ValueError("expected an hour from 0 to 23")
    if not isinstance(offset,str) or not re.fullmatch(r"Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9]",offset):
        raise ValueError("expected a known offset")
    local_day = date.fromisoformat(day)
    lo = datetime.combine(local_day, time(hour or 0))
    hi = datetime.combine(local_day, time(23 if hour is None else hour,59,59,999999))
    value = {"earliest":lo.isoformat(timespec="seconds")+offset,
             "latest":hi.isoformat(timespec="microseconds")+offset}
    span(value)
    return value


def decide(times, cutoff, required):
    """An AND over explicitly required fields; a known failure dominates missing values."""
    if type(times) is not dict or not set(times) <= set(FIELDS):
        raise ValueError("unknown temporal field or malformed record")
    if type(required) not in (tuple,list) or not required or any(k not in FIELDS for k in required):
        raise ValueError("specify at least one known required temporal field")
    if len(set(required)) != len(required):
        raise ValueError("duplicate field in admission policy")
    cut_lo, cut_hi = span(cutoff)
    values = {k:None if v is None else span(v) for k,v in times.items()}
    fields = {}
    for field in required:
        bounds = values.get(field)
        if bounds is None:
            fields[field] = "indeterminate"
        elif bounds[1] <= cut_lo:
            fields[field] = "eligible"
        elif bounds[0] > cut_hi:
            fields[field] = "ineligible"
        else:
            fields[field] = "indeterminate"
    statuses = fields.values()
    status = "ineligible" if "ineligible" in statuses else "indeterminate" if "indeterminate" in statuses else "eligible"
    return {"decision":status, "fields":fields}


def uint64(value):
    if type(value) is not int or not 0 <= value < (1 << 64):
        raise ValueError("expected an unsigned 64-bit integer")
    return value.to_bytes(8, "big")


def hashed(domain, *parts):
    return hashlib.sha256(PREFIX+domain+b"".join(parts)).digest()


def leaf_hash(index, leaf):
    if not isinstance(leaf, bytes):
        raise ValueError("expected exact leaf bytes")
    return hashed(b"\x00",uint64(index),uint64(len(leaf)),leaf)


def node_levels(leaves):
    if not isinstance(leaves,(tuple,list)):
        raise ValueError("expected an ordered sequence of leaves")
    current = [leaf_hash(i, item) for i,item in enumerate(leaves)]
    levels = [current]
    while len(current) > 1:
        following = []
        for i in range(0,len(current),2):
            following.append(hashed(b"\x01",current[i],current[i+1]) if i+1 < len(current)
                             else hashed(b"\x02",current[i]))
        levels.append(following)
        current = following
    return levels


def wrapped(size, nodes):
    return hashed(b"\x03",uint64(size),nodes[0] if nodes else b"").hex()


def merkle_root(leaves):
    levels = node_levels(leaves)
    return wrapped(len(levels[0]),levels[-1])


def inclusion_proof(leaves, index):
    levels = node_levels(leaves)
    size = len(levels[0])
    if type(index) is not int or not 0 <= index < size:
        raise ValueError("leaf index outside the tree")
    location, siblings = index, []
    for nodes in levels[:-1]:
        neighbor = location ^ 1
        if neighbor < len(nodes):
            siblings.append(nodes[neighbor].hex())
        location //= 2
    return {"scheme":TREE,"size":size,"index":index,"siblings":siblings}


def verify_inclusion(leaf, proof, expected_root):
    """Raise on malformed or mismatched evidence. Success requires an external expected root."""
    digest_hex(expected_root)
    if type(proof) is not dict or set(proof) != {"scheme","size","index","siblings"} or proof["scheme"] != TREE:
        raise ValueError("unsupported proof structure or scheme")
    size, index, siblings = proof["size"], proof["index"], proof["siblings"]
    uint64(size); uint64(index)
    if index >= size or type(siblings) is not list or len(siblings)>64:
        raise ValueError("invalid proof bounds")
    path = [bytes.fromhex(digest_hex(h)) for h in siblings]
    position, width, consumed = index, size, 0
    node = leaf_hash(index, leaf)
    while width > 1:
        if (position ^ 1) < width:
            if consumed >= len(path):
                raise ValueError("incomplete authentication path")
            neighbor = path[consumed]; consumed += 1
            node = hashed(b"\x01",neighbor,node) if position & 1 else hashed(b"\x01",node,neighbor)
        else:
            node = hashed(b"\x02",node)
        width, position = (width+1)//2, position//2
    if consumed != len(path) or not hmac.compare_digest(wrapped(size,[node]),expected_root):
        raise ValueError("authentication path or pinned root mismatch")
    return True


def verify_snapshot(manifest_path, expected_manifest_sha256=None):
    """Verify a retained local file; an external manifest digest can also bind the metadata."""
    path = Path(manifest_path)
    raw = path.read_bytes()
    if expected_manifest_sha256 is not None:
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),digest_hex(expected_manifest_sha256)):
            raise ValueError("manifest digest mismatch")
    entry = json.loads(raw.decode("utf-8"),object_pairs_hook=strict_pairs)
    fields = {"schema","file","bytes","sha256","source_url","version","git_blob_sha1","times","interpretation"}
    if type(entry) is not dict or set(entry) != fields or entry["schema"] != "spe-snapshot-git-v1":
        raise ValueError("unknown snapshot manifest schema")
    for k in ("file","source_url","version","git_blob_sha1","interpretation"):
        if not isinstance(entry[k],str) or not entry[k].strip():
            raise ValueError(f"missing snapshot field {k}")
    if not entry["source_url"].startswith("https://") or not re.fullmatch(r"[0-9a-f]{40}",entry["version"]):
        raise ValueError("expected an HTTPS source and a Git revision identifier")
    if not re.fullmatch(r"[0-9a-f]{40}",entry["git_blob_sha1"]):
        raise ValueError("malformed Git blob ID")
    if type(entry["times"]) is not dict or set(entry["times"]) != set(FIELDS) or entry["times"]["capture"] is None:
        raise ValueError("expected five temporal fields, with an explicit capture time")
    for bound in entry["times"].values():
        if bound is not None: span(bound)
    if type(entry["bytes"]) is not int or entry["bytes"] < 0:
        raise ValueError("expected a nonnegative byte count")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*",entry["file"]):
        raise ValueError("expected a single local filename")
    data = (path.parent/entry["file"]).read_bytes()
    git_blob = hashlib.sha1(b"blob "+str(len(data)).encode("ascii")+b"\x00"+data).hexdigest()
    if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest()!=digest_hex(entry["sha256"]) or git_blob!=entry["git_blob_sha1"]:
        raise ValueError("snapshot bytes disagree with manifest")
    return entry


def main():
    ap=argparse.ArgumentParser(description=__doc__); cmd=ap.add_subparsers(dest="command",required=True)
    snap=cmd.add_parser("snapshot");snap.add_argument("manifest",type=Path);snap.add_argument("--expected-manifest-sha256")
    proof=cmd.add_parser("inclusion");proof.add_argument("leaf",type=Path);proof.add_argument("proof",type=Path);proof.add_argument("--root",required=True)
    dates=cmd.add_parser("decide"); dates.add_argument("manifest",type=Path)
    dates.add_argument("--cutoff",required=True); dates.add_argument("--fields",nargs="+",required=True,choices=FIELDS)
    args=ap.parse_args()
    try:
        if args.command=="snapshot": verify_snapshot(args.manifest,args.expected_manifest_sha256)
        elif args.command=="inclusion": verify_inclusion(args.leaf.read_bytes(),load_json(args.proof),args.root)
        else:
            entry=verify_snapshot(args.manifest)
            print(json.dumps(decide(entry["times"],args.cutoff,args.fields),indent=2))
            return
    except (ValueError,OSError) as exc: ap.exit(1,f"Verification failed: {exc}\n")
    print("Verified.")


if __name__=="__main__":
    main()
