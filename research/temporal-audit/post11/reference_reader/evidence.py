"""Package exact run bytes once, or verify an evidence package without a model."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
from mask import canonical
from protocol import read, verify_run
from score import compare, score


def checked(directory):
    plan=directory/"plan"
    counts=[]
    for name in ("run1","run2"):
        _, records=verify_run(plan,directory/name)
        counts.append(sum(r["status"]=="ok" for r in records.values()))
    diffs=compare(plan,directory/"run1",directory/"run2")
    if diffs!=read(directory/"agreement.json"):
        raise ValueError("replication table differs from the receipts")
    if (directory/"gold.json").exists():
        for name in ("run1","run2"):
            sc=score(plan,directory/name,directory/"gold.json",directory/"mapping.json")
            if sc!=read(directory/(name+"-score.json")):
                raise ValueError("score differs from the recorded answers")
    return {"valid_run1":counts[0],"valid_run2":counts[1],"total":diffs["n"],
            "identical_decisions":diffs["identical_decision"]}


def package(directory, target):
    checked(directory)
    paths=sorted(p for p in directory.rglob("*") if p.is_file())
    data={p.relative_to(directory).as_posix():p.read_bytes() for p in paths}
    if "inventory.json" in data:raise ValueError("reserved path")
    inv={name:hashlib.sha256(value).hexdigest() for name,value in data.items()}
    data["inventory.json"]=canonical(inv)
    with ZipFile(target,"x",compression=ZIP_DEFLATED,compresslevel=9) as z:
        for name in sorted(data):
            info=ZipInfo(name,date_time=(1980,1,1,0,0,0));info.compress_type=ZIP_DEFLATED;info.external_attr=0o100644<<16;info.create_system=3
            z.writestr(info,data[name],compresslevel=9)
    return hashlib.sha256(target.read_bytes()).hexdigest()


def verify_zip(archive):
    with ZipFile(archive) as z, tempfile.TemporaryDirectory() as td:
        names=z.namelist()
        if len(names)!=len(set(names)) or "inventory.json" not in names:
            raise ValueError("duplicate or missing inventory")
        inventory=json.loads(z.read("inventory.json"))
        if set(names)!=(set(inventory)|{"inventory.json"}):raise ValueError("inventory mismatch")
        d=Path(td)
        for name,expected in inventory.items():
            path=Path(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name:raise ValueError("invalid archive path")
            raw=z.read(name)
            if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError("changed member: "+name)
            f=d/path;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(raw)
        return checked(d)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest="op",required=True)
    write=s.add_parser("pack");write.add_argument("directory",type=Path);write.add_argument("archive",type=Path)
    check=s.add_parser("verify");check.add_argument("archive",type=Path)
    a=p.parse_args()
    print(json.dumps(package(a.directory,a.archive) if a.op=="pack" else verify_zip(a.archive),indent=2))
