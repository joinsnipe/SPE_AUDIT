"""Create separate, unfilled 16-case reviewer kits and a private coordination folder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
V11 = HERE / "v11" if (HERE / "v11").is_dir() else HERE.parents[1] / "v11"
DESK = ("desk.py", "desk.html", "desk.css", "desk.js")

def sha(data):
    return hashlib.sha256(data).hexdigest()

def sample(cases):
    """Select without labels, predictions or reader outputs. Stable across Python versions."""
    def rank(c):
        return sha(("SPE-pilot16-ed1|" + c["id"]).encode())
    ranked = sorted(cases, key=rank)
    groups = {(c["event_id"], c["language"]) for c in ranked}
    if len(ranked) != 48 or len(groups) != 12:
        raise ValueError("Expected the frozen bilingual six-event challenge")
    selected = [next(c for c in ranked if (c["event_id"], c["language"]) == g) for g in sorted(groups)]
    for language in ("en", "es"):
        selected += [c for c in ranked if c["language"] == language and c not in selected][:2]
    return sorted(selected, key=rank)

def add_role_zip(role, packet, out):
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(packet, role + ".sqlite")
        z.write(HERE / "REVIEWER.md", "LEEME_README.md")
        for f in DESK:
            z.write(V11 / "desk" / f, "desk/" + f)
        z.write(V11 / "review/review.py", "review/review.py")
        z.write(HERE / "LICENSE", "LICENSE")
        command = f'python3 -B desk/desk.py {role}.sqlite --authored-holdout'
        info = zipfile.ZipInfo("ABRIR_macOS.command")
        info.external_attr = 0o100755 << 16
        z.writestr(info, '#!/bin/sh\ncd "$(dirname "$0")" || exit 1\n'+command+'\n')
        z.writestr("ABRIR_Windows.cmd",'@echo off\r\ncd /d "%~dp0"\r\n'
                   +f'py -3 -B desk/desk.py {role}.sqlite --authored-holdout\r\nif errorlevel 1 pause\r\n')

def create(destination):
    if destination.exists():
        raise FileExistsError(f"Please choose a new directory: {destination}")
    freeze = json.loads((HERE / "inputs.sha256.json").read_text(encoding="utf8"))
    for name, expected in freeze.items():
        if sha((V11 / name).read_bytes()) != expected:
            raise ValueError(f"Input does not match frozen study: {name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp:
        work = Path(temp)
        deliverables = work / "complete"
        deliverables.mkdir()
        selected = sample(json.loads((V11 / "holdout/cases.json").read_text(encoding="utf8")))
        casesfile = work / "cases.json"
        casesfile.write_text(json.dumps(selected,ensure_ascii=False,indent=2)+"\n", encoding="utf8")
        events = V11 / "holdout/events.json"
        freeze_file = deliverables / "pilot_freeze.json"
        declaration = {"study": "Open feasibility pilot / fixed 16, first edition",
                       "sha256":{"holdout/cases.json":sha(casesfile.read_bytes()),
                                 "holdout/events.json":sha(events.read_bytes()),
                                 "protocol":sha((HERE / "README.md").read_bytes()),
                                 "published_inputs":sha((HERE / "inputs.sha256.json").read_bytes())}}
        freeze_file.write_text(json.dumps(declaration,indent=2)+"\n",encoding="utf8")
        batch = deliverables / "COORDINATION"
        subprocess.run([sys.executable,"-B",str(V11/"review/review.py"),"prepare",
                        "--mode","human_collection","--out",str(batch),
                        "--freeze",str(freeze_file),"--freeze-sha256",sha(freeze_file.read_bytes()),
                        "--cases",str(casesfile),"--events",str(events)],check=True)
        for role in ("A","B"):
            packet = batch / (role+".sqlite")
            add_role_zip(role, packet, deliverables / ("REVISOR_"+role+".zip"))
            packet.unlink()   # The coordinator receives completed files here only on return.
        shutil.copyfile(V11/"review/review.py",deliverables/"review.py")
        shutil.copyfile(HERE/"COORDINATOR.md",deliverables/"LEEME_COORDINACION.md")
        if destination.exists():
            raise FileExistsError(f"Please choose a new directory: {destination}")
        os.rename(deliverables, destination)
    print("Ready / Listo:",destination,"— 0/16 per reviewer")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out",type=Path,default=Path("SPE_PILOT_16"))
    create(p.parse_args().out.resolve())
