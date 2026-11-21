"""Check the released lab evidence offline. Does not run a new model or enrol participants."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
INVENTORY = ROOT / "SHA256.json"

def run_py(*args):
    subprocess.run([sys.executable, "-B", *map(str, args)], cwd=ROOT, check=True)

def verify(expected):
    if expected and hashlib.sha256(INVENTORY.read_bytes()).hexdigest() != expected:
        raise ValueError("The manifest does not match the expected independent digest")
    files = json.loads(INVENTORY.read_text(encoding="utf8"))
    for name, digest in files.items():
        path = ROOT / name
        if not path.resolve().is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("Changed artifact: " + name)
    print(f"{len(files)} files verified against the follow-up manifest.", flush=True)
    run_py("generalization/analyze.py")
    run_py("external/replay.py", "--check")
    run_py("open-pilot/test_pilot.py")
    run_py("-m", "unittest", "discover", "-s", "reference_reader", "-p", "test_protocol.py")
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        run_py("escalation/replay.py", "--out", out)
        for name in ("routes.csv", "summary.json"):
            if (out / name).read_bytes() != (ROOT / "escalation" / name).read_bytes():
                raise ValueError("Case-routing output changed: " + name)
    archives = sorted((ROOT / "reference_reader").glob("*.zip"))
    if len(archives) != 2:
        raise ValueError("Expected the two language-model evidence archives")
    for archive in archives:
        run_py("reference_reader/evidence.py", "verify", archive)
    node = shutil.which("node")
    if node is None:
        print("Node.js is unavailable. The interactive desk check was skipped.")
    else:
        subprocess.run([node, "review-desk/verify.cjs"], cwd=ROOT, check=True)
    print("Offline checks complete. Raw model response bytes were independently rescored against the archived plan.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-sha256",help="Optional trusted digest of the entire lab manifest")
    verify(parser.parse_args().manifest_sha256)
