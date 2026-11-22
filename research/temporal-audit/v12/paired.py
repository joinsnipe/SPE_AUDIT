"""Freeze and run the two-arm retrospective replay. No reference labels are loaded here."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile

HERE = Path(__file__).resolve().parent
STUDY = HERE.parent / "study"
READER = HERE.parent / "post11" / "reference_reader"
sys.path.insert(0, str(READER))
from protocol import FLAGS, canonical, hashfile, local_server, runtime
from download_reference import MODEL_ID

DECISIONS = ["POST_ASSERTION", "OTHER", "REVIEW"]
MODEL_HASH = "8030f04528538d47bda434f6f0bdf3952c40a58123e4d5e755332f23731a8684"
ENGINE_HASH = "36a0e300a5f827798fc4ad253ab35e6ceea2b82e4e060ef9fd73397fcf083b50"
CAPTURE_HASH = "174ca466891bbd35e8c5b208b612d74dddf4984b9e7a31537bf7e02d41447e20"
ARMS = ("eligible_only", "plus_event_date")
SEED = 20261122


def load_cases():
    events = {e["id"]: e["event_date"] for e in json.loads((STUDY / "data/events.json").read_bytes())}
    captures = STUDY / "results/capsules.jsonl"
    if hashfile(captures) != CAPTURE_HASH:
        raise ValueError("unexpected capture collection")
    records = [json.loads(line) for line in captures.read_bytes().splitlines()]
    cases = []
    for split, name in (("constructed", "cases"), ("challenge", "challenge")):
        for case in json.loads((STUDY / f"data/{name}.json").read_bytes()):
            record = records[len(cases)]
            request = json.loads(record["request_utf8"])
            if request["prompt"] != case["prompt"] or request["cutoff"] != case["cutoff"] or record["output"] != case["output"]:
                raise ValueError("case does not match its archived request")
            cards = [{"date": c["date"], "text": c["text"]} for c in request["sources"]]
            if any(c["date"] > request["cutoff"] for c in cards):
                raise ValueError("ineligible card in capture")
            packet = dict(cutoff=request["cutoff"], question=request["prompt"], answer=record["output"], cards=cards)
            cases.append((case["id"], split, packet, events[case["event"]]))
    if len(cases) != 112 or len({x[0] for x in cases}) != 112:
        raise ValueError("unexpected case count")
    return cases


def requests():
    instructions = (HERE / "prompt.txt").read_text(encoding="utf-8").strip()
    schema = {"type": "object", "properties": {"decision": {"type": "string", "enum": DECISIONS}},
              "required": ["decision"], "additionalProperties": False}
    for i, (case_id, split, packet, date) in enumerate(load_cases()):
        for arm in ARMS if i % 2 == 0 else reversed(ARMS):
            view = dict(packet)
            if arm == "plus_event_date":
                view["retrospective_event_date"] = date
            data = canonical(view).decode().strip()
            prompt = "<|im_start|>system\n" + instructions + "<|im_end|>\n<|im_start|>user\n" + data + "<|im_end|>\n<|im_start|>assistant\n"
            payload = dict(prompt=prompt, json_schema=schema, temperature=0.0, seed=SEED, n_predict=64,
                           cache_prompt=False, stream=False, stop=["<|im_end|>", "<|im_start|>"])
            yield case_id, split, arm, canonical(payload)


def plan():
    files = ["paired.py", "prompt.txt", "PRIOR_PROTOCOL.md", "../post11/reference_reader/protocol.py",
             "../post11/reference_reader/mask.py", "../post11/reference_reader/download_reference.py"]
    return canonical(dict(files={p: hashfile(HERE / p) for p in files}, model=MODEL_ID, model_sha256=MODEL_HASH,
                          engine_sha256=ENGINE_HASH, flags=FLAGS, capture_sha256=CAPTURE_HASH, seed=SEED,
                          requests=[dict(id=k, split=s, arm=a, sha256=hashlib.sha256(b).hexdigest())
                                    for k, s, a, b in requests()]))


def decision(raw):
    data = json.loads(raw)
    if data.get("truncated") or data.get("stopped_limit") or data.get("stop_type") == "limit":
        raise ValueError("truncated generation")
    settings = data["generation_settings"]
    if settings["temperature"] != 0.0 or settings["seed"] != SEED:
        raise ValueError("unexpected settings")
    parsed = json.loads(data["content"])
    if set(parsed) != {"decision"} or parsed["decision"] not in DECISIONS:
        raise ValueError("invalid response")
    return parsed["decision"]


def run(engine, model, output):
    frozen = (HERE / "plan.json").read_bytes()
    if plan() != frozen:
        raise ValueError("research plan differs from freeze")
    identity = runtime(engine, model, MODEL_ID)
    if identity["model_sha256"] != MODEL_HASH or identity["executable_sha256"] != ENGINE_HASH:
        raise ValueError("model or binary differs from freeze")
    with tempfile.TemporaryDirectory() as tmp, local_server(engine, model, Path(tmp) / "server.log") as call:
        with ZipFile(output, "x", compression=ZIP_DEFLATED) as evidence:
            evidence.writestr("runtime.json", canonical(identity))
            evidence.writestr("plan.sha256", hashlib.sha256(frozen).hexdigest() + "\n")
            for case_id, split, arm, body in requests():
                item = {"id": case_id, "split": split, "arm": arm, "request_sha256": hashlib.sha256(body).hexdigest()}
                try:
                    status, raw = call(body)
                    item.update(http_status=status, response_b64=base64.b64encode(raw).decode())
                    if status != 200:
                        raise ValueError(f"HTTP {status}")
                    item["decision"] = decision(raw)
                except (OSError, ValueError, KeyError) as exc:
                    item.update(decision="ERROR", error=str(exc))
                evidence.writestr(f"{case_id}/{arm}.json", canonical(item))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    commands.add_parser("freeze")
    infer = commands.add_parser("run")
    for key in ("engine", "model", "output"):
        infer.add_argument(key, type=Path)
    args = parser.parse_args()
    if args.mode == "freeze":
        with (HERE / "plan.json").open("xb") as handle:
            handle.write(plan())
    else:
        run(args.engine, args.model, args.output)
