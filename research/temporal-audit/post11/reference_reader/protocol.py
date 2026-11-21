"""Seal masked inputs and execute a bounded reader on a loopback-only llama.cpp server."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import time
from mask import canonical, check

ROOT = Path(__file__).resolve().parent
PROMPT = ROOT / "prompt_v1.txt"
CODE = ("prompt_v1.txt", "mask.py", "protocol.py", "score.py")
DECISIONS = ["POST_ASSERTION", "OTHER", "REVIEW"]
CONFIG = {"temperature": 0.0, "seed": 20261121, "n_predict": 384, "cache_prompt": False,
          "stream": False, "stop": ["<|im_end|>", "<|im_start|>"], "n_probs": 0}
FLAGS = ["--ctx-size", "4096", "--threads", "1", "--threads-batch", "1", "--parallel", "1", "--n-gpu-layers", "0"]
FIXTURE_ID = "TEST-TRANSPORT-ONLY/fixed-OTHER/v1"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hashfile(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def stamp():
    return datetime.now(timezone.utc).isoformat()


def write(path, obj):
    path.write_bytes(canonical(obj))


def quotes(answer):
    parts = re.findall(r'[^.!?\n]+[.!?]+|[^.!?\n]+$', answer)
    options = [answer.strip(), *(p.strip() for p in parts)]
    return list(dict.fromkeys(q for q in options if q and len(q) <= 420))[:8]


def request(row, prompt):
    options = quotes(row["answer"])
    if not options:
        raise ValueError("no eligible complete quote up to 420 characters")
    data = {"E1": {"event": row["event"], "event_date": row["event_date"], "cutoff": row["cutoff"], "source": row["source"]},
            "E2": row["question"], "E3": row["answer"], "quote_options": options}
    body = json.dumps(data, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e")
    full = "<|im_start|>system\n" + prompt.rstrip("\n") + "<|im_end|>\n<|im_start|>user\n" + body + "<|im_end|>\n<|im_start|>assistant\n"
    # An enum limits exact quotes. Keeping a single string for evidence avoids
    # unsupported array combinations in older llama.cpp JSON-schema converters.
    schema = {"type":"object","properties":{"decision":{"type":"string","enum":DECISIONS},
               "answer_quote":{"type":"string","enum":options},
               "evidence_ids":{"type":"string","enum":["E1 E3","E1 E2 E3"]}},
              "required":["decision","answer_quote","evidence_ids"],"additionalProperties":False}
    return {**CONFIG, "prompt": full, "json_schema": schema}


def resolve_output(raw, row):
    envelope = json.loads(raw)
    if envelope.get("truncated") or envelope.get("stopped_limit") or envelope.get("stop_type") == "limit":
        raise ValueError("backend truncated the prompt or reached the output limit")
    settings = envelope.get("generation_settings", {})
    for field in ("temperature", "seed"):
        if field in settings and settings[field] != CONFIG[field]:
            raise ValueError("backend sampling mismatch: " + field)
    output = json.loads(envelope["content"])
    if not isinstance(output,dict) or set(output) != {"decision", "answer_quote", "evidence_ids"}:
        raise ValueError("wrong response shape")
    if output["decision"] not in DECISIONS or output["answer_quote"] not in quotes(row["answer"]):
        raise ValueError("unknown decision or quote outside E3")
    if output["evidence_ids"] not in ("E1 E3", "E1 E2 E3"):
        raise ValueError("evidence outside allowlist")
    q = output["answer_quote"]
    start = row["answer"].index(q)
    return dict(output, answer_span=[start,start+len(q)])


def runtime(engine, model, model_id):
    if not engine or not model or not model_id:
        raise ValueError("real runs require binary, GGUF and exact model identifier")
    engine, model = engine.resolve(), model.resolve()
    with model.open("rb") as handle:
        if handle.read(4) != b"GGUF":
            raise ValueError("model is not GGUF")
    cmd = subprocess.run([str(engine), "--version"], capture_output=True, timeout=20)
    if cmd.returncode:
        raise ValueError("version command failed")
    version = (cmd.stdout+cmd.stderr).decode(errors="replace").replace(str(engine.parent), "<engine-dir>")
    libs = {f.name:hashfile(f) for f in sorted(engine.parent.glob("*.so*")) if f.is_file()}
    return {"kind":"llama.cpp","model_id":model_id,"model_bytes":model.stat().st_size,"model_sha256":hashfile(model),
            "executable_sha256":hashfile(engine),"engine_version":version,"adjacent_shared_libraries_sha256":libs}


def verify_plan(plan):
    sealed = read(plan/"plan.json")
    if (plan/"plan.sha256").read_text().strip() != sha(canonical(sealed)):
        raise ValueError("plan digest mismatch")
    for f, expected in sealed["files"].items():
        if hashfile(plan/f) != expected:
            raise ValueError("plan file digest mismatch: "+f)
    if sealed["implementation_sha256"] != {n:hashfile(ROOT/n) for n in CODE}:
        raise ValueError("implementation differs from the sealed plan")
    return sealed, check(read(plan/"masked.json"))


def freeze(masked, output, backend, engine=None, model=None, model_id=None, purpose="prospective"):
    rows = check(read(masked))
    identity = runtime(engine,model,model_id) if backend == "llama.cpp" else {"kind":"fixture","model_id":FIXTURE_ID}
    if purpose not in ("prospective","retrospective-replay","engineering-fixture"):
        raise ValueError("unknown study purpose")
    if (identity["kind"]=="fixture") != (purpose=="engineering-fixture"):
        raise ValueError("a fixture must be identified as an engineering fixture")
    output.mkdir(parents=True,exist_ok=False)
    (output/"masked.json").write_bytes(canonical(rows))
    shutil.copyfile(PROMPT,output/"prompt_v1.txt")
    sealed={"protocol_version":"bounded-reader-1","purpose":purpose,"sealed_utc":stamp(),"cases":len(rows),
            "prompt_id":"semantic-stance-chatml-v1","sampling":CONFIG,"server_flags":FLAGS,"identity":identity,
            "implementation_sha256":{n:hashfile(ROOT/n) for n in CODE},
            "files":{n:hashfile(output/n) for n in ("masked.json","prompt_v1.txt")}}
    write(output/"plan.json",sealed)
    (output/"plan.sha256").write_text(sha(canonical(sealed))+"\n")
    return sealed


def exchange(port, method, path, body=None):
    con = http.client.HTTPConnection("127.0.0.1", port, timeout=90)
    try:
        con.request(method,path,body=body,headers={"Content-Type":"application/json"})
        resp = con.getresponse()
        return resp.status, resp.read()
    finally:
        con.close()


@contextmanager
def local_server(engine, model, logfile):
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        port=s.getsockname()[1]
    args = [str(engine.resolve()),"--model",str(model.resolve()),"--host","127.0.0.1","--port",str(port),*FLAGS]
    with logfile.open("wb") as log:
        proc=subprocess.Popen(args,stdout=log,stderr=log,env={**os.environ,"CUDA_VISIBLE_DEVICES":"","OMP_NUM_THREADS":"1"})
        try:
            for _ in range(300):
                if proc.poll() is not None:
                    raise RuntimeError("local engine exited before readiness")
                try:
                    if exchange(port,"GET","/health")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(.1)
            else:raise TimeoutError("local engine failed readiness check")
            yield lambda payload:exchange(port,"POST","/completion",payload)
        finally:
            proc.terminate()
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill();proc.wait()


def fixture(payload):
    req=json.loads(payload)
    q=req["json_schema"]["properties"]["answer_quote"]["enum"][0]
    out={"decision":"OTHER","answer_quote":q,"evidence_ids":"E1 E3"}
    return 200,canonical({"content":json.dumps(out,ensure_ascii=False),"fixture":True})


def execute(plan, output, *, engine=None, model=None, test_transport=None):
    sealed, rows=verify_plan(plan)
    identity=sealed["identity"]
    if identity["kind"]=="llama.cpp":
        if test_transport is not None:raise ValueError("cannot replace a real backend")
        if runtime(engine,model,identity["model_id"]) != identity:raise ValueError("runtime identity changed")
    output.mkdir(parents=True,exist_ok=False)
    (output/"cases").mkdir()
    prompt=(plan/"prompt_v1.txt").read_text(encoding="utf-8")
    manifest={"protocol_version":sealed["protocol_version"],"plan_sha256":hashfile(plan/"plan.json"),
              "kind":identity["kind"],"purpose":sealed["purpose"],"started_utc":stamp(),"python":platform.python_version(),
              "machine":platform.machine(),"platform":platform.platform(),"entries":[]}
    def record(call):
        for row in rows:
            key=row["key"]
            folder=output/"cases"/key
            folder.mkdir()
            state={"key":key,"started_utc":stamp(),"status":"error","http_status":None}
            try:
                payload=canonical(request(row,prompt))
                (folder/"request.json").write_bytes(payload)
                code,raw=call(payload)
                (folder/"response.raw").write_bytes(raw)
                state["http_status"]=code
                if code!=200:raise ValueError("HTTP "+str(code))
                if len(raw)>2_000_000:raise ValueError("oversized response body")
                state["output"]=resolve_output(raw,row)
                state["status"]="ok"
            except Exception as error:
                state["error"]=type(error).__name__+": "+str(error)
            state["finished_utc"]=stamp()
            write(folder/"record.json",state)
            manifest["entries"].append({"key":key,"files":{f.name:hashfile(f) for f in sorted(folder.iterdir())}})
    startup_error=None
    try:
        if identity["kind"] == "fixture":record(test_transport or fixture)
        else:
            with tempfile.TemporaryDirectory() as temp:
                with local_server(engine,model,Path(temp)/"engine.log") as call:record(call)
    except Exception as error:
        startup_error=type(error).__name__+": "+str(error)
    manifest["startup_or_run_error"]=startup_error
    manifest["finished_utc"]=stamp()
    write(output/"manifest.json",manifest)
    (output/"manifest.sha256").write_text(hashfile(output/"manifest.json")+"\n")
    return manifest


def verify_run(plan, run):
    sealed, rows=verify_plan(plan)
    m=read(run/"manifest.json")
    if hashfile(run/"manifest.json") != (run/"manifest.sha256").read_text().strip() or m["plan_sha256"]!=hashfile(plan/"plan.json"):
        raise ValueError("run or plan hash mismatch")
    entries=m["entries"]
    keys=[e["key"] for e in entries]
    if len(keys)!=len(set(keys)) or not set(keys).issubset({r["key"] for r in rows}):raise ValueError("unexpected case keys")
    results={}
    for row in rows:
        entry=next((e for e in entries if e["key"]==row["key"]),None)
        if entry is None:
            if not m["startup_or_run_error"]:raise ValueError("unrecorded input")
            results[row["key"]]={"status":"error","error":"engine or run failed before this case"};continue
        folder=run/"cases"/entry["key"]
        files={f.name:hashfile(f) for f in sorted(folder.iterdir())}
        if files!=entry["files"]:raise ValueError("changed case bytes")
        rec=read(folder/"record.json")
        if rec["key"]!=row["key"]:raise ValueError("wrong record key")
        if (folder/"request.json").exists():
            expected=canonical(request(row,(plan/"prompt_v1.txt").read_text(encoding="utf-8")))
            if (folder/"request.json").read_bytes()!=expected:raise ValueError("request changed")
        if rec["status"]=="ok" and (rec["http_status"]!=200 or resolve_output((folder/"response.raw").read_bytes(),row)!=rec["output"]):
            raise ValueError("output changed")
        results[row["key"]]=rec
    return m,results


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    subs=p.add_subparsers(dest="action",required=True)
    a=subs.add_parser("freeze")
    a.add_argument("--masked",type=Path,required=True)
    a.add_argument("--backend",choices=["llama.cpp","fixture"],required=True)
    a.add_argument("--model-id")
    a.add_argument("--purpose",required=True,choices=["prospective","retrospective-replay","engineering-fixture"])
    b=subs.add_parser("run");b.add_argument("--plan",type=Path,required=True)
    for sub in (a,b):
        sub.add_argument("--output",type=Path,required=True);sub.add_argument("--engine",type=Path);sub.add_argument("--model",type=Path)
    c=subs.add_parser("verify");c.add_argument("--plan",type=Path,required=True);c.add_argument("--run",type=Path,required=True)
    args=p.parse_args()
    if args.action=="freeze":freeze(args.masked,args.output,args.backend,args.engine,args.model,args.model_id,args.purpose)
    elif args.action=="run":
        m=execute(args.plan,args.output,engine=args.engine,model=args.model)
        print("recorded",len(m["entries"]),"case attempts")
        if m["startup_or_run_error"]:raise SystemExit(m["startup_or_run_error"])
    else:print("verified",len(verify_run(args.plan,args.run)[1]),"records")
