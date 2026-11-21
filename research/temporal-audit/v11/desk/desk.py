"""Serve a single blinded reviewer packet on this computer. Python 3.10+."""
import argparse
import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import sys
import threading
import time
import webbrowser
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "review"))
import review

HERE = Path(__file__).resolve().parent
IDLE_SECONDS = 15
DEFAULT = {"active_seconds": 0.0, "assisted_seconds": 0.0, "ever_assisted": False,
           "assisting": False, "note": "", "label": "", "spans": []}


def parse_spans(value, text):
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError("Invalid selections")
    result = []
    for span in value:
        if not isinstance(span, list) or len(span) != 2 or any(type(v) is not int for v in span):
            raise ValueError("Invalid selection offsets")
        start, end = span
        if not 0 <= start < end <= len(text) or (result and start < result[-1][1]):
            raise ValueError("Selections must be ordered, nonoverlapping character ranges")
        result.append([start,end])
    return result


def load_contexts(path, packet):
    if path is None:
        return {}
    doc = review.json_file(path)
    if not isinstance(doc, dict):
        raise ValueError("Contexts must be keyed by the blinded ticket")
    with review.db(packet) as conn:
        cards = {row["ticket"]: json.loads(row["card"]) for row in conn.execute("SELECT ticket,card FROM items")}
    checked = {}
    for ticket, cap in doc.items():
        if ticket not in cards:
            raise ValueError("Context references an unknown ticket")
        card = cards[ticket]
        raw = cap["request_utf8"]
        proof = hashlib.sha256(raw.encode("utf8")).hexdigest()
        if proof != cap["request_sha256"] or cap["output_sha256"] != review.digest(card["text"].encode()):
            raise ValueError("Context request or output digest mismatch")
        req = json.loads(raw)
        if req["cutoff"] != card["cutoff"] or req["prompt"] != card["prompt"] or not isinstance(req["sources"], list):
            raise ValueError("Request does not match the ticket's prompt or cutoff")
        sources = []
        for src in req["sources"]:
            # Only source content. Other capture fields can contain a method name or a reference label.
            sources.append({"date": str(src.get("date","")), "text": review.required_text(src["text"],"source text"),
                            "url": str(src.get("url",""))})
        checked[ticket] = {"kind": "observed", "sources": sources, "request_digest": proof}
    return checked


@contextmanager
def packet_lock(packet):
    """One live desk per packet. The OS releases its lock after process exit."""
    with open(str(packet) + ".desk-lock", "a+b") as stream:
        if sys.platform == "win32":
            import msvcrt
            if stream.seek(0,2) == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


class Desk:
    def __init__(self, packet, contexts=None, authored=False, clock=time.monotonic):
        self.packet = Path(packet)
        self.contexts = contexts or {}
        self.authored = authored
        self.clock = clock
        self.guard = threading.Lock()
        self.running = None
        self.last = None
        self.tab = None
        with review.db(packet, "rw") as conn:
            conn.execute("SELECT ticket,card FROM items LIMIT 1")
            conn.execute("CREATE TABLE IF NOT EXISTS desk_drafts (ticket TEXT PRIMARY KEY REFERENCES items(ticket), data TEXT NOT NULL)")

    def stop(self):
        if self.running is not None:
            self.act("pause", {"ticket":self.running}, self.tab)

    def act(self, action, body, tab):
        with self.guard:
            return self._act(action, body, tab)

    def _act(self, action, body, tab):
        with review.db(self.packet, "rw") as conn:
            assigned = conn.execute("SELECT count(*) FROM items").fetchone()[0]
            done = conn.execute("SELECT count(*) FROM answers").fetchone()[0]
            closed = review.sealed(conn)
            state = {"assigned": assigned, "done": done, "sealed": closed}
            if closed or done == assigned:
                if action not in ("state","seal"):
                    raise ValueError("Packet complete or sealed")
                receipt = review.answer_digest(conn)
                if closed and receipt != conn.execute("SELECT answers_sha256 FROM state").fetchone()[0]:
                    raise ValueError("Sealed answers changed")
                if action == "seal" and not closed:
                    conn.execute("UPDATE state SET sealed=1, answers_sha256=?", (receipt,))
                    state["sealed"] = True
                state["receipt"] = receipt if state["sealed"] else None
                return state
            if action == "seal":
                raise ValueError("Complete the pending cases first")
            ticket, card = review.next_card(conn)
            if action != "state" and body.get("ticket") != ticket:
                raise ValueError("This view is out of date. Reload.")
            saved = conn.execute("SELECT data FROM desk_drafts WHERE ticket=?", (ticket,)).fetchone()
            draft = json.loads(saved[0]) if saved else DEFAULT.copy()
            now = self.clock()
            running = self.running == ticket
            if running and self.tab != tab:
                if now - self.last <= IDLE_SECONDS:
                    raise ValueError("Another tab is active. Pause or close it before resuming here.")
            elapsed = now-self.last if running else 0
            expired = running and elapsed > IDLE_SECONDS
            if running:
                delta = min(max(elapsed,0), IDLE_SECONDS)
                draft["active_seconds"] += delta
                if draft["assisting"]:
                    draft["assisted_seconds"] += delta
            active = running and not expired
            if action == "start":
                active = True
            if action in ("draft","pause","assist","finish"):
                if not running and action != "pause":
                    raise ValueError("Start or resume review before editing")
                if "note" in body:
                    note, label = body["note"], body.get("label","")
                    if not isinstance(note,str) or len(note)>8000 or label not in ("",*review.LABELS):
                        raise ValueError("Invalid draft")
                    draft.update(note=note,label=label,spans=parse_spans(body.get("spans",[]),card["text"]))
            if action == "assist":
                if expired:
                    raise ValueError("Resume the timer first")
                draft["ever_assisted"] = True
                draft["assisting"] = True
            if action == "pause":
                active = False
            if action == "finish":
                if expired:
                    raise ValueError("Resume the timer first")
                annotation = {"review_mode":"assisted" if draft["ever_assisted"] else "blind",
                              "active_assisted_seconds":round(draft["assisted_seconds"],3),
                              "selections":[{"start":a,"end":b,"quote":card["text"][a:b]} for a,b in draft["spans"]]}
                clean = review.checked_answer(draft["label"],draft["note"],draft["active_seconds"],"clock")
                label, note, seconds, timing = clean
                evidence = note + "\n[SPE desk] " + review.canonical(annotation)
                conn.execute("INSERT INTO answers VALUES (?,?,?,?,?)",(ticket,label,evidence,seconds,timing))
                conn.execute("DELETE FROM desk_drafts WHERE ticket=?", (ticket,))
                self.running = self.last = self.tab = None
                return {"saved": True}
            conn.execute("INSERT INTO desk_drafts VALUES (?,?) ON CONFLICT(ticket) DO UPDATE SET data=excluded.data",
                         (ticket, review.canonical(draft)))
            self.running, self.last, self.tab = (ticket, now, tab) if active else (None,None,None)
            state.update(ticket=ticket, active=active, seconds=draft["active_seconds"],
                         assisted=draft["ever_assisted"])
            if active:
                state.update(card=card,draft=draft,context=self.contexts.get(ticket,{"kind":"authored" if self.authored else "unknown"}))
            return state


def summary(packet):
    result = {"blind":0,"assisted":0,"other_interface":0,"assisted_seconds":0.0}
    with review.db(packet) as conn:
        for row in conn.execute("SELECT evidence FROM answers"):
            note = row[0].rsplit("\n[SPE desk] ",1)
            if len(note) == 1:
                result["other_interface"] += 1
            else:
                try:
                    annotation = json.loads(note[1])
                    mode = annotation["review_mode"]
                    seconds = annotation["active_assisted_seconds"]
                    if mode not in ("blind","assisted") or type(seconds) not in (int,float):
                        raise ValueError("Unrecognised desk note")
                except (ValueError,KeyError,TypeError):
                    result["other_interface"] += 1
                    continue
                result[mode] += 1
                result["assisted_seconds"] += seconds
    return result


class LocalHandler(BaseHTTPRequestHandler):
    server_version = "SPE-Desk"
    def log_message(self, *args):
        pass

    def send_data(self, code, data, mime):
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Referrer-Policy","no-referrer")
        self.send_header("Content-Security-Policy", self.server.csp)
        self.end_headers()
        self.wfile.write(data)

    def host_ok(self):
        return self.headers.get_all("Host",[]) == [self.server.host]

    def do_GET(self):
        if not self.host_ok() or self.path != "/":
            self.send_data(404,b"Not found","text/plain")
            return
        self.send_data(200,self.server.page,"text/html; charset=utf-8")

    def do_POST(self):
        def answer(status,obj):
            self.send_data(status,json.dumps(obj,ensure_ascii=False).encode(),"application/json; charset=utf-8")
        if (not self.host_ok() or self.headers.get_all("Origin",[]) != ["http://"+self.server.host]
                or not hmac.compare_digest(self.headers.get("X-Desk-Token",""),self.server.token)):
            answer(403,{"error":"Local session authorization required"}); return
        tab = self.headers.get("X-Desk-Tab","")
        action = self.path.removeprefix("/api/")
        if self.path != "/api/"+action or action not in ("state","start","draft","pause","assist","finish","seal"):
            answer(404,{"error":"Unknown action"}); return
        try:
            length = int(self.headers.get("Content-Length","-1"))
            if not 0 <= length <= 65536 or self.headers.get_content_type() != "application/json" or not re.fullmatch(r"[a-zA-Z0-9-]{16,80}",tab):
                raise ValueError("Invalid local request")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body,dict):
                raise ValueError("Expected an object")
            answer(200,self.server.desk.act(action,body,tab))
        except (ValueError, KeyError, sqlite3.Error, TypeError) as e:
            answer(400,{"error":str(e)})


def build_server(desk, port=0):
    server = ThreadingHTTPServer(("127.0.0.1",port),LocalHandler)
    template = (HERE / "desk.html").read_text(encoding="utf-8")
    style = (HERE / "desk.css").read_text(encoding="utf-8")
    script = (HERE / "desk.js").read_text(encoding="utf-8")
    template = template.replace('<link rel="stylesheet" href="/desk.css">', "<style>"+style+"</style>")
    template = template.replace('<script src="/desk.js" defer></script>', "")
    server.page = template.replace("</body>", "<script>"+script+"</script></body>").encode()
    def csp_hash(content):
        return base64.b64encode(hashlib.sha256(content.encode()).digest()).decode()
    server.csp = ("default-src 'none'; script-src 'sha256-"+csp_hash(script)+"'; "
                  "style-src 'sha256-"+csp_hash(style)+"'; connect-src 'self'; img-src 'none'; "
                  "base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
    server.host = f"127.0.0.1:{server.server_port}"
    server.token, server.desk = secrets.token_urlsafe(32), desk
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet",type=Path)
    ctx = parser.add_mutually_exclusive_group()
    ctx.add_argument("--authored-holdout",action="store_true",help="Known authored responses without a generation request")
    ctx.add_argument("--contexts",type=Path,help="Verified local request capsules keyed by blinded ticket")
    parser.add_argument("--summary",action="store_true",help="Count completed cases by assistance exposure")
    parser.add_argument("--no-browser",action="store_true")
    args = parser.parse_args()
    if not args.packet.is_file():
        parser.error("Select an existing A.sqlite or B.sqlite reviewer packet")
    try:
        if args.summary:
            print(json.dumps(summary(args.packet),indent=2)); return
        contexts = load_contexts(args.contexts,args.packet)
        with packet_lock(args.packet):
            desk = Desk(args.packet,contexts,args.authored_holdout)
            with build_server(desk) as server:
                url = f"http://{server.host}/#{server.token}"
                print("SPE Audit · Abre este enlace privado en este equipo / Open this private link on this computer:\n"
                      +url+"\nCtrl+C para cerrar / to close.",flush=True)
                if not args.no_browser:
                    webbrowser.open(url)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
                finally:
                    desk.stop()
    except (OSError,sqlite3.Error,ValueError,KeyError,TypeError) as e:
        parser.exit(2, f"desk: {e}\n")


if __name__=="__main__":
    main()
