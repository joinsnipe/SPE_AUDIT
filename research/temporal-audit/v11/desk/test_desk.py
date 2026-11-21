"""Temporary, simulated observations only. No human reads or timing measurements."""
import http.client
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

import desk


class DeskTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.packet=self.root/"A.sqlite"
        self.card=dict(cutoff="2000-01-01",language="en",prompt="SIMULATED?",text="🕐 It landed in 2001.",
                       event="SIMULATED",event_date="2001-01-02",source_url="https://example.invalid/source")
        desk.review.make_packet(self.packet,[(1,"ticket-a",desk.review.canonical(self.card)),
                                             (2,"ticket-b",desk.review.canonical(self.card))])
        self.now=0
        self.d=desk.Desk(self.packet,authored=True,clock=lambda:self.now)

    def test_blind_spans_pause_restart_assistance_separate(self):
        tab="simulated-tab-001"
        state=self.d.act("state",{},tab)
        self.assertNotIn("card",state)
        first=self.d.act("start",dict(ticket="ticket-a"),tab)
        self.assertEqual(first["context"]["kind"],"authored")
        self.assertFalse(first["assisted"])
        self.assertEqual(first["draft"]["spans"],[])
        self.now=4
        state=self.d.act("pause",dict(ticket="ticket-a",note="SIMULATED blind",label="other",spans=[[0,1]]),tab)
        self.assertFalse(state["active"])
        self.now=1000
        rest=desk.Desk(self.packet,clock=lambda:self.now)
        state=rest.act("start",dict(ticket="ticket-a"),tab)
        self.assertEqual(state["context"]["kind"],"unknown")
        self.assertEqual(state["draft"]["spans"],[[0,1]])
        self.assertEqual(state["seconds"],4)
        self.now=1005
        rest.act("finish",dict(ticket="ticket-a"),tab)
        rest.act("start",dict(ticket="ticket-b"),tab)
        self.now=1009
        rest.act("assist",dict(ticket="ticket-b"),tab)
        self.now=1016
        rest.act("finish",dict(ticket="ticket-b",note="SIMULATED assisted",label="indeterminate",spans=[]),tab)
        sealed=rest.act("seal",{},tab)
        self.assertTrue(sealed["sealed"])
        self.assertEqual(desk.summary(self.packet),dict(blind=1,assisted=1,other_interface=0,assisted_seconds=7))
        with desk.review.db(self.packet) as con:
            rows=list(con.execute("select * from answers order by ticket"))
            self.assertEqual([r["seconds"] for r in rows],[9,11])
            self.assertEqual(json.loads(rows[0]["evidence"].split("[SPE desk] ")[1])["selections"][0]["quote"],"🕐")
            self.assertEqual(desk.review.answer_digest(con),sealed["receipt"])

    def test_idle_tab_and_invalid_span(self):
        self.d.act("start",dict(ticket="ticket-a"),"first")
        self.now=3
        with self.assertRaisesRegex(ValueError,"tab"):
            self.d.act("state",{},"second")
        with self.assertRaisesRegex(ValueError,"ranges"):
            self.d.act("draft",dict(ticket="ticket-a",note="",spans=[[8,14],[2,9]]),"first")
        self.now=150
        s=self.d.act("state",{},"second")
        self.assertFalse(s["active"])
        self.assertEqual(s["seconds"],15)
        self.assertNotIn("card",s)
        self.assertNotIn("draft",s)

    def test_observed_empty_unknown_and_mismatched_capsule(self):
        path=self.root/"contexts.json"
        def cap(sources):
            raw=desk.review.canonical(dict(prompt=self.card["prompt"],cutoff=self.card["cutoff"],sources=sources))
            return dict(request_utf8=raw,request_sha256=desk.review.digest(raw.encode()),
                        output_sha256=desk.review.digest(self.card["text"].encode()))
        record=cap([dict(text="SIMULATED card on wire",date="1999-12-22",url="https://example.invalid/archive",label="DO NOT LEAK")])
        path.write_text(json.dumps({"ticket-a":record,"ticket-b":cap([])}))
        ctx=desk.load_contexts(path,self.packet)
        self.assertNotIn("DO NOT LEAK",str(ctx))
        self.assertEqual(ctx["ticket-a"]["sources"][0]["text"],"SIMULATED card on wire")
        self.assertEqual(ctx["ticket-b"]["sources"],[])
        record["output_sha256"]="x"
        path.write_text(json.dumps({"ticket-a":record}))
        with self.assertRaisesRegex(ValueError,"digest"):
            desk.load_contexts(path,self.packet)

    @unittest.skipUnless(shutil.which("node"), "Node is optional for the UI harness")
    def test_ui_controls_over_http(self):
        runtime=desk.Desk(self.packet,authored=True)
        with desk.build_server(runtime) as srv:
            th=threading.Thread(target=srv.serve_forever,daemon=True)
            th.start()
            try:
                result=subprocess.run(["node",str(desk.HERE/"ui_smoke.cjs"),"http://"+srv.host,srv.token],
                                      capture_output=True,text=True,timeout=20)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn("PASS",result.stdout)
                self.assertEqual(desk.summary(self.packet)["blind"],1)
                self.assertEqual(desk.summary(self.packet)["assisted"],1)
            finally:
                srv.shutdown()
                th.join()

    def test_loopback_page_and_api(self):
        with desk.build_server(self.d) as srv:
            th=threading.Thread(target=srv.serve_forever,daemon=True);th.start()
            try:
                def call(method,url,payload=None,headers=None):
                    conn=http.client.HTTPConnection("127.0.0.1",srv.server_port,timeout=3)
                    conn.request(method,url,json.dumps(payload).encode() if payload is not None else None,headers or {})
                    response=conn.getresponse();data=response.read();code=response.status;hdr=response.getheaders();conn.close()
                    return code,data,dict(hdr)
                status,page,hdr=call("GET","/")
                self.assertEqual(status,200)
                self.assertIn(b"<script>",page)
                self.assertIn(b"<style>",page)
                self.assertNotIn(b'<script src=',page)
                self.assertNotIn(b"example.invalid",page)
                self.assertIn("sha256-",hdr["Content-Security-Policy"])
                self.assertEqual(call("GET","/other")[0],404)
                headers={"Origin":"http://"+srv.host,"X-Desk-Token":srv.token,"X-Desk-Tab":"simulated-browser-001","Content-Type":"application/json"}
                self.assertEqual(call("POST","/api/state",{},headers)[0],200)
                for name,bad in [("Host","unexpected.invalid"),("Origin","http://unexpected.invalid"),("X-Desk-Token","wrong")]:
                    self.assertEqual(call("POST","/api/state",{},headers|{name:bad})[0],403)
                state=json.loads(call("POST","/api/start",dict(ticket="ticket-a"),headers)[1])
                self.assertEqual(state["card"]["text"],self.card["text"])
                self.assertEqual(call("POST","/api/state?alternate",{},headers)[0],404)
            finally:
                srv.shutdown();th.join()


if __name__=="__main__":
    unittest.main()
