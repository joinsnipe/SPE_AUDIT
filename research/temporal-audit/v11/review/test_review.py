"""Every case, annotation, time and freeze in these tests is SIMULATED. Zero human participants."""
import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as Args

import review


class SimulatedReview(unittest.TestCase):
    def setUp(self):
        store = tempfile.TemporaryDirectory()
        self.addCleanup(store.cleanup)
        self.root = Path(store.name)
        self.batch = self.root / "batch"
        self.freeze = self.root / "freeze"
        self.freeze.write_text("SIMULATION ONLY: frozen example specification")
        self.cases = self.root / "cases.json"
        self.events = self.root / "events.json"
        self.cases.write_text(json.dumps([
            dict(id=f"hidden-topic-{i}", event_id="private-event-id", language="en",
                 cutoff="2000-01-01", prompt="SIMULATED prompt", text=f"SIMULATED example sentence {i}.",
                 prediction="NEVER-EXPORT-ME", label="HIDDEN-LABEL") for i in range(4)]))
        self.events.write_text(json.dumps([dict(id="private-event-id", name="Simulated event",
                                               event_date="2000-01-02", source_url="https://example.invalid/simulation",
                                               outcome_regex="LEAKED-MATCHER")]))
        self.args = Args(out=self.batch, cases=self.cases, events=self.events, mode="simulation",
                         freeze=self.freeze, freeze_sha256=review.digest(self.freeze.read_bytes()))
        with contextlib.redirect_stdout(io.StringIO()):
            review.prepare(self.args)
        self.map = review.json_file(self.batch/"coordinator.json")["roles"]

    def ticket(self, role, i):
        return next(k for k,v in self.map[role]["tickets"].items() if v==f"hidden-topic-{i}")

    def answer(self, role, i, label, seconds=15):
        review.record(self.batch/(role+".sqlite"), self.ticket(role,i),label,"SIMULATED evidence",seconds,"manual")

    def seal(self, role, partial=False):
        with contextlib.redirect_stdout(io.StringIO()):
            review.seal(Args(packet=self.batch/(role+".sqlite"),allow_pending=partial))

    def test_freeze_guard_and_no_clobber(self):
        with self.assertRaises(FileExistsError):
            review.prepare(self.args)
        self.args.cases=self.root/"DOES-NOT-EXIST.json"
        self.args.freeze_sha256="0"*64
        with self.assertRaisesRegex(ValueError,"were not opened"):
            review.prepare(self.args)

    def test_json_freeze_binds_each_input_before_packet_creation(self):
        self.args.out = self.root / "bound"
        paths = {"holdout/cases.json": self.cases, "holdout/events.json": self.events}
        hashes = {name: review.digest(path.read_bytes()) for name, path in paths.items()}
        self.freeze.write_text(json.dumps({"description": "SIMULATED freeze", "sha256": hashes}))
        self.args.freeze_sha256 = review.digest(self.freeze.read_bytes())
        for name, path in paths.items():
            with self.subTest(replaced=name):
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(ValueError, name):
                    review.prepare(self.args)
                self.assertFalse(self.args.out.exists())
                path.write_bytes(original)
        with contextlib.redirect_stdout(io.StringIO()):
            review.prepare(self.args)
        manifest = review.json_file(self.args.out / "coordinator.json")
        self.assertEqual(manifest["cases_sha256"], hashes["holdout/cases.json"])
        self.assertEqual(manifest["events_sha256"], hashes["holdout/events.json"])

    def test_partial_json_input_commitment_fails_closed(self):
        self.args.out = self.root / "partial"
        self.freeze.write_text(json.dumps({"sha256": {"holdout/cases.json": review.digest(self.cases.read_bytes())}}))
        self.args.freeze_sha256 = review.digest(self.freeze.read_bytes())
        with self.assertRaisesRegex(ValueError, "holdout/events.json"):
            review.prepare(self.args)
        self.assertFalse(self.args.out.exists())

    def test_packets_strip_known_leaks_and_crosswalk_and_order(self):
        orders=[]
        for role in review.ROLES:
            packet=self.batch/(role+".sqlite")
            with review.db(packet) as conn:
                rows=list(conn.execute("select ticket,card from items order by pos"))
            orders.append([self.map[role]["tickets"][r["ticket"]] for r in rows])
            for marker in ("private-event-id","hidden-topic","NEVER-EXPORT","HIDDEN-LABEL","LEAKED-MATCHER"):
                self.assertNotIn(marker.encode(),packet.read_bytes())
            self.assertEqual(set(json.loads(rows[0]["card"])), set(review.FIELDS)|{"event","event_date","source_url"})
        self.assertNotEqual(orders[0],orders[1])
        self.assertTrue(set(self.map["A"]["tickets"]).isdisjoint(self.map["B"]["tickets"]))

    def test_pause_resume_and_bad_times(self):
        p=self.batch/"A.sqlite"
        ticket=self.ticket("A",0)
        inputs=iter(["p","r","a","other","SIMULATED reasoning"])
        ticks=iter([0,5,1000,1012])
        with contextlib.redirect_stdout(io.StringIO()):
            review.session(Args(packet=p,ticket=ticket), clock=lambda:next(ticks),read=lambda _:next(inputs))
        with review.db(p) as conn:
            row=conn.execute("select * from answers").fetchone()
        self.assertEqual((row["seconds"],row["timing"]),(17,"clock"))
        for bad in (-3,0,float("nan"),float("inf"),False):
            with self.assertRaises(ValueError):
                self.answer("A",1,"other",bad)
        with self.assertRaises(ValueError):
            self.answer("A",0,"indeterminate")
        with self.assertRaisesRegex(ValueError,"pending"):
            self.seal("A")

    def test_paired_agreement_partial_and_adjudication(self):
        P,O,I=review.LABELS
        for role,labs in [("A",[P,O,I,P]),("B",[P,I,I])]:
            for i,label in enumerate(labs):
                self.answer(role,i,label,(i+1)*10)
            self.seal(role,True)
        old=(self.batch/"A.sqlite").read_bytes()
        r=review.report(self.batch)
        self.assertEqual(r["matrix"],[[1,0,0],[0,0,1],[0,0,1]])
        self.assertAlmostEqual(r["agreement_pct"],200/3)
        self.assertAlmostEqual(r["kappa"],0.5)
        self.assertEqual(r["reviewers"]["A"]["median_seconds"],25)
        self.assertEqual(r["reviewers"]["A"]["p90_seconds_nearest_rank"],40)
        self.assertEqual(r["double_review_active_time"]["median_seconds"],40)
        self.assertEqual((r["n_paired"],r["pending_pairs"],r["adjudication"]["required"],r["pending_review_tasks"]),(3,1,2,1))
        review.adjudicate(Args(batch=self.batch,case="hidden-topic-1",label=I,evidence="SIMULATED unresolved",seconds=5))
        r2=review.report(self.batch)
        self.assertEqual(r2["matrix"],r["matrix"])
        self.assertEqual(r2["final_case_counts"],{P:1,O:0,I:1})
        self.assertEqual(r2["adjudication"]["pending"],1)
        self.assertAlmostEqual(r2["observed_person_minutes_including_adjudication"],165/60)
        self.assertEqual(old,(self.batch/"A.sqlite").read_bytes())
        with self.assertRaises(ValueError):
            self.answer("A",2,O)
        with self.assertRaises(ValueError):
            review.adjudicate(Args(batch=self.batch,case="hidden-topic-1",label=P,evidence="SIM",seconds=5))

    def test_seals_and_anonymous_card_commitment(self):
        with self.assertRaisesRegex(ValueError,"must be sealed"):
            review.report(self.batch)
        self.answer("A",0,"other")
        self.seal("A",True)
        self.seal("B",True)
        r=review.report(self.batch)
        self.assertIsNone(r["kappa"])
        self.assertIsNone(r["agreement_pct"])
        self.assertIsNone(r["double_review_active_time"]["p90_seconds_nearest_rank"])
        with review.db(self.batch/"A.sqlite","rw") as conn:
            conn.execute("update answers set evidence='SIMULATED altered'")
        with self.assertRaisesRegex(ValueError,"answer commitment"):
            review.report(self.batch)
        with self.assertRaisesRegex(ValueError,"were changed"):
            self.seal("A",True)

    def test_swapped_packet_and_invalid_metadata(self):
        self.seal("A",True)
        self.seal("B",True)
        shutil.copyfile(self.batch/"B.sqlite", self.batch/"A.sqlite")
        with self.assertRaisesRegex(ValueError,"card/order"):
            review.report(self.batch)
        self.args.out=self.root/"invalid"
        self.events.write_text("[]")
        with self.assertRaisesRegex(ValueError,"nonempty JSON array"):
            review.prepare(self.args)
        self.assertFalse(self.args.out.exists())

    def test_cli_roundtrip_all_simulated(self):
        pyfile = Path(review.__file__)
        def run(*argv, expect=0, stdin=None):
            proc = subprocess.run([sys.executable, "-B", str(pyfile), *map(str, argv)],
                                  input=stdin, text=True, capture_output=True)
            self.assertEqual(proc.returncode, expect, proc.stderr)
            return proc.stdout
        dest = self.root/"other_batch"
        run("prepare", "--out", dest, "--cases", self.cases, "--events", self.events,
            "--freeze", self.freeze, "--freeze-sha256", self.args.freeze_sha256, "--mode", "simulation")
        mapping = review.json_file(dest/"coordinator.json")["roles"]
        for role, label in zip(review.ROLES, ["other","indeterminate"]):
            packet = dest/(role+".sqlite")
            first = json.loads(run("show",packet))
            self.assertIn("ticket",first)
            ticket = next(t for t,i in mapping[role]["tickets"].items() if i=="hidden-topic-0")
            run("record",packet,"--ticket",ticket,"--label",label,"--evidence","SIMULATED manual","--seconds","25")
            run("seal",packet,expect=2)
            receipt = run("seal",packet,"--allow-pending")
            self.assertIn(json.loads(run("status",packet))["answers_sha256"], receipt)
        result = json.loads(run("report",dest))
        self.assertEqual((result["mode"],result["n_paired"],result["agreement_pct"]),("simulation",1,0))
        self.assertEqual(json.loads(run("adjudicate",dest))["id"],"hidden-topic-0")
        run("adjudicate",dest,"--case","hidden-topic-0","--label","indeterminate",
            "--evidence","SIMULATED unresolved","--seconds","14")
        self.assertEqual(json.loads(run("report",dest))["final_case_counts"]["indeterminate"],1)

    def test_undefined_kappa_after_perfect_constant_answers(self):
        res=review.agreement([[0,0,0],[0,3,0],[0,0,0]])
        self.assertEqual(res["agreement_pct"],100)
        self.assertIsNone(res["kappa"])


if __name__=="__main__":
    unittest.main()
