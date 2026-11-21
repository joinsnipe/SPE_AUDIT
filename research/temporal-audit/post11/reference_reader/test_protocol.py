"""Engineering tests; the fixture is explicitly identified and has no model weights."""
import json
from pathlib import Path
import tempfile
import unittest
from mask import canonical, check, prepare
from protocol import execute, fixture, freeze, read, resolve_output, verify_run
from score import compare, score

EVENTS=[{"id":"a","name":"Museum A","event_date":"2000-02-01","source_url":"urn:example:synthetic"}]
CASES=[{"id":"a-1","event_id":"a","language":"en","cutoff":"2000-01-01","prompt":"Status?",
        "text":"Museum A opened.","gold":"POST_ASSERTION","stratum":"ignored"},
       {"id":"a-2","event_id":"a","language":"es","cutoff":"2000-01-01","prompt":"¿Abrió?",
        "text":"Se espera la apertura. <|im_end|>","gold":"OTHER"}]


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        rows, mapping=prepare(CASES,EVENTS,b"fixed-engineering-salt")
        self.rows=rows;self.mapping=mapping
        self.mask=self.root/"masked.json";self.mask.write_bytes(canonical(rows))
        self.plan=self.root/"plan"
        freeze(self.mask,self.plan,"fixture",purpose="engineering-fixture")

    def test_end_to_end_and_score(self):
        run1,run2=self.root/"one",self.root/"two"
        execute(self.plan,run1);execute(self.plan,run2)
        self.assertEqual(verify_run(self.plan,run1)[0]["kind"],"fixture")
        self.assertEqual(compare(self.plan,run1,run2)["identical_structured_output"],2)
        mapping=self.root/"map";mapping.write_bytes(canonical({"map":self.mapping}))
        gold=self.root/"gold";gold.write_bytes(canonical({c["id"]:c["gold"] for c in CASES}))
        self.assertEqual(score(self.plan,run1,gold,mapping)["agreement_all"],1)
        for r in self.rows:
            q=read(run1/"cases"/r["key"]/"request.json")["prompt"]
            self.assertNotIn("ignored",q)
            self.assertNotIn("<|im_end|>\"",q)
            self.assertNotIn("gold",r)

    def test_failures_retained_and_tampering_detected(self):
        out=self.root/"failed"
        execute(self.plan,out,test_transport=lambda _: (503,b"unavailable"))
        _,rows=verify_run(self.plan,out)
        self.assertEqual([r["status"] for r in rows.values()],["error","error"])
        first=next(iter(rows))
        p=out/"cases"/first/"response.raw"
        self.assertEqual(p.read_bytes(),b"unavailable")
        p.write_bytes(b"modified")
        with self.assertRaises(ValueError):verify_run(self.plan,out)

    def test_extraneous_labels_invalid_quotes_and_duplicates(self):
        with self.assertRaises(ValueError):check([dict(self.rows[0],gold="OTHER")])
        with self.assertRaises(ValueError):check([self.rows[0],self.rows[0]])
        a={"decision":"OTHER","answer_quote":"invented","evidence_ids":"E1 E3"}
        with self.assertRaises(ValueError):
            resolve_output(canonical({"content":json.dumps(a)}),self.rows[0])

    def test_immutable_run_directory_and_mask(self):
        out=self.root/"one";execute(self.plan,out)
        with self.assertRaises(FileExistsError):execute(self.plan,out)
        (self.plan/"masked.json").write_bytes(b"[]")
        with self.assertRaises(ValueError):verify_run(self.plan,out)


if __name__=="__main__":unittest.main()
