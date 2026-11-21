import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from study import (
    ARMS, CUTOFF, HERE, MODES, N, RESULTS, ROLES, cards, check_plan, commitments, outcomes, public_design,
    register, schedule, trial, verify,
)


class InterventionTests(unittest.TestCase):
    def test_randomized_matrix(self):
        design=public_design()
        self.assertEqual(len(design),40)
        values=[p[k] for p in design for k in ROLES]
        self.assertEqual(len(set(values)),120)
        order=schedule()
        self.assertEqual(len(order),360)
        self.assertEqual(set(order),{(i,m,a) for i in range(1,41) for m in MODES for a in ARMS})
        self.assertNotEqual(order, sorted(order))

    def test_local_subprocess(self):
        pair=public_design()[0]
        rows=[trial(pair,m,a) for m in MODES for a in ARMS]
        s=outcomes(rows,[pair])
        metrics={(x["mode"],x["condition"]):x for x in s["conditions"]}
        self.assertEqual(metrics["reader","present"]["target"],1)
        self.assertEqual(metrics["reader","absent"]["unavailable"],1)
        self.assertEqual(metrics["reader","decoy"]["decoy"],1)
        for a in ARMS:
            self.assertEqual(metrics["generic",a]["generic"],1)
            self.assertEqual(metrics["side",a]["target"],1)
            raw={r["capture"]["request_utf8"] for r in rows if r["condition"]==a}
            self.assertEqual(len(raw),1)
            self.assertNotIn(pair["future"],raw.pop())
        modes={x["mode"]:x["target_rate_difference"] for x in s["paired_differences"]}
        self.assertEqual(modes,{"reader":1.0,"side":0.0,"generic":0.0})
        with self.assertRaises(ValueError):outcomes(rows[:-1],[pair])
        with self.assertRaises(ValueError):outcomes(rows+[rows[0]],[pair])
        rows[0]["capture"]["output"]="edited"
        with self.assertRaises(ValueError):outcomes(rows,[pair])

    def test_released_recount(self):
        s=verify(HERE/"results")
        self.assertEqual((s["pairs"],s["local_calls"]),(40,360))
        self.assertEqual(sum(x["future"] for x in s["conditions"]),0)
        self.assertEqual(sum(x["n"] for x in s["conditions"]),360)
        rows=[json.loads(line) for line in (HERE/"results"/"captures.jsonl").read_bytes().splitlines()]
        for r in rows:
            prompt=json.loads(r["capture"]["request_utf8"])["prompt"]
            self.assertEqual(prompt,s["prompt"])

    def test_private_registration(self):
        with tempfile.TemporaryDirectory() as td:
            a=Path(td)/"a";b=Path(td)/"b"
            pin=register(a,4);self.assertEqual(pin,check_plan(a))
            self.assertNotEqual(pin,register(b,4))
            with self.assertRaises(FileExistsError):register(a,4)
            plan=json.loads((a/"private.json").read_bytes())
            public=(a/"commitments.json").read_text()
            for p in plan:
                for k in (*ROLES,"salt"):self.assertNotIn(p[k], public)
            if os.name=="posix":self.assertEqual((a/"private.json").stat().st_mode & 0o077,0)
            plan[0]["order"].reverse()
            (a/"private.json").write_text(json.dumps(plan))
            with self.assertRaises(ValueError): check_plan(a)
            plan[1]["target"]=plan[0]["target"]
            with self.assertRaises(ValueError):commitments(plan)
