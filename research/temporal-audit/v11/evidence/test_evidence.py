import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from evidence import (
    civil_interval, decide, inclusion_proof, instant, load_json, merkle_root,
    span, verify_inclusion, verify_snapshot,
)
from timestamp import verify_timestamp

HERE = Path(__file__).resolve().parent
CUT = "2026-03-29T12:00:00Z"
OLD = "2026-03-28T12:00:00Z"
LATE = "2026-03-30T12:00:00Z"


class TimeTests(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(civil_interval("2026-03-29","+02:00",0)["latest"],"2026-03-29T00:59:59.999999+02:00")
        for observation,cutoff,decision in [
            (CUT,"2026-03-29T14:00:00+02:00","eligible"),
            ({"earliest":OLD,"latest":CUT},CUT,"eligible"),
            (CUT,{"earliest":CUT,"latest":LATE},"eligible"),
            ({"earliest":CUT,"latest":LATE},CUT,"indeterminate"),
            (LATE,{"earliest":OLD,"latest":CUT},"ineligible"),
            (civil_interval("2026-03-29","Z"),CUT,"indeterminate"),
            (civil_interval("2026-03-29","Z",11),CUT,"eligible"),
            ("2026-03-29T12:00:00.000001Z",CUT,"ineligible"),
        ]:
            with self.subTest(observation=observation,cutoff=cutoff):
                self.assertEqual(decide({"publication":observation},cutoff,["publication"])["decision"],decision)

    def test_time_validation(self):
        for value in ("2026-03-29","2026-03-29T12:00:00",CUT.replace("Z","-00:00"),
                      CUT.replace("-03-29","-02-29"),CUT.replace("Z","+05:99"),CUT.replace("12:","24:"),
                      CUT.replace("00Z","60Z"),CUT.replace("00Z","00.0000001Z"),"0001-01-01T00:00:00+23:00",False):
            with self.assertRaises(ValueError): instant(value)
        for value in ({"earliest":LATE,"latest":OLD},{"start":OLD,"end":LATE},None,17):
            with self.assertRaises(ValueError): span(value)
        for day,offset,hour in (("2026-02-30","Z",None),("2026-03-29","-00:00",None),
                                ("2026-03-29","+01:00",True),("2026-03-29","QZ",None)):
            with self.assertRaises(ValueError): civil_interval(day,offset,hour)

    def test_dst_interval(self):
        lo,hi=span({"earliest":"2026-03-29T00:00:00+01:00","latest":"2026-03-29T23:59:59.999999+02:00"})
        self.assertEqual((hi-lo).total_seconds(),23*3600-.000001)

    def test_policy(self):
        times={"event":OLD,"publication":None,"effective":LATE,"ingestion":CUT,"capture":LATE}
        self.assertEqual(decide(times,CUT,["event"])["decision"],"eligible")
        self.assertEqual(decide(times,CUT,["publication"])["decision"],"indeterminate")
        self.assertEqual(decide(times,CUT,["publication","effective"]),{
            "decision":"ineligible","fields":{"publication":"indeterminate","effective":"ineligible"}})
        self.assertEqual(decide({},CUT,["capture"])["decision"],"indeterminate")
        for malformed,policy in ((times,[]),(times,["effect"]),(times,["event","event"]),
                                 ({"event":OLD,"x":OLD},["event"]),({"ingestion":"broken"},["event"])):
            with self.assertRaises(ValueError): decide(malformed,CUT,policy)


class MerkleTests(unittest.TestCase):
    def test_shapes_and_duplicates(self):
        for n in range(1,34):
            leaves=[bytes([i%3]) for i in range(n)]
            root=merkle_root(leaves)
            for i,leaf in enumerate(leaves):
                self.assertTrue(verify_inclusion(leaf,inclusion_proof(leaves,i),root))
        self.assertNotEqual(merkle_root([]),merkle_root([b""]))
        self.assertNotEqual(merkle_root([b"x"]),merkle_root([b"x",b"x"]))
        self.assertNotEqual(merkle_root([b"a",b"b",b"c"]),merkle_root([b"a",b"b",b"c",b"c"]))
        self.assertNotEqual(merkle_root([b"a",b"b"]),merkle_root([b"b",b"a"]))
        with self.assertRaises(ValueError): inclusion_proof([],0)

    def test_tampering(self):
        leaves=[b"a",b"b",b"a",b"c",b"d"]
        proof=inclusion_proof(leaves,2); root=merkle_root(leaves)
        for key,value in (("scheme","other"),("index",0),("size",4),("size",6),("size",True),
                          ("index",-1),("index",5),("size",2**64),("siblings",["0"*64]),
                          ("siblings",proof["siblings"]+["0"*64]),("siblings",["X"*64]*3),
                          ("siblings",list(reversed(proof["siblings"])))):
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                verify_inclusion(b"a",{**proof,key:value},root)
        for changed,ref in ((b"A",root),(b"a","0"*64),(b"a",None)):
            with self.assertRaises(ValueError): verify_inclusion(changed,proof,ref)
        for invalid in (b"whole byte stream",["unencoded string"]):
            with self.assertRaises(ValueError): merkle_root(invalid)

    def test_published_vector(self):
        folder=HERE/"snapshots"; manifest=folder/"manifest.json"
        raw=(folder/"core-merkle.py.txt").read_bytes()
        leaves=[manifest.read_bytes(),raw,b"SPE Audit teaching example.\n"]
        root=(folder/"root.txt").read_text().strip()
        self.assertEqual(root,merkle_root(leaves))
        proof=load_json(folder/"inclusion.json")
        self.assertEqual(proof,inclusion_proof(leaves,1))
        self.assertTrue(verify_inclusion(raw,proof,root))


class SnapshotTests(unittest.TestCase):
    def test_exact_bytes(self):
        original=HERE/"snapshots/manifest.json"
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"snapshot";shutil.copytree(original.parent,p)
            manifest=p/"manifest.json"
            expected=hashlib.sha256(manifest.read_bytes()).hexdigest()
            entry=verify_snapshot(manifest,expected)
            self.assertEqual(entry["bytes"],949)
            self.assertEqual(decide(entry["times"],"2026-03-01T00:00:00Z",["publication"])["decision"],"indeterminate")
            manifest.write_bytes(manifest.read_bytes()+b" ")
            with self.assertRaises(ValueError): verify_snapshot(manifest,expected)
            (p/entry["file"]).write_bytes(b"other")
            with self.assertRaises(ValueError): verify_snapshot(manifest)

    def test_schema(self):
        entry=load_json(HERE/"snapshots/manifest.json")
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"manifest.json"
            for key,value in (("bytes",True),("sha256","0"*63),("file","../elsewhere"),("schema","unknown"),
                              ("times",{"capture":None}),("version","branch")):
                path.write_text(json.dumps({**entry,key:value}))
                with self.assertRaises((ValueError,FileNotFoundError)): verify_snapshot(path)
            path.write_text('{"schema":1,"schema":2}')
            with self.assertRaises(ValueError): verify_snapshot(path)


def has_openssl():
    return shutil.which("openssl") and subprocess.check_output(["openssl","version"]).startswith(b"OpenSSL 3.")


@unittest.skipUnless(has_openssl(),"OpenSSL 3.x is optional")
class TimestampTests(unittest.TestCase):
    def test_ephemeral_local_tsa(self):
        # Everything is generated inside a temporary directory for a verification exercise.
        # The local key provides no independent public witness.
        with tempfile.TemporaryDirectory() as d:
            base=Path(d)
            def run(*args):
                return subprocess.run(["openssl",*args],cwd=d,check=True,capture_output=True).stdout
            run("req","-x509","-newkey","rsa:2048","-nodes","-subj","/CN=LOCAL-TEST-ROOT","-days","2",
                "-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign",
                "-keyout","root.key","-out","root.pem")
            run("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN=LOCAL-TEST-TSA",
                "-keyout","tsa.key","-out","tsa.csr")
            (base/"ext.cnf").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n")
            run("x509","-req","-in","tsa.csr","-CA","root.pem","-CAkey","root.key","-set_serial","2",
                "-days","1","-extfile","ext.cnf","-out","tsa.pem")
            (base/"serial").write_text("01\n")
            (base/"tsa.cnf").write_text(
                "[tsa]\ndefault_tsa=local\n[local]\nserial=serial\nsigner_cert=tsa.pem\n"
                "certs=root.pem\nsigner_key=tsa.key\nsigner_digest=sha256\ndefault_policy=1.2.3.4.5\n"
                "digests=sha256\naccuracy=secs:1\nordering=no\ntsa_name=yes\ness_cert_id_chain=no\n")
            data=base/"data";data.write_bytes(b"Local fixture; no independent timestamp.\n")
            run("ts","-query","-data","data","-sha256","-cert","-out","request.tsq")
            run("ts","-reply","-config","tsa.cnf","-queryfile","request.tsq","-out","response.tsr")
            run("ts","-reply","-in","response.tsr","-token_out","-out","token.tst")
            ca=base/"root.pem"; resp=base/"response.tsr"; req=base/"request.tsq"
            pin=hashlib.sha256(run("x509","-in","root.pem","-outform","DER")).hexdigest()
            self.assertIn("Time stamp:",verify_timestamp(data,resp,ca,pin,query=req))
            self.assertIn("Time stamp:",verify_timestamp(data,base/"token.tst",ca,pin,token=True))
            with self.assertRaises(ValueError): verify_timestamp(data,resp,ca,"0"*64)
            run("req","-x509","-newkey","rsa:2048","-nodes","-subj","/CN=OTHER-LOCAL-CA",
                "-days","2","-keyout","other.key","-out","other.pem")
            other=hashlib.sha256(run("x509","-in","other.pem","-outform","DER")).hexdigest()
            with self.assertRaises(ValueError): verify_timestamp(data,resp,base/"other.pem",other)
            run("ts","-query","-data","data","-sha256","-cert","-out","another.tsq")
            with self.assertRaises(ValueError): verify_timestamp(data,resp,ca,pin,query=base/"another.tsq")
            data.write_bytes(b"changed")
            with self.assertRaises(ValueError): verify_timestamp(data,resp,ca,pin)


if __name__=="__main__":
    unittest.main()
