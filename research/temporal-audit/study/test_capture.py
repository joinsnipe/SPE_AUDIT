"""Regression tests for local temporal capture. Run with Python unittest."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from capture import POLICY_ID, run_capture, verify_capture, verify_file


def card(name, when):
    return {"id": name, "date": when, "text": f"{name}: año\n二", "url": "https://example.org"}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.cutoff = "2020-02-29"
        self.prompt = "¿Qué se sabía?\n"
        self.sources = [card("z", self.cutoff), card("later", "2020-03-01"), card("a", "2019-12-31")]

    def make(self, output="answer"):
        return run_capture(self.cutoff, self.prompt, self.sources, lambda _: output)

    def test_exact_bytes_and_output_including_empty_output(self):
        sent = []
        def send(data):
            sent.append(data)
            return "Año\r\n🚀"
        record = run_capture(self.cutoff, self.prompt, self.sources, send)
        self.assertEqual(sent, [record["request_utf8"].encode("utf-8")])
        parsed = json.loads(sent[0])
        self.assertEqual(parsed["cutoff"], self.cutoff)
        self.assertEqual(parsed["policy_id"], POLICY_ID)
        self.assertEqual(parsed["prompt"], self.prompt)
        self.assertEqual(parsed["sources"], [self.sources[2], self.sources[0]])
        self.assertEqual(record["output"], "Año\r\n🚀")
        self.assertTrue(verify_capture(record, record["record_sha256"]))
        self.assertTrue(verify_capture(self.make("")))

    def test_order_invariance_and_no_source_case(self):
        expected = self.make()
        self.sources.reverse()
        self.assertEqual(self.make(), expected)
        self.sources = [card("later", "2021-01-01")]
        record = self.make()
        self.assertEqual(json.loads(record["request_utf8"])["sources"], [])
        self.assertTrue(verify_capture(record))

    def test_invalid_input_never_invokes_sender(self):
        for field, value in [
            ("cutoff", "2021-02-29"), ("cutoff", "2020-02-29T23:59Z"),
            ("prompt", " "), ("prompt", "\ud800"), ("source_cards", self.sources * 2),
            ("source_cards", [dict(self.sources[1], date="broken")]),
            ("source_cards", [dict(self.sources[1], text="\ud800")]),
            ("source_cards", [dict(self.sources[0], extra="")]),
        ]:
            with self.subTest(field=field):
                args = dict(cutoff=self.cutoff, prompt=self.prompt, source_cards=self.sources,
                            send=lambda _: self.fail("invalid request reached sender"))
                args[field] = value
                with self.assertRaises(ValueError):
                    run_capture(**args)

    def test_invalid_response_or_transport_failure(self):
        with self.assertRaises(ValueError):
            run_capture(self.cutoff, self.prompt, [], lambda _: b"bytes")
        with self.assertRaises(ValueError):
            run_capture(self.cutoff, self.prompt, [], lambda _: "\ud800")
        def unavailable(_):
            raise RuntimeError("sender failed")
        with self.assertRaises(RuntimeError):
            run_capture(self.cutoff, self.prompt, [], unavailable)

    def test_field_changes_fail(self):
        record = self.make()
        for key in record:
            with self.subTest(key=key):
                changed = dict(record)
                changed[key] += " "
                self.assertFalse(verify_capture(changed))
        self.assertFalse(verify_capture(record, "0" * 64))
        self.assertFalse(verify_capture(dict(record, other="extra")))

    def test_resealing_cannot_validate_post_cutoff_or_noncanonical_request(self):
        original = self.make()
        parsed = json.loads(original["request_utf8"])
        post = copy.deepcopy(parsed)
        post["sources"].append(card("new", "2022-03-05"))
        for altered in [json.dumps(post, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
                        json.dumps(parsed, indent=4), "null", "[]", '"text"']:
            changed = dict(original, request_utf8=altered)
            changed["request_sha256"] = hashlib.sha256(altered.encode()).hexdigest()
            del changed["record_sha256"]
            sealed_body = json.dumps(changed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            changed["record_sha256"] = hashlib.sha256(sealed_body.encode()).hexdigest()
            self.assertFalse(verify_capture(changed))

    def test_replay_expected_root_pins_bytes_and_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capsules.jsonl"
            lines = [json.dumps(self.make(out)).encode() + b"\n" for out in ["one", "two"]]
            path.write_bytes(b"".join(lines))
            root = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(verify_file(path, root), (2, root))
            path.write_bytes(b"".join(reversed(lines)))
            with self.assertRaisesRegex(ValueError, "expected root"):
                verify_file(path, root)
            path.write_bytes(lines[0].replace(b"{", b'{"schema":"extra",', 1))
            with self.assertRaisesRegex(ValueError, "line 1"):
                verify_file(path)
            path.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "empty"):
                verify_file(path)


if __name__ == "__main__":
    unittest.main()
