"""Offline contract tests that read no trial data."""
import json
import math
from pathlib import Path
import unittest

from local_model import LANGUAGES, ROOT, head_probability, load, next_characters, predict


class LocalModelTests(unittest.TestCase):
    def setUp(self):
        self.event = {"id": "e", "name": "Archive", "event_date": "2001-01-02",
                      "aliases": ["Museum"], "outcome_terms": ["opened"], "source_url": "urn:example:source"}
        self.case = {"id": "example", "event_id": "e", "cutoff": "2000-12-31", "language": "en",
                     "prompt": "Archive", "text": "Museum opened."}

    def test_language_model_and_fingerprint(self):
        report = json.loads((ROOT / "training_report.json").read_bytes())
        self.assertEqual(load()[2], report["weights_sha256"])
        probabilities = next_characters("a", count=100)
        self.assertTrue(math.isclose(sum(p["probability"] for p in probabilities), 1))
        self.assertEqual(len(probabilities), report["fit"]["vocabulary_size"])

    def test_local_interface_and_exact_quote(self):
        result = predict(self.case, self.event)
        self.assertIn(result["decision"], {"OTHER", "POST_ASSERTION", "REVIEW"})
        self.assertAlmostEqual(result["score"], head_probability(self.case["text"]))
        self.assertEqual(result["trace"]["answer_quote"], self.case["text"])
        span = result["trace"]["subject_in_answer"][0]
        self.assertEqual(self.case["text"][span["start"]:span["end"]], "Museum")
        self.assertEqual(result["trace"]["registered_outcome_in_answer"][0]["text"], "opened")

    def test_dates_languages_and_review(self):
        for lang in LANGUAGES:
            r = predict(dict(self.case, cutoff=self.event["event_date"], language=lang), self.event)
            self.assertEqual((r["decision"], r["score"]), ("OTHER", None))
        for values in [{"event_id": "unrelated"}, {"cutoff": "2000-02-30"}, {"text": ""}, {"language": "xx"},
                       {"text": "x" * 513}, {"prompt": "", "text": "No named subject."}]:
            self.assertEqual(predict(dict(self.case, **values), self.event)["decision"], "REVIEW")

    def test_parameter_counts(self):
        data, _, _ = load()
        def scalars(value):
            return sum(scalars(x) for x in value) if isinstance(value, list) else 1
        self.assertEqual(sum(scalars(v) for v in data["parameters"].values()), 3638)


if __name__ == "__main__":
    unittest.main()
