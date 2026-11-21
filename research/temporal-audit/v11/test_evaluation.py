"""Denominators for the three-way scoring contract."""
import unittest
from evaluate import metrics

class MetricsTest(unittest.TestCase):
    def test_referrals_and_ambiguous_references(self):
        x=metrics([('POST_ASSERTION','POST_ASSERTION'), ('POST_ASSERTION','REVIEW'),
                   ('OTHER','POST_ASSERTION'), ('OTHER','OTHER'),
                   ('INDETERMINATE','POST_ASSERTION'), ('INDETERMINATE','REVIEW')])
        self.assertEqual(x['n'],6)
        self.assertEqual(x['sensitivity'],0.5)
        self.assertEqual(x['precision_determinate'],0.5)
        self.assertEqual(x['coverage'],4/6)
        self.assertEqual(x['selective_error_determinate'],1/3)
        self.assertEqual(x['automatic_on_indeterminate'],1)
        self.assertEqual(x['alerts_on_indeterminate'],1)

    def test_abstain_everywhere(self):
        x=metrics([('POST_ASSERTION','REVIEW'),('OTHER','REVIEW')])
        self.assertEqual(x['sensitivity'],0)
        self.assertEqual(x['coverage'],0)
        self.assertIsNone(x['precision_determinate'])
        self.assertIsNone(x['selective_error_determinate'])

    def test_invalid_reference(self):
        with self.assertRaises(ValueError):
            metrics([('REVIEW','OTHER')])

