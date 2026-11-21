import json
import unittest

from replay import HERE, NEG, POS, REVIEW, mark_check, run, summarize


class RobustnessReplayTests(unittest.TestCase):
    def test_conditional_denominator_and_destinations(self):
        def row(gold, start, end):
            return {'reference':gold,'base':{'method':start},'variant':{'method':end}}
        measures=summarize([row(POS,POS,REVIEW),row(POS,POS,NEG),row(POS,NEG,POS),row(NEG,POS,NEG)],'method')
        self.assertEqual(measures['positive_pairs'],3)
        self.assertEqual(measures['detected_positive_bases'],2)
        self.assertEqual(measures['conditional_alert_loss'],1)
        self.assertEqual(measures['conditional_review'],0.5)
        self.assertEqual(measures['conditional_other'],0.5)
        self.assertEqual(measures['all_positive_variants_alerted'],1)
        self.assertEqual(measures['false_alert_rates'],{'base':1,'variant':0})

    def test_empty_denominators_are_undefined(self):
        outcome=summarize([], 'method')
        self.assertIsNone(outcome['conditional_alert_loss'])
        self.assertIsNone(outcome['false_alert_rates']['base'])

    def test_local_field_contract(self):
        evidence=mark_check()
        self.assertEqual(evidence['sender_calls'],2)
        self.assertTrue(evidence['marker_at_declared_location_only'])
        self.assertTrue(evidence['same_policy_cutoff_and_prompt'])
        self.assertTrue(evidence['eligible_id_unchanged'])
        self.assertTrue(evidence['both_receipts_validate'])
        self.assertNotEqual(*evidence['request_hashes'])

    def test_all_public_records_replay(self):
        result=run()
        self.assertEqual(result,json.loads((HERE/'results.json').read_text()))
        self.assertEqual(result['distinct_texts'],48)
        for key in ('en','es'):
            for method,metrics in result['groups'][key].items():
                with self.subTest(key=key,method=method):
                    self.assertEqual((metrics['positive_pairs'],metrics['control_pairs'],metrics['indeterminate_pairs']),(6,4,2))
                    self.assertEqual(metrics['retained_alerts']+metrics['changed_to_review']+metrics['changed_to_other'],metrics['detected_positive_bases'])
        one=result['groups']['overall']
        self.assertEqual(one['year_rule']['changed_to_other'],4)
        self.assertEqual(one['proposition']['changed_to_review'],6)
        self.assertEqual(one['proposition']['controls']['variant'][POS],2)


if __name__=='__main__':
    unittest.main()
