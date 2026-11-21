"""Translation invariants, selective decision accounting and learned baseline boundaries."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import unittest

import replay_languages as replay
import small_baseline as learned

HERE=Path(__file__).resolve().parent


class TestLanguages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outputs=replay.build()
        cls.rows=[json.loads(s) for s in cls.outputs['language_evidence.jsonl'].splitlines()]

    def test_replay_matches_both_artifacts(self):
        for name,text in self.outputs.items():
            self.assertEqual(text,(HERE/name).read_text())

    def test_aligned_ids_and_equal_year_decisions(self):
        by_id={}
        for row in self.rows:
            by_id.setdefault(row['id'],[]).append(row)
        self.assertEqual(len(by_id),112)
        for variants in by_id.values():
            self.assertEqual({v['language'] for v in variants},{'en','es','fr','de'})
            self.assertEqual(len({v['gold'] for v in variants}),1)
            self.assertEqual(len({v['methods']['year_rule']['decision'] for v in variants}),1)

    def test_signals_and_source_fields(self):
        for row in self.rows:
            self.assertTrue(row['registered_subject'] and row['registered_event_date'])
            self.assertTrue(row['retrospective_source'].startswith('https://'))
            self.assertTrue(row['reference_stance'] and row['text'] and row['cutoff'])
            for clause in row['methods']['proposition']['clauses']:
                self.assertIn(clause['text'],row['text'])

    def test_unsupported_separate_from_review(self):
        for row in self.rows:
            for name in ('proposition','char_ngram_nb'):
                self.assertEqual(row['methods'][name]['decision']=='UNSUPPORTED',row['language'] in ('fr','de'))

    def test_training_files_and_ids_fixed(self):
        meta=learned.model()[2]
        self.assertEqual(len(meta['training_ids']),42)
        self.assertEqual(meta['training_counts'],{'POST_ASSERTION':16,'OTHER':26})
        self.assertFalse(set(meta['training_ids'])&{r['id'] for r in self.rows})
        for line in (HERE/'learned_freeze.sha256').read_text().splitlines():
            digest,name=line.split()
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest)

    def test_training_texts_do_not_repeat_evaluation_texts(self):
        ids=set(learned.model()[2]['training_ids'])
        training={c['text'].strip().casefold() for c in json.loads(learned.CALIBRATION.read_text()) if c['id'] in ids}
        self.assertFalse(training&{r['text'].strip().casefold() for r in self.rows})

    def test_selective_accounting(self):
        for split in ('original96','public16'):
            for lang in replay.LANGUAGES:
                subset=[r for r in self.rows if r['split']==split and r['language']==lang]
                for method in replay.METHODS:
                    totals=replay.metrics(subset,method)
                    self.assertEqual(totals['decided']+totals['review_positive']+totals['review_negative']+totals['unsupported'],len(subset))
                    if totals['status']=='UNSUPPORTED':
                        self.assertIsNone(totals['selective_error'])
                        self.assertIsNone(totals['coverage'])

    def test_model_input_invariants(self):
        event={'id':'example','event_date':'2020-03-01'}
        case={'event_id':'example','language':'en','cutoff':'2020-01-01','text':'The spacecraft has arrived.'}
        base=learned.predict(case,event)
        self.assertEqual(learned.predict(dict(case,prompt='other',gold='OTHER',id='different'),event),base)
        self.assertEqual(learned.predict(dict(case,cutoff='2020-03-01'),event)['decision'],'OTHER')
        self.assertEqual(learned.predict(dict(case,language='de'),event)['decision'],'UNSUPPORTED')
        self.assertEqual(learned.predict(dict(case,text='♟♞♝'),event)['decision'],'REVIEW')


if __name__=='__main__':
    unittest.main()
