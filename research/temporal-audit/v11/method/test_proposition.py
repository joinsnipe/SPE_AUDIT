"""Contract, scope and replay tests, independent of any new challenge."""
import hashlib
import json
from pathlib import Path
import unittest

from calibrate import run
from proposition import predict

HERE=Path(__file__).resolve().parent
EVENT={'id':'festival','name':'Marea','aliases':['Festival Marea'],'event_date':'2024-05-02',
       'outcome_terms':['opened the festival','opened','abrió el festival','inauguró'],
       'source_url':'urn:example:method-test'}


class TestProposition(unittest.TestCase):
    def case(self,text,lang='en',**changes):
        row=dict(id='unit',event_id='festival',cutoff='2024-04-01',language=lang,
                 prompt='What can be said of Marea?',text=text)
        row.update(changes)
        return row

    def decision(self,text,**kwargs):
        return predict(self.case(text,**kwargs),EVENT)['decision']

    def test_exact_assertion_in_two_languages(self):
        self.assertEqual(self.decision('Marea opened the festival.'),'POST_ASSERTION')
        self.assertEqual(self.decision('Marea inauguró el festival.',lang='es'),'POST_ASSERTION')

    def test_negatives_and_predicate_inside_question(self):
        for text in ['Marea did not open the festival.','Did Marea open the festival?',
                     'The question asks whether Marea opened the festival.']:
            self.assertEqual(self.decision(text),'OTHER')
        self.assertEqual(self.decision('Marea no inauguró el festival.',lang='es'),'OTHER')

    def test_forecast_and_counterfactual(self):
        self.assertEqual(self.decision('Marea might open the festival.'),'OTHER')
        self.assertEqual(self.decision('Had Marea opened the festival, we could celebrate.'),'OTHER')
        self.assertEqual(self.decision('Marea inaugurará el festival.',lang='es'),'OTHER')

    def test_aliases_are_whole_words(self):
        self.assertEqual(self.decision('Mareana opened.'),'REVIEW')

    def test_mixed_assertion_overrides_forecast_in_other_clause(self):
        self.assertEqual(self.decision('The festival may be postponed, but Marea opened the festival.'),'POST_ASSERTION')
        self.assertEqual(self.decision('Marea inauguró el festival. El concierto podría demorarse.',lang='es'),'POST_ASSERTION')

    def test_quotation_and_endorsement(self):
        self.assertEqual(self.decision('The sketch read “Marea opened the festival”.'),'REVIEW')
        self.assertEqual(self.decision('The example headline is “Marea opened the festival”.'),'OTHER')
        self.assertEqual(self.decision('Marea opened the festival. That was false.'),'REVIEW')

    def test_unresolved_referents_and_unrelated_text(self):
        self.assertEqual(self.decision('Another team opened the festival near Marea.'),'REVIEW')
        self.assertEqual(self.decision('Several witnesses went home.'),'REVIEW')

    def test_prompt_alone_cannot_supply_a_positive(self):
        self.assertEqual(self.decision('The records are incomplete.',prompt='Marea opened the festival?'),'REVIEW')

    def test_threshold_and_trace(self):
        case=self.case('Marea opened the festival.')
        result=predict(case,EVENT)
        self.assertTrue(result['clauses'][0]['outcome_term'])
        self.assertIn('explicit_referent',result['clauses'][0]['signals'])
        self.assertEqual(predict(case,EVENT,threshold=8)['decision'],'REVIEW')

    def test_event_date_is_inclusive(self):
        self.assertEqual(self.decision('Marea opened the festival.',cutoff='2024-05-02'),'OTHER')

    def test_invalid_language_dates_and_event(self):
        for changes in [{'cutoff':'invalid'}, {'language':'fr'}, {'event_id':'other'}]:
            self.assertEqual(self.decision('Marea opened the festival.',**changes),'REVIEW')
        self.assertEqual(self.decision(''),'REVIEW')

    def test_calibration_selection_and_file_integrity(self):
        threshold,report=run()
        self.assertEqual(threshold,json.loads((HERE/'threshold.json').read_text()))
        self.assertEqual(report,json.loads((HERE/'calibration_report.json').read_text()))
        for line in (HERE/'freeze.sha256').read_text().splitlines():
            digest,name=line.split()
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest,name)


if __name__=='__main__':
    unittest.main()
