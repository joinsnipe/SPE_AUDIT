"""Replay the frozen readers on the unlabelled English cases; scoring reads the key separately."""
import argparse
import csv
import hashlib
import io
import json
from collections import Counter
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parents[1]
POS, NEG, AMB, REVIEW = 'POST_ASSERTION', 'OTHER', 'INDETERMINATE', 'REVIEW'
METHODS = ('year_rule', 'proposition', 'char_ngram_nb', 'neural_char_lm')


def table(records):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=records[0].keys(), lineterminator='\n')
    writer.writeheader()
    writer.writerows(records)
    return stream.getvalue()


def check(manifest, base):
    for line in (HERE/manifest).read_text().splitlines():
        digest, name = line.split('  ', 1)
        if hashlib.sha256((base/name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'Changed input: {name}')


def read(name):
    return json.loads((HERE/name).read_text())


def indexed(records):
    by_id = {r['id']: r for r in records}
    if len(records) != len(by_id):
        raise ValueError('Repeated ID')
    return by_id


def predict_all():
    check('inputs.sha256', HERE)
    check('readers.sha256', RESEARCH)
    sys.path.insert(0, str(RESEARCH/'v11/languages'))
    sys.path.insert(0, str(RESEARCH/'v11/local_model'))
    from local_model import predict as neural
    from replay_languages import predict_all as frozen_predict
    cases, events, sources = map(lambda n: indexed(read(n)), ('cases.json', 'events.json', 'source_index.json'))
    if cases.keys() != sources.keys():
        raise ValueError('Incomplete source inventory')
    rows = []
    for key, case in cases.items():
        event = events[case['event_id']]
        if case['language'] != 'en' or not 0 < len(case['text'].split()) <= 18:
            raise ValueError('Language or excerpt length outside design')
        results = frozen_predict(case, event)
        results['neural_char_lm'] = neural(case, event)
        for method in METHODS:
            result = results[method]
            rows.append(dict(id=key, event_id=event['id'], method=method, decision=result['decision'],
                             reason=result['reason'], score=result.get('score', result.get('margin', ''))))
    return rows


def fraction(a, b):
    return {'numerator':a, 'denominator':b, 'rate':a / b if b else None}


def score(rows):
    check('reference.sha256', HERE)
    labels = indexed(read('labels.json'))
    if {r['id'] for r in rows} != labels.keys():
        raise ValueError('Missing reference or prediction')
    results = {}
    for method in METHODS:
        method_rows = [r for r in rows if r['method'] == method]
        if len(labels) != len(indexed(method_rows)):
            raise ValueError('Missing or duplicate prediction')
        c = Counter((labels[r['id']]['gold'],r['decision']) for r in method_rows)
        confusion = {g:{p:c[g,p] for p in (POS,NEG,REVIEW)} for g in (POS,NEG,AMB)}
        tp, fp, tn, fn = c[POS,POS], c[NEG,POS], c[NEG,NEG], c[POS,NEG]
        decided = tp+fp+tn+fn
        determinate = decided+c[POS,REVIEW]+c[NEG,REVIEW]
        ambiguous = sum(confusion[AMB].values())
        n = len(method_rows)
        if determinate+ambiguous != n:
            raise ValueError('Class outside the scoring design')
        results[method] = dict(n=n, confusion=confusion, determinate=determinate,
             coverage_all=fraction(n-sum(c[g,REVIEW] for g in (POS,NEG,AMB)),n),
             coverage_determinate=fraction(decided,determinate),
             selective_error_determinate=fraction(fp+fn,decided),
             alert_precision_determinate=fraction(tp,tp+fp),
             alerts_over_all_reference_positives=fraction(tp,sum(confusion[POS].values())),
             decisions_on_ambiguous=fraction(ambiguous-c[AMB,REVIEW],ambiguous))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--predictions-only',action='store_true',help='Do not open reference labels.')
    parser.add_argument('--check', action='store_true', help='Verify byte-identical replay outputs without rewriting.')
    args = parser.parse_args()
    rows = predict_all()
    outputs = {'predictions.csv':table(rows)}
    if not args.predictions_only:
        outputs['results.json'] = json.dumps(score(rows),ensure_ascii=False,indent=2)+'\n'
    for name,contents in outputs.items():
        path = HERE/name
        if args.check:
            if path.read_bytes() != contents.encode():
                raise ValueError(f'Replay mismatch: {name}')
        else:
            path.write_bytes(contents.encode())
    print(f'{len(rows)} decisions across {len(METHODS)} frozen readers')


if __name__ == '__main__':
    main()
