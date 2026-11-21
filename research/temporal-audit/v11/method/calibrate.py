"""Select and replay a small, empirical threshold. No network or third-party packages."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from proposition import predict

HERE=Path(__file__).resolve().parent
POLICY={'grid':[4,5,6,7,8],'max_observed_error':0.05,'minimum_coverage':0.4,
        'minimum_per_language_and_decision':2,
        'objective':'maximize coverage, then minimize errors, then prefer higher threshold'}
FIELDS=('id','event_id','cutoff','language','prompt','text')


def evaluate(cases,events,t):
    records=[]
    for row in cases:
        pred=predict({k:row[k] for k in FIELDS},events[row['event_id']],threshold=t)
        records.append({'id':row['id'],'language':row['language'],'stratum':row['stratum'],
                        'gold':row['gold'],'decision':pred['decision'],'score':pred['score']})
    return records


def metrics(records):
    decided=[r for r in records if r['decision']!='REVIEW']
    errors=sum(r['decision']!=r['gold'] for r in decided)
    counts=Counter((r['gold'],r['decision']) for r in records)
    return {'n':len(records),'decisions':len(decided),'errors':errors,'reviews':len(records)-len(decided),
            'coverage':len(decided)/len(records),'selective_error':errors/len(decided) if decided else None,
            'confusion':{g:{p:counts[g,p] for p in ('POST_ASSERTION','OTHER','REVIEW')} for g in ('POST_ASSERTION','OTHER')}}


def summarize(rows,field):
    return {v:metrics([r for r in rows if r[field]==v]) for v in sorted({r[field] for r in rows})}


def run():
    cases=json.loads((HERE/'calibration.json').read_text())
    events={e['id']:e for e in json.loads((HERE/'development_events.json').read_text())}
    grid=[]
    for t in POLICY['grid']:
        records=evaluate(cases,events,t)
        m=metrics(records)
        classes=Counter((r['language'],r['decision']) for r in records)
        eligible=(m['coverage']>=POLICY['minimum_coverage'] and m['selective_error'] is not None
                  and m['selective_error']<=POLICY['max_observed_error']
                  and all(classes[lang,p]>=POLICY['minimum_per_language_and_decision']
                          for lang in ('en','es') for p in ('POST_ASSERTION','OTHER')))
        grid.append(dict(threshold=t,eligible=eligible,**m))
    eligible=[r for r in grid if r['eligible']]
    if not eligible: raise ValueError('No threshold met the calibration policy.')
    winner=max(eligible,key=lambda r:(r['decisions'],-r['errors'],r['threshold']))
    t=winner['threshold']
    records=evaluate(cases,events,t)
    threshold={'threshold':t,'policy':POLICY,'calibration_sha256':hashlib.sha256((HERE/'calibration.json').read_bytes()).hexdigest()}
    report={'selection':threshold,'grid':grid,'overall':metrics(records),'language':summarize(records,'language'),
            'stratum':summarize(records,'stratum'),'records':records}
    return threshold,report


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--write',action='store_true',help='explicitly regenerate the calibration artifacts')
    args=ap.parse_args()
    threshold,report=run()
    for name,data in [('threshold.json',threshold),('calibration_report.json',report)]:
        p=HERE/name
        expected=json.dumps(data,ensure_ascii=False,indent=2)+'\n'
        if args.write:
            p.write_text(expected)
        elif p.read_text()!=expected:
            raise SystemExit(f'Calibration artifact mismatch: {name}')
    print(json.dumps({'threshold':threshold['threshold'],**report['overall']}))

if __name__=='__main__':
    main()
