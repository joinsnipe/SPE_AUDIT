"""Score an archived blinded reading. Does not call or emulate a language model."""
import argparse
import csv
import json
import sys
from pathlib import Path
from worksheet import build, ROOT
sys.path.insert(0,str(ROOT))
from evaluate import metrics, serial

def score(answers_path, decisions_path):
    rows,ids=build()
    answers=json.loads(answers_path.read_text(encoding='utf8'))
    if len(answers)!=len(ids) or {r['key'] for r in answers}!=set(ids):
        raise ValueError('missing, duplicate or unmatched masked reader decisions')
    refs=json.loads((ROOT/'holdout/labels.json').read_text(encoding='utf8'))
    cases={x['id']:x for x in json.loads((ROOT/'holdout/cases.json').read_text(encoding='utf8'))}
    groups={}
    with decisions_path.open(encoding='utf8',newline='') as f:
        rule={r['id']:r['proposition'] for r in csv.DictReader(f) if r['group']=='new_challenge'}
    if set(rule)!=set(refs):
        raise ValueError('rule routing outputs missing or unmatched')
    for row in sorted(answers,key=lambda r:r['key']):
        if not row.get('rationale','').strip():
            raise ValueError('missing rationale')
        case_id=ids[row['key']]
        case=cases[case_id]
        routed=row['decision'] if rule[case_id]=='REVIEW' else rule[case_id]
        groups.setdefault('exploratory_cascade',[]).append((refs[case_id],routed))
        for key in ['all','by_language/'+case['language'],'by_event/'+case['event_id']]:
            groups.setdefault(key,[]).append((refs[case_id],row['decision']))
    return {k:metrics(v) for k,v in groups.items()}
if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--answers',type=Path,default=ROOT/'reader/answers.json')
    ap.add_argument('--decisions',type=Path,default=ROOT/'results/decisions.csv')
    args=ap.parse_args()
    args.out.write_bytes(serial(score(args.answers,args.decisions)))

