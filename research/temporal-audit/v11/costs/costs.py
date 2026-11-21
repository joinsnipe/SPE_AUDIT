"""Illustrative asymmetric decision costs on frozen data. Standard library only."""
import argparse
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'method'))
from proposition import predict

POLICIES={
    'administration':dict(false_alert=12,miss=25,refer=1,auto_ambiguous=14,max_referral=None),
    'service':dict(false_alert=4,miss=5,refer=2,auto_ambiguous=3,max_referral=.20),
}

def read(path):
    return json.loads(path.read_text(encoding='utf8'))

def counts(pairs):
    out=dict(n=len(pairs),false_alert=0,miss=0,refer=0,auto_ambiguous=0)
    for gold,choice in pairs:
        if choice=='REVIEW': out['refer']+=1
        elif gold=='INDETERMINATE': out['auto_ambiguous']+=1
        elif gold=='POST_ASSERTION' and choice=='OTHER': out['miss']+=1
        elif gold=='OTHER' and choice=='POST_ASSERTION': out['false_alert']+=1
    return out

def loss(c,p):
    return sum(c[k]*p[k] for k in ['false_alert','miss','refer','auto_ambiguous'])

def cohort(items,events,labels):
    candidates={}
    for threshold in range(2,9):
        decisions=[predict(c,events[c['event_id']],threshold=threshold)['decision'] for c in items]
        candidates[str(threshold)]=counts([(labels[c['id']],p) for c,p in zip(items,decisions)])
    candidates['review_all']=counts([(labels[c['id']],'REVIEW') for c in items])
    return candidates

def permitted(x,p):
    return p['max_referral'] is None or x['refer']/x['n'] <= p['max_referral']

def calculate():
    cal=read(ROOT/'method/calibration.json')
    dev={c['id']:c for c in read(ROOT/'method/development_events.json')}
    calibration=cohort(cal,dev,{c['id']:c['gold'] for c in cal})
    selections={}
    for name,p in POLICIES.items():
        feasible=[key for key,x in calibration.items() if permitted(x,p)]
        # Prefer the higher evidence threshold when costs tie; review-all ranks last on a tie.
        priority=lambda key:(loss(calibration[key],p),-int(key) if key.isdigit() else 1)
        selections[name]=(min(feasible,key=priority) if feasible else None)
    new=read(ROOT/'holdout/cases.json')
    future_events={e['id']:e for e in read(ROOT/'holdout/events.json')}
    test=cohort(new,future_events,read(ROOT/'holdout/labels.json'))
    result={}
    for name,p in POLICIES.items():
        key=selections[name]
        result[name]=dict(weights=p,selected_on_calibration=key,
           calibration_counts=calibration.get(key),test_counts=test.get(key),
           test_cost_units=loss(test[key],p) if key else None,
           test_within_referral_budget=permitted(test[key],p) if key else None,
           heldout_costs_by_threshold={k:dict(loss=loss(v,p),within_budget=permitted(v,p),counts=v) for k,v in test.items()})
    return result

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True)
    ap.parse_args().out.write_bytes((json.dumps(calculate(),indent=2,sort_keys=True)+'\n').encode())

