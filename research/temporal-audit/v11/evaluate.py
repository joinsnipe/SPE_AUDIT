"""Evaluate the fixed proposition rule, retaining abstentions and ambiguous references."""
import argparse
import csv
import hashlib
import io
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
V1 = ROOT.parent / 'study'
sys.path.insert(0, str(V1 / 'vendor'))
sys.path.insert(0, str(V1))
sys.path.insert(0, str(ROOT / 'method'))
from matcher import classify as november
from spe_engine.tvoc.detector import detect_tvoc_strong

GOLD = ('POST_ASSERTION', 'OTHER', 'INDETERMINATE')
CALLED = ('POST_ASSERTION', 'OTHER', 'REVIEW')

def read(p):
    return json.loads(p.read_text(encoding='utf-8'))

def serial(x):
    return (json.dumps(x, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()

def digest(b):
    return hashlib.sha256(b).hexdigest()

def ratio(n, d):
    return n/d if d else None

def metrics(pairs):
    cells = Counter(pairs)
    if any(g not in GOLD or p not in CALLED for g,p in cells):
        raise ValueError('unknown reference state or decision')
    m = {g:{p:cells[g,p] for p in CALLED} for g in GOLD}
    pos,neg,amb=(m[g] for g in GOLD)
    tp,fp=pos[CALLED[0]],neg[CALLED[0]]
    n=sum(cells.values())
    review=sum(row['REVIEW'] for row in m.values())
    determinate_calls=sum(pos.values())+sum(neg.values())-pos['REVIEW']-neg['REVIEW']
    return dict(n=n, confusion=m, alerts_determinate=tp+fp, referred=review,
        coverage=ratio(n-review,n),referral_rate=ratio(review,n),
        sensitivity=ratio(tp,sum(pos.values())),precision_determinate=ratio(tp,tp+fp),
        selective_error_determinate=ratio(fp+pos['OTHER'],determinate_calls),
        automatic_on_indeterminate=sum(amb.values())-amb['REVIEW'],
        alerts_on_indeterminate=amb['POST_ASSERTION'])

def require_unique(items):
    result = {i['id']:i for i in items}
    if len(result)!=len(items):
        raise ValueError('duplicate identifier')
    return result

def classify_all(predict):
    known_events=require_unique(read(ROOT/'method/development_events.json'))
    old_events=require_unique(read(V1/'data/events.json'))
    new_events=require_unique(read(ROOT/'holdout/events.json'))
    rows=[]
    for group,filename in [('constructed','cases.json'),('old_challenge','challenge.json'),('new_challenge','cases.json')]:
        old=group!='new_challenge'
        cases=read((V1/'data' if old else ROOT/'holdout')/filename)
        for original in cases:
            c=dict(id=original['id'],event_id=original['event'],cutoff=original['cutoff'],
                   language='en',prompt=original['prompt'],text=original['output']) if old else original
            event=(known_events if old else new_events)[c['event_id']]
            explanation=predict(c,event)
            decision=explanation['decision']
            if decision not in CALLED:
                raise ValueError('invalid method decision')
            year=detect_tvoc_strong(c['text'],int(c['cutoff'][:4]),False)
            choices={'year_rule':CALLED[0] if year['tvoc']=='STRONG' else 'OTHER','proposition':decision}
            if old:
                choices['matcher_v1']=november(c['text'],c['cutoff'],old_events[c['event_id']])
            rows.append(dict(group=group,id=c['id'],event_id=c['event_id'],language=c['language'],cutoff=c['cutoff'],
                             choices=choices,explanation=explanation))
    require_unique(rows)
    return rows

def evaluate(destination):
    from proposition import predict
    destination.mkdir(parents=True,exist_ok=True)
    records=classify_all(predict)
    raw=b''.join((json.dumps(r,ensure_ascii=False,sort_keys=True,allow_nan=False)+'\n').encode() for r in records)
    (destination/'predictions.jsonl').write_bytes(raw)
    labels={}
    for file in [V1/'data/labels.json',V1/'data/challenge_labels.json',ROOT/'holdout/labels.json']:
        block=read(file)
        if labels.keys() & block.keys():
            raise ValueError('reference ids collide')
        labels.update({k:v['label'] if isinstance(v,dict) else v for k,v in block.items()})
    if set(labels)!={r['id'] for r in records}:
        raise ValueError('reference and prediction ids differ')
    subsets={}
    buffer=io.StringIO(newline='')
    writer=csv.writer(buffer,lineterminator='\n')
    writer.writerow(['group','id','event_id','language','reference','year_rule','matcher_v1','proposition'])
    for r in records:
        gold=labels[r['id']]
        writer.writerow([r['group'],r['id'],r['event_id'],r['language'],gold,r['choices']['year_rule'],
                         r['choices'].get('matcher_v1',''),r['choices']['proposition']])
        keys=[r['group']]
        if r['group']=='new_challenge':
            keys+=['by_language/'+r['language'],'by_event/'+r['event_id']]
        for key in keys:
            for method,decision in r['choices'].items():
                subsets.setdefault(key,{}).setdefault(method,[]).append((gold,decision))
    (destination/'decisions.csv').write_bytes(buffer.getvalue().encode())
    results={k:{method:metrics(pairs) for method,pairs in v.items()} for k,v in subsets.items()}
    (destination/'metrics.json').write_bytes(serial(dict(predictions_sha256=digest(raw),groups=results)))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    evaluate(parser.parse_args().out)

