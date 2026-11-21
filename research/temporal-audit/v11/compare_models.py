"""Replay frozen learned comparators on translations and the new held-out events."""
import argparse
import csv
import hashlib
import io
import json
import sys
from pathlib import Path
from evaluate import metrics, read, serial
ROOT=Path(__file__).resolve().parent
V1=ROOT.parent/'study'/'data'
sys.path.insert(0,str(ROOT/'languages'))
sys.path.insert(0,str(ROOT/'local_model'))
from small_baseline import predict as bayes
from local_model import predict as neural

def compare(destination):
    required={'local_model/local_model.py':'18e2538f98b8887f8b824e0b07e7d40131451b570cb72cbc0f71f069896ebf30',
              'local_model/weights.json':'8f444d23138b39c16a2bce1ada44f17cc971c296ed6bb7fa04c4be7f8f6897e2',
              'languages/small_baseline.py':'be5b953d5756fe673ea17070a3fe53505d8f2104254f249ff48e72b242215d1c'}
    for path,sha in required.items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=sha:
            raise ValueError(f'changed frozen comparator: {path}')
    events={r['id']:r for r in read(ROOT/'method/development_events.json')+read(ROOT/'holdout/events.json')}
    ids={}
    rows=[]
    for group,name,goldfile in [('known96','cases','labels'),('known16','challenge','challenge_labels')]:
        texts=read(V1/(name+'.json'));gold=read(V1/(goldfile+'.json'))
        for t in texts:
            c=dict(id=t['id'],event_id=t['event'],cutoff=t['cutoff'],language='en',prompt=t['prompt'],text=t['output'])
            ids[c['id']]=(group,c,gold[c['id']]['label'])
            rows.append(ids[c['id']])
    for lang,name in [('es','spanish'),('fr','french'),('de','german')]:
        translated=read(ROOT/'languages'/(name+'.json'))
        if len(translated)!=len(ids) or {x['id'] for x in translated}!=set(ids):
            raise ValueError('translation rows mismatch')
        for t in translated:
            group,base,gold=ids[t['id']]
            rows.append((group,dict(base,language=lang,prompt=t['prompt'],text=t['text']),gold))
    gold=read(ROOT/'holdout/labels.json')
    rows.extend(('new48',c,gold[c['id']]) for c in read(ROOT/'holdout/cases.json'))
    groups={}; trace=[]
    for group,c,g in rows:
        for name,method in [('neural',neural),('ngram_nb',bayes)]:
            pred=method(c,events[c['event_id']])
            p=pred['decision']
            trace.append(dict(group=group,id=c['id'],language=c['language'],method=name,reference=g,prediction=pred))
            if p=='UNSUPPORTED':continue
            for marker in ([group+'/'+c['language'],group+'/all'] if group=='new48' else [group+'/'+c['language']]):
                groups.setdefault(marker,{}).setdefault(name,[]).append((g,p))
    destination.mkdir(parents=True,exist_ok=True)
    (destination/'learned_metrics.json').write_bytes(serial({k:{m:metrics(p) for m,p in v.items()} for k,v in groups.items()}))
    (destination/'learned_traces.jsonl').write_bytes(b''.join((json.dumps(r,ensure_ascii=False,sort_keys=True,allow_nan=False)+'\n').encode() for r in trace))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    compare(p.parse_args().out)

