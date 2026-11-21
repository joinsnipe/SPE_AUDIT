"""Derive a masked post-hoc worksheet without labels or rule predictions."""
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def build():
    events={r['id']:r for r in json.loads((ROOT/'holdout/events.json').read_text(encoding='utf8'))}
    cases=json.loads((ROOT/'holdout/cases.json').read_text(encoding='utf8'))
    rows=[]
    mapping={}
    for c in cases:
        key=hashlib.sha256(('spe-1.1-reader|'+c['id']).encode()).hexdigest()[:10]
        if key in mapping:
            raise ValueError('reader identifier collision')
        mapping[key]=c['id']
        e=events[c['event_id']]
        rows.append(dict(key=key,event=e['name'],event_date=e['event_date'],cutoff=c['cutoff'],
                         question=c['prompt'],answer=c['text']))
    return sorted(rows,key=lambda r:r['key']),mapping
if __name__=='__main__':
    for row in build()[0]:
        print(json.dumps(row,ensure_ascii=False))

