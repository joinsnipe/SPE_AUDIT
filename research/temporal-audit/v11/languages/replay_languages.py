"""Replay four aligned languages with a shared registered event and unchanged text rules."""
import argparse
from collections import Counter
import csv
import io
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
STUDY=HERE.parent.parent/'study'
DATA=STUDY/'data'
sys.path.insert(0,str(STUDY/'vendor'))
sys.path.insert(0,str(HERE.parent/'method'))
from spe_engine.tvoc.detector import detect_tvoc_strong
from spe_engine.tvoc.extract import extract_years
from proposition import predict as proposition_predict
from small_baseline import predict as learned_predict

POS='POST_ASSERTION'
NEG='OTHER'
METHODS=('year_rule','proposition','char_ngram_nb')
LANGUAGES={'en':None,'es':'spanish.json','fr':'french.json','de':'german.json'}


def read(path):
    return json.loads(path.read_text())


def translations(original,path):
    base=[{'id':c['id'],'prompt':c['prompt'],'text':c['output']} for c in original]
    translated=base if path is None else read(path)
    if [r['id'] for r in translated]!=[r['id'] for r in base]:
        raise ValueError(f'Translation ID/order mismatch: {path}')
    if len({r['id'] for r in translated})!=len(base):
        raise ValueError('Duplicate source or translation identifier')
    for source,row in zip(base,translated):
        for key in ['prompt','text']:
            if not isinstance(row.get(key),str) or not row[key].strip() or extract_years(source[key])!=extract_years(row[key]):
                raise ValueError(f'Translation text or year mismatch: {path} {row["id"]} {key}')
    return {r['id']:r for r in translated}


def predict_all(case,event):
    cut_year=int(case['cutoff'][:4])
    year=detect_tvoc_strong(case['text'],cut_year,False)
    prop=(proposition_predict(case,event) if case['language'] in ('en','es') else
          {'decision':'UNSUPPORTED','reason':'proposition_rules_cover_EN_ES_only','clauses':[]})
    nb=learned_predict(case,event)
    return {'year_rule':{'decision':POS if year['tvoc']=='STRONG' else NEG,
                         'reason':'explicit_future_year' if year['violating_years'] else 'no_explicit_future_year',
                         'extracted_years':extract_years(case['text']),'violating_years':year['violating_years']},
            'proposition':prop,'char_ngram_nb':nb}


def metrics(rows,method):
    cells=Counter((r['gold'],r['methods'][method]['decision']) for r in rows)
    tp=cells[POS,POS]; fp=cells[NEG,POS]; tn=cells[NEG,NEG]; fn=cells[POS,NEG]
    covered=tp+fp+tn+fn
    rp,rn=cells[POS,'REVIEW'],cells[NEG,'REVIEW']
    unsupported=cells[POS,'UNSUPPORTED']+cells[NEG,'UNSUPPORTED']
    assert covered+rp+rn+unsupported==len(rows)
    return {'n':len(rows),'status':'UNSUPPORTED' if unsupported==len(rows) else 'EVALUATED',
            'decided':covered,'errors':fp+fn if covered else None,'tp':tp,'fp':fp,'tn':tn,'fn':fn,
            'review_positive':rp,'review_negative':rn,'unsupported':unsupported,
            'coverage':covered/(len(rows)-unsupported) if len(rows)>unsupported else None,
            'selective_error':(fp+fn)/covered if covered else None}


def build():
    originals={split:read(DATA/file) for split,file in [('original96','cases.json'),('public16','challenge.json')]}
    all_cases=[r for cases in originals.values() for r in cases]
    events={r['id']:r for r in read(HERE.parent/'method'/'development_events.json')}
    frozen_sources={r['id']:r['sources'] for r in read(DATA/'events.json')}
    records=[]
    for lang,filename in LANGUAGES.items():
        variants=translations(all_cases,HERE/filename if filename else None)
        for split,cases in originals.items():
            for original in cases:
                key=original['id']
                event=events[original['event']]
                variant=variants[key]
                case=dict(id=key,event_id=event['id'],cutoff=original['cutoff'],language=lang,
                          prompt=variant['prompt'],text=variant['text'])
                # Same frozen source eligibility as the English study. The registered outcome date
                # and outcome source are retrospective auditor inputs, independent of this filter.
                eligible=[s for s in frozen_sources[event['id']] if s['date']<=case['cutoff']]
                predictions=predict_all(case,event)
                records.append(dict(**case,split=split,registered_subject=event['name'],
                                    registered_event_date=event['event_date'],outcome_terms=event['outcome_terms'],
                                    retrospective_source=event['source_url'],eligible_card_ids=[s['id'] for s in eligible],
                                    methods=predictions))
    labels=dict(read(DATA/'labels.json'),**read(DATA/'challenge_labels.json'))
    for row in records:
        label=labels[row['id']]
        row.update(gold=label['label'],reference_stance=label['form'])
    summary=[]
    for split in originals:
        for lang in LANGUAGES:
            group=[r for r in records if r['split']==split and r['language']==lang]
            for method in METHODS:
                summary.append(dict(split=split,language=lang,method=method,**metrics(group,method)))
    matrix=io.StringIO(newline='')
    writer=csv.DictWriter(matrix,fieldnames=list(summary[0]),lineterminator='\n')
    writer.writeheader()
    writer.writerows(summary)
    evidence=''.join(json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n' for row in records)
    return {'language_matrix.csv':matrix.getvalue(),'language_evidence.jsonl':evidence}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--write',action='store_true',help='regenerate stored analysis outputs')
    args=parser.parse_args()
    for name,generated in build().items():
        path=HERE/name
        if args.write: path.write_text(generated)
        elif path.read_text()!=generated: raise SystemExit(f'Replay mismatch: {name}')
    print('112 prompts and outputs × 4 languages, 24 split/language/method groups.')


if __name__=='__main__':
    main()
