"""Replay the paired historical-language controls and the inert local capture check."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
METHOD = HERE.parent / 'method'
STUDY = HERE.parents[1] / 'study'
sys.path[:0] = [str(METHOD), str(STUDY), str(STUDY / 'vendor')]
from capture import run_capture, verify_capture
from proposition import predict
from spe_engine.tvoc.detector import detect_tvoc_strong

POS, NEG, AMBIG, REVIEW = 'POST_ASSERTION', 'OTHER', 'INDETERMINATE', 'REVIEW'
DECISIONS = (POS, NEG, REVIEW)


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rate(numerator, denominator):
    return numerator / denominator if denominator else None


def summarize(records, method):
    cells = Counter((row['reference'], row['base'][method], row['variant'][method]) for row in records)
    triples = [(g, b, v, c) for (g, b, v), c in cells.items()]
    positives = sum(c for g, b, v, c in triples if g == POS)
    detected = sum(c for g, b, v, c in triples if g == POS and b == POS)
    def disposition(label):
        return cells[POS, POS, label]
    controls = sum(c for g, b, v, c in triples if g == NEG)
    ambiguous = sum(c for g, b, v, c in triples if g == AMBIG)
    def count_status(gold, phase, label):
        return sum(c for g, b, v, c in triples if g == gold and (b if phase == 'base' else v) == label)
    return {
        'pairs':len(records),'positive_pairs':positives,'detected_positive_bases':detected,
        'all_positive_variants_alerted':count_status(POS, 'variant', POS),
        'retained_alerts':disposition(POS),'changed_to_review':disposition(REVIEW),'changed_to_other':disposition(NEG),
        'conditional_alert_loss':rate(disposition(REVIEW)+disposition(NEG),detected),
        'conditional_review':rate(disposition(REVIEW),detected),'conditional_other':rate(disposition(NEG),detected),
        'control_pairs':controls,'indeterminate_pairs':ambiguous,
        'controls':{p:{d:count_status(NEG,p,d) for d in DECISIONS} for p in ('base','variant')},
        'false_alert_rates':{p:rate(count_status(NEG,p,POS),controls) for p in ('base','variant')},
        'indeterminate':{p:{d:count_status(AMBIG,p,d) for d in DECISIONS} for p in ('base','variant')},
        'transitions':[{'reference':g,'base':b,'variant':v,'n':n} for g,b,v,n in sorted(triples)]}


def mark_check():
    marker = 'EDITORIAL NOTE · INERTE'
    base = {'id':'editorial-card','date':'2020-12-01','text':'Copy desk note.', 'url':'urn:example:editorial:1'}
    later = dict(base, id='later-card', date='2021-02-18', text='Post-cutoff fixture.')
    marked = dict(base, text=base['text']+' '+marker)
    envelope = []
    def local_sender(raw):
        envelope.append(json.loads(raw))
        return 'Local fixture.'
    clean = run_capture('2020-12-31','Record the available source.',[base,later],local_sender)
    changed = run_capture('2020-12-31','Record the available source.',[marked,later],local_sender)
    left, right = envelope
    differences = {k for k in left if left[k] != right[k]}
    location = right['sources'][0]['text']
    unique = json.dumps(right, ensure_ascii=False).count(marker)==1
    same_controls = all(left[k] == right[k] for k in ('policy_id','cutoff','prompt'))
    result = {'marker':marker,'location':'sources[0].text','same_policy_cutoff_and_prompt':same_controls,
              'only_sources_changed':differences=={'sources'},'marker_at_declared_location_only':unique and location==marked['text'],
              'eligible_id_unchanged':left['sources']==[base] and right['sources']==[marked],
              'identical_output':clean['output']==changed['output'],
              'request_hash_changed':clean['request_sha256']!=changed['request_sha256'],
              'both_receipts_validate':verify_capture(clean,clean['record_sha256']) and verify_capture(changed,changed['record_sha256']),
              'sender_calls':len(envelope),'request_hashes':[clean['request_sha256'],changed['request_sha256']]}
    if not all(result[k] for k in ('same_policy_cutoff_and_prompt','only_sources_changed','marker_at_declared_location_only',
                                    'eligible_id_unchanged','identical_output','request_hash_changed','both_receipts_validate')):
        raise ValueError('The inert field did not preserve the stated local capture contract.')
    return result


def run():
    pairs=read(HERE/'pairs.json'); events={e['id']:e for e in read(METHOD/'development_events.json')}
    if len({p['id'] for p in pairs})!=len(pairs):
        raise ValueError('Duplicate pair identifier.')
    frozen={}
    for line in (METHOD/'freeze.sha256').read_text().splitlines():
        expected,name=line.split()
        if sha(METHOD/name)!=expected:
            raise ValueError('Frozen file changed: '+name)
        frozen[name]=expected
    texts=set();records=[]
    for pair in pairs:
        event=events[pair['event_id']]; lang=pair['language']
        if lang not in ('en','es') or pair['reference'] not in (POS, NEG, AMBIG) or not pair['cutoff']<event['event_date']:
            raise ValueError('Invalid reference, language or cutoff for '+pair['id'])
        record={k:pair[k] for k in ('id','event_id','language','cutoff','form','reference')}
        prompt = ('What is the status of '+event['name']+'?' if lang=='en' else '¿Cuál es el estado de '+event['name']+'?')
        for phase in ('base','variant'):
            text=pair[phase]; texts.add(text.casefold().strip())
            case={'id':pair['id']+'-'+phase,'language':lang,'event_id':event['id'],'cutoff':pair['cutoff'],'prompt':prompt,'text':text}
            year=detect_tvoc_strong(text,int(pair['cutoff'][:4]),False)
            prop=predict(case,event)
            record[phase]={'year_rule':POS if year['tvoc']=='STRONG' else NEG,'proposition':prop['decision'],
                           'detected_years':year['violating_years'],'proposition_score':prop['score'],'proposition_reason':prop['reason']}
        records.append(record)
    if len(texts)!=2*len(pairs): raise ValueError('The paired cases include duplicate sentences.')
    old_texts={r['text'].strip().casefold() for r in read(METHOD/'calibration.json')}
    for file in ('cases.json','challenge.json'):
        old_texts.update(r['output'].strip().casefold() for r in read(STUDY/'data'/file))
    methods=('year_rule','proposition')
    groups={'overall':records,**{lang:[r for r in records if r['language']==lang] for lang in ('en','es')}}
    return {'corpus_sha256':sha(HERE/'pairs.json'),'frozen_files':frozen,'year_detector_sha256':sha(STUDY/'vendor/spe_engine/tvoc/detector.py'),
            'year_extractor_sha256':sha(STUDY/'vendor/spe_engine/tvoc/extract.py'),'threshold':read(METHOD/'threshold.json')['threshold'],
            'distinct_texts':len(texts),'exact_casefolded_overlap_with_development_and_calibration':sorted(texts & old_texts),
            'sources':{k:{'event_date':v['event_date'],'source_url':v['source_url']} for k,v in events.items()},
            'groups':{g:{m:summarize(rows,m) for m in methods} for g,rows in groups.items()},
            'predictions':records,'inert_local_capture':mark_check()}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--write',action='store_true',help='Regenerate the published result and stdout fixtures')
    write=ap.parse_args().write
    result=run(); report=json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n'
    brief={m:{k:g[k] for k in ('positive_pairs','detected_positive_bases','retained_alerts','changed_to_review','changed_to_other','conditional_alert_loss','control_pairs','false_alert_rates','indeterminate_pairs')}
           for m,g in result['groups']['overall'].items()}
    stdout=json.dumps(brief,indent=2,allow_nan=False)+'\n'
    for name,txt in [('results.json',report),('stdout.json',stdout)]:
        if write: (HERE/name).write_text(txt,encoding='utf-8')
        elif (HERE/name).read_text(encoding='utf-8')!=txt: raise SystemExit('Replay mismatch: '+name)
    print(stdout,end='')

if __name__=='__main__':
    main()
