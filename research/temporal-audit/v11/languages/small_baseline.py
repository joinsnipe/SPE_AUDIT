"""Small supervised baseline: bilingual character n-gram multinomial naive Bayes."""
from collections import Counter
from datetime import date
from functools import lru_cache
import hashlib
import json
from math import log
from pathlib import Path
import re
import unicodedata

HERE=Path(__file__).resolve().parent
CALIBRATION=HERE.parent/'method'/'calibration.json'
EVENTS=HERE.parent/'method'/'development_events.json'
EXPECTED_CAL='c642b9739f6b05a7b5544aadb6bac1923eff97fe2b7f68a9cfbcf7e04512750f'
EXPECTED_EVENTS='a580345fc98ebe6cc324dca0672da12fe46899193e1035e06a5ec4bd835a913c'
POS='POST_ASSERTION'
NEG='OTHER'


def grams(text):
    value=unicodedata.normalize('NFKC',text).casefold()
    value=re.sub(r'\d+','#',value)
    value=' '+' '.join(value.split())+' '
    return Counter(value[i:i+size] for size in (3,4,5)
                   for i in range(len(value)-size+1))


def read_pinned(path,expected):
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError(f'Training input changed: {path.name}')
    return json.loads(raw)


@lru_cache(maxsize=1)
def model():
    events={e['id']:e for e in read_pinned(EVENTS,EXPECTED_EVENTS)}
    examples=read_pinned(CALIBRATION,EXPECTED_CAL)
    counts={POS:Counter(),NEG:Counter()}
    documents=Counter()
    ids=[]
    for case in examples:
        if date.fromisoformat(events[case['event_id']]['event_date'])<=date.fromisoformat(case['cutoff']):
            continue
        label=case['gold']
        counts[label].update(grams(case['text']))
        documents[label]+=1
        ids.append(case['id'])
    vocab=sorted(set(counts[POS])|set(counts[NEG]))
    # Add-one smoothing, with the empirical document prior and shared vocabulary.
    log_odds={}
    positive_total=counts[POS].total()+len(vocab)
    other_total=counts[NEG].total()+len(vocab)
    for feature in vocab:
        log_odds[feature]=log((counts[POS][feature]+1)/positive_total)-log((counts[NEG][feature]+1)/other_total)
    prior=log(documents[POS]/documents[NEG])
    return log_odds,prior,{'algorithm':'multinomial_naive_bayes_char_3_4_5',
                           'training_ids':ids,'training_counts':dict(documents),
                           'vocabulary_size':len(vocab),'calibration_sha256':EXPECTED_CAL,
                           'event_dictionary_sha256':EXPECTED_EVENTS,
                           'decision_boundary':'margin > 0; tie goes to OTHER'}


def predict(case,event):
    """Study contract. No evaluation labels, model downloads or network access."""
    def result(decision,reason,margin=None,features=None):
        return {'decision':decision,'reason':reason,'margin':margin,'features':features or []}
    if case.get('language') not in {'en','es'}:
        return result('UNSUPPORTED','no_EN_ES_training_support')
    if case.get('event_id')!=event.get('id') or not isinstance(case.get('text'),str) or not case['text'].strip():
        return result('REVIEW','missing_output_or_event_mismatch')
    try:
        happened=date.fromisoformat(event['event_date'])
        cutoff=date.fromisoformat(case['cutoff'])
    except (KeyError,TypeError,ValueError):
        return result('REVIEW','invalid_day')
    if happened<=cutoff:
        return result(NEG,'registered_event_on_or_before_cutoff')
    odds,prior,_=model()
    contributions={key:freq*odds[key] for key,freq in grams(case['text']).items() if key in odds}
    if not contributions:
        return result('REVIEW','no_known_ngram')
    margin=prior+sum(contributions.values())
    ranked=sorted(contributions.items(),key=lambda kv:(-abs(kv[1]),kv[0]))[:3]
    return result(POS if margin>0 else NEG,'character_ngram_margin',round(margin,6),
                  [{'ngram':key,'signed_contribution':round(value,6)} for key,value in ranked])


if __name__=='__main__':
    print(json.dumps(model()[2],indent=2))
