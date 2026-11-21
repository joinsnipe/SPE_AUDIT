"""Selective proposition matcher for a single registered event. Python 3.10+."""
from datetime import date
from functools import lru_cache
import json
from pathlib import Path
import re
import unicodedata


def normalized(text):
    """Preserve word/quotation boundaries while ignoring accents and case."""
    text = text.casefold().replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    return ''.join(ch for ch in unicodedata.normalize('NFKD', text)
                   if not unicodedata.combining(ch))


def words(text):
    return re.findall(r"[a-z0-9]+", normalized(text))


def has_phrase(tokens, phrase):
    return bool(phrase) and any(tokens[i:i+len(phrase)] == phrase for i in range(len(tokens)))


# Small bilingual morphology only. Synonyms belong in the published event dictionary.
IRREGULAR = {
    'won':'win','winning':'win','held':'hold','made':'make','took':'take','taken':'take',
    'went':'go','gone':'go','began':'begin','begun':'begin','built':'build','broke':'break',
    'broken':'break','hit':'hit','struck':'strike','woke':'wake','woken':'wake','rose':'rise',
    'risen':'rise','sent':'send','came':'come','fallen':'fall','fell':'fall','met':'meet',
    'signed':'sign','closed':'close','used':'use','released':'release','reached':'reach',
    'opened':'open','landed':'land','returned':'return','delivered':'deliver',
    'fue':'ser','fueron':'ser','hizo':'hacer','hicieron':'hacer','hecho':'hacer',
    'obtuvo':'obtener','obtenido':'obtener','puso':'poner','puesto':'poner','dio':'dar',
    'tuvo':'tener','llego':'llegar','llegada':'llegar','volvio':'volver','vuelto':'volver',
    'recibio':'recibir','abierto':'abrir','abierta':'abrir','abrio':'abrir',
}
STOP = set('a an the of in on at into by for to as from its their that have had has was were is are el la las los un una unos unas de del en al a por para con se su sus ha han fue fueron es y and'.split())


def root(w, lang):
    w = IRREGULAR.get(w, w)
    if lang == 'es':
        for end in ('amientos','imiento','aciones','acion','ieron','aron','ados','adas','idos','idas','ado','ada','ido','ida','ar','er','ir'):
            if w.endswith(end) and len(w)-len(end)>=3:
                return w[:-len(end)]
        if len(w)>3 and w.endswith(('io','o')):
            return w[:-2] if w.endswith('io') else w[:-1]
    else:
        if w.endswith('ied') and len(w)>4:
            return w[:-3]+'y'
        for end in ('ing','ed','es','s'):
            if w.endswith(end) and len(w)-len(end)>=3:
                return w[:-len(end)]
    return w


def phrase_strength(tokens, terms, lang):
    """2 = contiguous phrase, 1 = content stems in order at gaps of at most two words."""
    best = (0, '')
    stems = [root(w,lang) for w in tokens]
    for term in terms:
        raw = words(term)
        if has_phrase(tokens,raw) and len(raw)>len(words(best[1])):
            best = (2, term)
            continue
        wanted = [root(w,lang) for w in raw if w not in STOP]
        if not wanted or best[0]==2:
            continue
        for start,x in enumerate(stems):
            if x!=wanted[0]:
                continue
            end=start
            for key in wanted[1:]:
                try:
                    end=stems.index(key,end+1,end+4)
                except ValueError:
                    break
            else:
                if not best[0] or len(raw)>len(words(best[1])):
                    best=(1,term)
                break
    return best


CLAUSE = re.compile(r"(?<=[.?!;])(?:[\u2019\u201d\u00bb\x22']*)\s+|\s*;\s*|\s*,?\s+\b(?:but|however|nevertheless|yet in fact|pero|sin embargo|no obstante|en cambio)\b\s*,?\s*",re.I)
QUESTION = re.compile(r"\b(?:the question (?:asks|is)|the question was|asked whether|asks whether|se pregunta si|pregunta (?:si|es)|pregunto si|la pregunta dice)\b")
NEGATION = re.compile(r"\b(?:no (?:confirmation|evidence|record|proof|sign|indication)|there is (?:still )?no|hasn.t|hadn.t|didn.t|did not|has not|have not|had not|never|not yet|had yet to|has yet to|not (?:confirmed|established|known|occurred)|failed to|unconfirmed|cannot (?:confirm|tell|establish|be established|say)|can.t (?:confirm|say)|cannot conclude|premature|ahead of the evidence|unclear whether|unknown whether|sin (?:pruebas|evidencia|confirmacion|constancia)|se desconoce|no (?:confirma|confirmamos|hay|consta|se ha|esta confirmado|puede|podemos|ocurrio|llego|fue|ha|hubo|sucedio)|aun no|todavia no|nunca|ni siquiera|no se (?:puede|sabe|confirmo)|no esta claro|seria prematuro)\b")
FORECAST = re.compile(r"\b(?:if|unless|could|would|might|may|will|should|going to|possible|possibly|probably|potentially|expected|scheduled|forecast|predict(?:ed|ion)?|planned|plans? to|plan calls for|hopes? to|aims? to|intends? to|set to|yet to|not due|unlikely|speculat\w*|si|quizas?|tal vez|podria[n]?|puede que|es posible|se espera|espera que|se preve|esta previst[oa]|estaba previst[oa]|se planea|pronostico|prevision|objetivo es|deberia[n]?|en caso de|ojala|probablemente|esperan|tiene previsto)\b")
SPANISH_FUTURE = re.compile(r"\b[a-záéíóúñ]{3,}(?:ará|erá|irá|arán|erán|irán|aría|ería|iría|arían|erían|irían)\b",re.I)
QUOTED = re.compile(r"""["«»]|(?:^|\s)'[^']+'""")
ATTRIBUTED = re.compile(r"\b(?:says?|said|wrote|quoted|claims?|alleged|according to|reported|the phrase|the headline|the words|hypothetical|rumou?r|cita|citado|dijo|dice|escribio|segun|titular|la frase|afirma|alega|rumor)\b")
COUNTERFACTUAL = re.compile(r"^(?:had\b|were\b|suppose\b|imagine\b|supongamos\b|imaginemos\b)|\b(?:habria|hubiera|hubiese)\b")
METALANGUAGE = re.compile(r"\b(?:the example|sample wording|example headline|example sentence|the words|the phrase|as an example|la frase|el ejemplo|como ejemplo|ejemplo de titular|el enunciado|borrador|hypothetical headline|possible headline)\b")
ANAPHOR = re.compile(r"\b(?:it (?:did so|happened)|that (?:happened|occurred)|which it did|so it did|asi (?:fue|ocurrio)|lo (?:hizo|consiguio)|eso (?:sucedio|ocurrio))\b")
EXPLICIT = re.compile(r"\b(?:indeed|in fact|actually|confirmed|confirmo|efectivamente|de hecho|ya|finalmente|already)\b")
REFERENCE = re.compile(r"\b(?:it|the mission|the team|the spacecraft|the vessel|the probe|the rover|the project|the event|the agency|this|la mision|el equipo|la nave|la sonda|el proyecto|el suceso|este|esta)\b")
ASYMMETRIC = re.compile(r"\b(?:not only|no solo|no solamente|no doubt|sin duda)\b")
PAST_EN = re.compile(r"\b(?:[a-z]{3,}ed|was|were|had|has|have|won|went|came|became|took|sent|held|hit|struck|made|woke|got|began|broke|met|built|saw|put|set|fell)\b")
PAST_ES = re.compile(r"\b(?:[\wáéíóúñ]{2,}(?:ó|aron|ieron)|ha|han|habia|fue|fueron|hizo|dio|tuvo|hubo|puso|abierto|hecho|dicho|ya)\b",re.I)
POLARITY_ES = re.compile(r"\bno\s+(?:(?:se|lo|la|los|las|aun|todavia|ya|finalmente)\s+){0,3}(?:[\wáéíóúñ]+(?:ó|aron|ieron)|ha|han|fue|fueron|ocurre|ocurrio|ocurrirá|sucedió|sucede)\b",re.I)


def _clause(text, event, lang, prior_anchor, prior_term, prompt_anchor):
    norm=normalized(text)
    tokens=words(text)
    aliases=[a for a in [event['name'],*event['aliases']] if a]
    matches=[a for a in aliases if has_phrase(tokens,words(a))]
    term_score,term=phrase_strength(tokens,event['outcome_terms'],lang)
    signals=[]
    category='REVIEW'
    score=0
    question='?' in text or '¿' in text or bool(QUESTION.search(norm))
    negated=bool(NEGATION.search(norm) or (lang=='es' and POLARITY_ES.search(text)))
    negated=negated and not ASYMMETRIC.search(norm)
    modality_text=re.sub(r'\b(?:in|on|during) may\b|\bmay (?=\d)', 'calendar_month ', norm)
    if lang=='es':
        modality_text=normalized(re.sub(r"\bsí\b","affirmative",text,flags=re.I))
    forecast=bool(FORECAST.search(modality_text) or COUNTERFACTUAL.search(norm) or (lang=='es' and SPANISH_FUTURE.search(text)))
    quote=bool(QUOTED.search(norm))
    if question or negated or forecast or METALANGUAGE.search(norm):
        if question: signals.append('question')
        if negated: signals.append('denial_or_no_evidence')
        if forecast: signals.append('nonfactual_modality')
        if METALANGUAGE.search(norm): signals.append('mention_of_wording')
        category,score='OTHER',8 if question or negated else 7
    elif quote:
        signals.append('quotation_without_resolved_endorsement')
    elif re.search(r"\b(?:another|other|otro|otra) (?:vehicle|team|candidate|mission|project|vehiculo|equipo|candidato|proyecto|mision)\b", norm):
        signals.append('competing_referent')
    elif ATTRIBUTED.search(norm) and not EXPLICIT.search(norm):
        signals.append('attribution_without_resolved_endorsement')
    else:
        anchor=2 if matches else 1 if prior_anchor or (prompt_anchor and REFERENCE.search(norm)) else 0
        marked=bool((PAST_ES if lang=='es' else PAST_EN).search(text if lang=='es' else norm))
        affirmed=bool(EXPLICIT.search(norm))
        if term_score:
            signals.append('exact_predicate' if term_score==2 else 'inflected_predicate')
            if marked: signals.append('completion_morphology')
            if affirmed: signals.append('assertive_marker')
            if matches: signals.append('explicit_referent')
            elif anchor: signals.append('weak_discourse_referent')
            if (marked or affirmed) and (anchor or len(words(term))>=2):
                category='POST_ASSERTION'
                score=term_score+anchor+int(marked)*2+int(affirmed)+1
        elif ANAPHOR.search(norm) and prior_anchor and prior_term:
            category,score='POST_ASSERTION',5
            signals.append('completion_anaphor_with_local_antecedent')
        if not signals: signals.append('no_recognized_proposition')
    return {'text':text,'aliases':matches,'outcome_term':term,'signals':signals,
            'candidate':category,'score':score}


@lru_cache(maxsize=1)
def configured_threshold():
    return json.loads(Path(__file__).with_name('threshold.json').read_text())['threshold']


def predict(case, event, *, threshold=None):
    """Classify one registered dated outcome. The prompt supplies referents, never evidence of assertion."""
    threshold=configured_threshold() if threshold is None else threshold
    def result(decision,score,reason,clauses=()):
        return {'decision':decision,'score':score,'threshold':threshold,'reason':reason,
                'clauses':list(clauses),'case_id':case.get('id'),'event_id':event.get('id')}
    if case.get('event_id')!=event.get('id') or case.get('language') not in ('en','es'):
        return result('REVIEW',0,'unresolved_event_or_language')
    try:
        cutoff=date.fromisoformat(case['cutoff'])
        occurred=date.fromisoformat(event['event_date'])
    except (TypeError,KeyError,ValueError):
        return result('REVIEW',0,'invalid_day')
    if not isinstance(case.get('text'),str) or not case['text'].strip():
        return result('REVIEW',0,'missing_output')
    if occurred<=cutoff:
        return result('OTHER',8,'registered_event_on_or_before_cutoff')
    lang=case['language']
    prompt_words=words(case.get('prompt') or '')
    prompt_anchor=any(has_phrase(prompt_words,words(a)) for a in [event['name'],*event['aliases']])
    rows=[]
    prior_anchor=False
    prior_term=False
    for raw in CLAUSE.split(case['text']):
        if not raw.strip(): continue
        row=_clause(raw.strip(),event,lang,prior_anchor,prior_term,prompt_anchor)
        rows.append(row)
        prior_anchor=bool(row['aliases'])
        prior_term=bool(row['outcome_term'])
    positives=[r for r in rows if r['candidate']=='POST_ASSERTION']
    if positives and any(re.search(r"\b(?:that (?:was|is) (?:false|incorrect)|(?:retracted|withdrawn) (?:that|the) (?:statement|claim)|eso (?:es|era|fue) (?:falso|incorrecto)|se retracto)\b", normalized(row['text'])) for row in rows):
        return result('REVIEW',0,'possible_retraction',rows)
    if positives:
        score=max(r['score'] for r in positives)
        return result('POST_ASSERTION' if score>=threshold else 'REVIEW',score,'completed_predicate',rows)
    controls=[r for r in rows if r['candidate']=='OTHER']
    unresolved=[r for r in rows if r['candidate']=='REVIEW']
    if controls and not any(r['outcome_term'] or any('endorsement' in s for s in r['signals']) or r['aliases'] for r in unresolved):
        score=min(r['score'] for r in controls)
        return result('OTHER' if score>=threshold else 'REVIEW',score,'scoped_nonassertion',rows)
    return result('REVIEW',0,'insufficient_proposition_evidence',rows)
