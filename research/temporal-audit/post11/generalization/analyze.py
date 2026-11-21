"""Recount the three public cohorts, replay a post-hoc dictionary transfer, and create blank human worksheets."""
import argparse
import csv
import hashlib
import io
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parents[1]
INPUTS_PIN = "e79516b7bcd05b448b2a598b4a225db7ca1a72978382da1b788b10394e668765"
POS = "POST_ASSERTION"
NEG = "OTHER"
AMB = "INDETERMINATE"
REVIEW = "REVIEW"
METHODS = ("year", "dated_native", "proposition", "dated_transfer")


def read(name):
    return json.loads((RESEARCH/name).read_bytes())


def unique(rows):
    by_id = {r["id"]:r for r in rows}
    if len(rows)!=len(by_id):
        raise ValueError("duplicate case or event identifier")
    return by_id


def verify_inputs():
    data = (HERE/"inputs.json").read_bytes()
    if hashlib.sha256(data).hexdigest()!=INPUTS_PIN:
        raise ValueError("changed input inventory")
    for path,expected in json.loads(data)["sha256"].items():
        if hashlib.sha256((RESEARCH/path).read_bytes()).hexdigest()!=expected:
            raise ValueError(f"frozen input changed: {path}")


def compact(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",",":"))


def csv_bytes(rows):
    memory=io.StringIO(newline="")
    writer=csv.DictWriter(memory,list(rows[0]),lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return memory.getvalue().encode("utf-8")


def assemble():
    # Check the actual historical code/data before importing any classifier.
    verify_inputs()
    sys.path.insert(0,str(RESEARCH/"v11"))
    sys.path.insert(0,str(RESEARCH/"v11/method"))
    from evaluate import classify_all
    from matcher import classify as dated
    from proposition import predict
    archive=[json.loads(line) for line in (RESEARCH/"v11/results/predictions.jsonl").read_bytes().splitlines()]
    fresh=classify_all(predict)
    if fresh!=archive:
        raise ValueError("recomputed 160 historical predictions or clause traces disagree")
    old_events=unique(read("study/data/events.json"))
    new_events=unique(read("v11/holdout/events.json"))
    if old_events.keys() & new_events.keys() or len(old_events)!=4 or len(new_events)!=6:
        raise ValueError("event inventory overlap differs from the published design")
    old_sources=read("study/data/cases.json")+read("study/data/challenge.json")
    old=unique([{"id":r["id"],"prompt":r["prompt"],"text":r["output"]} for r in old_sources])
    new=unique(read("v11/holdout/cases.json"))
    rows=[]
    for item in fresh:
        case_id=item["id"]; group=item["group"]; event_id=item["event_id"]
        is_new=group=="new_challenge"
        src=(new if is_new else old)[case_id]
        prediction=item["explanation"]; clauses=prediction["clauses"]
        cues=sorted({s for clause in clauses for s in clause["signals"]})
        transfer=""; hits=[]
        if is_new:
            if "matcher_v1" in item["choices"]:
                raise ValueError("unexpected archived native result for a new event")
            event=new_events[event_id]
            fixed=event["outcome_terms"]
            # No derivation from responses, outcome labels, aliases, or translations.
            if not fixed or any(not isinstance(p,str) or not p.strip() for p in fixed):
                raise ValueError("invalid frozen transfer dictionary")
            transfer=dated(src["text"],item["cutoff"],{"event_date":event["event_date"],"affirmed_phrases":fixed})
            hits=[p for p in fixed if p.casefold() in src["text"].casefold().strip()]
        rows.append({"cohort":group,"id":case_id,"language":item["language"],"event":event_id,"cutoff":item["cutoff"],
                     "question":src["prompt"],"answer":src["text"],"year":item["choices"]["year_rule"],
                     "dated_native":item["choices"].get("matcher_v1",""),"proposition":prediction["decision"],
                     "dated_transfer":transfer,"transfer_literal_dictionary_hits":compact(hits) if is_new else "",
                     "reason":prediction["reason"],"score":prediction["score"],"threshold":prediction["threshold"],
                     "has_predicate_cue":int(bool({"exact_predicate","inflected_predicate"} & set(cues))),
                     "signals":compact(cues),"clause_trace":compact(clauses)})
    # Join reference labels only after the post-hoc transfer has run.
    gold={}
    for file in ("study/data/labels.json","study/data/challenge_labels.json","v11/holdout/labels.json"):
        labels=read(file)
        if labels.keys() & gold.keys():raise ValueError("duplicate reference label")
        gold.update({k:v["label"] if isinstance(v,dict) else v for k,v in labels.items()})
    if set(gold)!=set(unique(rows)):
        raise ValueError("reference / prediction identifier mismatch")
    for row in rows:
        row["reference"]=gold[row["id"]]
    if Counter(r["cohort"] for r in rows)!={"constructed":96,"old_challenge":16,"new_challenge":48}:
        raise ValueError("unexpected cohort sizes")
    return rows,old


def summary(rows,method):
    scored=[r for r in rows if r[method]]
    cells=Counter((r["reference"],r[method]) for r in scored)
    p=sum(cells[POS,b] for b in (POS,NEG,REVIEW))
    n=sum(cells[NEG,b] for b in (POS,NEG,REVIEW))
    a=sum(cells[AMB,b] for b in (POS,NEG,REVIEW))
    if p+n+a!=len(scored):
        raise ValueError("unexpected state")
    return {"cohort_rows":len(rows),"supported":len(scored),"unsupported":len(rows)-len(scored),
            "positive_n":p,"control_n":n,"indeterminate_n":a,"positive_alert":cells[POS,POS],
            "positive_other":cells[POS,NEG],"positive_review":cells[POS,REVIEW],
            "control_alert":cells[NEG,POS],"control_other":cells[NEG,NEG],"control_review":cells[NEG,REVIEW],
            "indeterminate_alert":cells[AMB,POS],"indeterminate_other":cells[AMB,NEG],"indeterminate_review":cells[AMB,REVIEW],
            "review_n":sum(cells[g,REVIEW] for g in (POS,NEG,AMB))}


def summaries(rows):
    cohorts=[]
    strata=[]
    reasons=[]
    for cohort in ("constructed","old_challenge","new_challenge"):
        subset=[r for r in rows if r["cohort"]==cohort]
        for method in METHODS:
            cohorts.append({"cohort":cohort,"method":method,**summary(subset,method)})
        for kind in ("language","event","event_and_language"):
            def stratum(r):
                return r[kind] if kind!="event_and_language" else r["event"]+"/"+r["language"]
            for value in sorted({stratum(r) for r in subset}):
                group=[r for r in subset if stratum(r)==value]
                for method in METHODS:
                    strata.append({"cohort":cohort,"stratified_by":kind,"stratum":value,"method":method,**summary(group,method)})
                categories=Counter((r["reference"],r["proposition"],r["reason"],r["has_predicate_cue"]) for r in group)
                for (gold,decision,reason,cue),count in sorted(categories.items()):
                    reasons.append({"cohort":cohort,"stratified_by":kind,"stratum":value,"stratum_n":len(group),
                                    "reference":gold,"decision":decision,"reason":reason,"predicate_cue_any_clause":cue,
                                    "count":count,"reference_n_in_stratum":sum(r["reference"]==gold for r in group)})
    return cohorts,strata,reasons


def worksheets(old):
    output={}
    for lang,file in (("fr","french"),("de","german")):
        translated=unique(read(f"v11/languages/{file}.json"))
        if old.keys()!=translated.keys() or len(old)!=112:
            raise ValueError("translation identifiers disagree")
        # Public deterministic pseudonyms let a coordinator recreate the sheet. The key and
        # the public originals must be withheld operationally during a prospective session.
        def ticket(k):
            return hashlib.sha256(f"spe-backtranslation-v1|{lang}|{k}".encode()).hexdigest()[:16]
        keys=sorted(old,key=ticket)
        if len({ticket(k) for k in keys})!=len(keys):raise ValueError("anonymous ticket collision")
        form=[];judge=[];coordinator=[]
        for k in keys:
            pseudonym=ticket(k);line=translated[k]
            form.append({"ticket":pseudonym,"language":lang,"source_prompt":line["prompt"],"source_answer":line["text"],
                         "backtranslated_prompt_en":"","backtranslated_answer_en":"","uncertainty_note":""})
            judge.append({"ticket":pseudonym,"english_original_prompt":old[k]["prompt"],"english_original_answer":old[k]["text"],
                          "backtranslated_prompt_en":"","backtranslated_answer_en":"",
                          "negation_scope":"","modality_or_attribution":"","tense_and_time":"","overall_fidelity":"",
                          "source_span_and_rationale":""})
            coordinator.append({"ticket":pseudonym,"public_case_id":k,"language":lang})
        output[f"forms/{lang}_translator.csv"]=csv_bytes(form)
        output[f"forms/{lang}_adjudicator.csv"]=csv_bytes(judge)
        output[f"forms/coordinator/{lang}_key.csv"]=csv_bytes(coordinator)
    return output


def artifacts():
    rows,old=assemble()
    cohorts,strata,reasons=summaries(rows)
    return {"cohorts.csv":csv_bytes(cohorts),"strata.csv":csv_bytes(strata),
            "reasons.csv":csv_bytes(reasons),"row_traces.csv":csv_bytes(rows),**worksheets(old)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path,help="write freshly generated artifacts to this directory; default checks published bytes")
    args=parser.parse_args()
    try:
        outputs=artifacts()
        for name,data in outputs.items():
            if args.out:
                file=args.out/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(data)
            elif (HERE/name).read_bytes()!=data:
                raise ValueError("published output mismatch: "+name)
    except (ValueError,OSError,KeyError) as exc:parser.exit(1,f"Generalization audit failed: {exc}\n")
    print(f"160 original rows checked; 48 post-hoc dictionary-transfer decisions; 112 blank tickets per language; {len(outputs)} matching or generated files.")


if __name__=="__main__":
    main()
