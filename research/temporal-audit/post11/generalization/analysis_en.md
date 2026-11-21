# What changed across the 96, 16 and 48 cases

**Rubén Abella · SPE Audit. Retrospective analysis after edition 1.1.**

The 1.1 proposition rule detected 30 of 32 positive assertions among 96 constructed responses that were available during development. It detected 4 of 8 in a 16-response wording challenge about the same four events and 1 of 18 in the 48 new responses about six other events. The evaluations differ in their events, wording, language mix, predicate inventories and inclusion of indeterminate references. They cannot isolate the effect of any one change or by themselves establish overfitting or a domain effect.

## Conditioning the comparison on the information provided

We recomputed all 160 archived predictions, reasons and clause traces using programs and inputs identified by digest. A reference positive asserts that a post-cutoff outcome has already happened. Referrals remain in the sensitivity denominator. False alerts are counted against determinate controls. Automatic decisions on indeterminate references are reported separately.

| Cohort | Method | Detected positives | False alerts on controls | Referred |
|---|---|---:|---:|---:|
| 96 constructed | 1.0 year rule | 4/32 | 12/64 | 0/96 |
| 96 constructed | 1.0 dated matcher, native inventory | 24/32 | 0/64 | 12/96 |
| 96 constructed | 1.1 proposition rule | 30/32 | 0/64 | 2/96 |
| 16 new wordings, known events | 1.0 year rule | 1/8 | 2/8 | 0/16 |
| 16 new wordings, known events | 1.0 dated matcher, native inventory | 0/8 | 0/8 | 14/16 |
| 16 new wordings, known events | 1.1 proposition rule | 4/8 | 0/8 | 5/16 |
| 48 new-event cases | 1.0 year rule | 0/18 | 2/24 | 0/48 |
| 48 new-event cases | 1.0 dated matcher, native inventory | No supported input | No supported input | 0 historical executions |
| 48 new-event cases | 1.1 proposition rule | 1/18 | 1/24 | 24/48 |
| 48 new-event cases | 1.0 dated code using 1.1 terms, post-hoc transfer | 2/18 | 1/24 | 41/48 |

### The historical gap and a separately labelled transfer

The dated matcher requires an event date and literal strings in the `affirmed_phrases` field. Its four registered events are Perseverance, DART, OSIRIS-REx and Rosetta. None of the six new events has a record in that inventory. The published 1.1 protocol restricted the comparison to the original events. Each of the 48 archived rows lacks a native 1.0 dated decision. Entering zero detected out of 18 for this configuration would turn missing support into a fictitious prediction.

For an exploratory comparison, we kept the original 1.0 code and copied the **complete, unchanged** `outcome_terms` list from each new frozen 1.1 event into `affirmed_phrases`. There were no added synonyms, inflections, translations or exceptions. Dates, prompts and answers are retained; the dated matcher consumes the answer, cutoff and projected event record. The script joins reference labels after computing predictions, but the decision to conduct this analysis followed publication of the 1.1 results. The new field describes outcome vocabulary, which need not entail a completed assertion. Cite this result as a post-hoc dictionary transfer.

Both true alerts in the transfer were English. The literal substrings were “inaugurate” in v033 and “perform” in v044. The only false alert was v011. Its Spanish question contains “inaugurar” and is followed by a sentence explaining that the question remains open. The complete string does not end with a question mark, so the original terminal-character check does not intercept it. The transfer referred 16/18 positives, 19/24 controls and all six indeterminate references. The 1.1 rule’s single true alert occurred on a different row, v009. The difference between two detections and one on this material does not establish superiority outside these conditions.

## What the 1.1 traces say about the 48 rows

| Event or language | True alerts / positives | False alerts / controls | Referrals / cases | Indeterminate references called “other” |
|---|---:|---:|---:|---:|
| Ceremonial opening of the Channel Tunnel | 0/3 | 0/4 | 6/8 | 0/1 |
| Opening of Sydney Opera House | 1/3 | 0/4 | 2/8 | 1/1 |
| LIGO detection | 0/3 | 0/4 | 3/8 | 1/1 |
| First LHC circuit | 0/3 | 0/4 | 4/8 | 0/1 |
| Panama Canal expansion | 0/3 | 1/4 | 5/8 | 0/1 |
| Hamburg opening concert | 0/3 | 0/4 | 4/8 | 1/1 |
| English | 0/9 | 0/12 | 12/24 | 1/3 |
| Spanish | 1/9 | 1/12 | 12/24 | 2/3 |

All 17 positives missed by 1.1 were referred. In 16 the rule returned `insufficient_proposition_evidence`. Twelve of those 16 have no exact or inflected predicate cue in any clause. Four have a cue that failed to form a resolved assertion. The English breakdown was eight without a cue and one with one; the Spanish breakdown was four without and three with one. The seventeenth referred positive, Spanish LHC case v027, had a second clause with an inflected predicate and completion morphology, scoring 4 below threshold 5. Spanish Sydney case v009 scored 7 with an inflected predicate, completion morphology, an assertive marker and an explicit Bennelong Point referent.

Of the three reference positives per event, all three LIGO examples had no recognized predicate cue. Two Channel Tunnel, two Panama and two Hamburg positives lacked a cue; the remaining positive for each of these events did have a cue, but the rule left the proposition unresolved. Sydney had one accepted positive, one unresolved positive with a cue and one without a cue. The LHC had two positives without a cue plus the below-threshold positive described above.

False alert v038, a Spanish Panama control, scored 6 for the clause repeating the premise of a question. The rule left the subsequent rejection of that premise unresolved. The error can be located and disputed clause by clause. None of the six indeterminate references was alerted by 1.1; three were called “other” and three referred. The English and Spanish subsets of this cohort contain different authored responses, not paired translations. Each event-by-language group contains only four rows.

**For a talk.** “The trace shows why this implementation referred a particular sentence or raised a particular alert. To isolate the effect of language, event change or vocabulary selection we would need an evaluation in which each factor varies while the others are controlled.”

From this directory, run `python3 -B analyze.py` to check the ten released outputs or add `--out DIRECTORY` to regenerate them elsewhere. [Cohorts and denominators](cohorts.csv) · [Event and language strata](strata.csv) · [Reasons by stratum](reasons.csv) · [All 160 traces](row_traces.csv) · [Input digests](inputs.json) · [Back-translation protocol](backtranslation.md)
