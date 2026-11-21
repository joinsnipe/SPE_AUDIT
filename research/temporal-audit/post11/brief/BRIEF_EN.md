# Reproducible inference can reproduce an error

**Rubén Abella · SPE Audit · 21 November 2026**

Post-deposit research note. The DOI links to the underlying paper. [Deposited paper on Zenodo](https://doi.org/10.5281/zenodo.24424024) · [Public research section](https://www.spetrace.com/research/temporal-audit)

## Two readings of the same 48 answers

The exploratory reading archived in the paper matched the editorial reference on all 18 positives, 24 controls and six ambiguous cases. It was commissioned **after** the aggregate rule results had been examined. The new run uses an identifiable local model to ask what happens when the inference setup is also fixed and recorded. It reuses 48 previously public English and Spanish answers written for the study. The local inferences were actually run on these constructed answers.

| Method on the same 48 cases | Alert | Other | Review | Positives detected / 18 |
|---|---:|---:|---:|---:|
| Proposition rule 1.1 | 2 | 22 | 24 | 1/18 |
| Archived exploratory reading | 18 | 24 | 6 | 18/18 |
| New local inference with fixed plan | 29 | 2 | 17 | 11/18 |

The plan fixed SmolLM2-135M-Instruct Q4_K_M quantized weights, llama.cpp b8058, the exact prompt, temperature 0 and seed 20261121. The reader received the event and reference dates, question and answer, with masked identifiers and no evaluation labels. Across two runs, all 48 decisions, selected quotations and evidence identifiers matched. The complete response bodies differed because they contained timing data. [Plan, captures and scores](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/reference_reader/replay48.zip) · [Archived reading](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/v11/results/reader_metrics.json)

The local reader flagged 13 of the 24 controls and referred the other 11. It correctly classified none of these controls as other. Of 42 determinate references it decided 26 and got 11 of those 26 right. It alerted on five of the six ambiguous references and referred one. Across all 48 cases, treating review as agreement on an ambiguous reference, it matched **12/48**. Output repeatability and agreement with a reference measure different properties. These fractions describe this model, prompt and set of cases.

## What changes with third-party excerpts

The second set comprises 17 short English excerpts, totalling 167 words from 17 pages about six public events. Eleven pages came from NIST and six from the U.S. Geological Survey. The agencies wrote the passages. The study selected sources, imposed counterfactual cutoffs and supplied questions and reference labels. There are five positives, eleven controls and one ambiguous reference. The exercise tests new, documented wording. The purposive sample cannot estimate error rates among real users or establish a model’s access to historical sources. [Sources and passage links](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/external/source_index.json) · [Excerpt-level references](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/external/labels.json)

| Same 17 excerpts | Positives detected / 5 | Decisions on 16 determinate cases | Errors among those decisions | Output on the ambiguous case |
|---|---:|---:|---:|---|
| Year rule | 0/5 | 16 | 5 | Other |
| Proposition rule 1.1 | 2/5 | 7 | 0 | Other |
| N-grams | 3/5 | 16 | 7 | Other |
| Character network 1.1 | 0/5 | 7 | 1 | Review |
| Fixed local reader | 0/5 | 1 | 1 | Review |

The proposition rule was correct on the seven determinate cases it decided. It left nine determinate cases unresolved and closed the ambiguous one as other. Reporting only the seven correct decisions would overstate how much of the sample was resolved. The local reader referred 16 of the 17 excerpts and closed one positive as other. Its only agreement was on the ambiguous case: 1/17. All 17 structured outputs repeated on the second pass. [Four baseline outcomes](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/external/results.json) · [Local inference captures](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/reference_reader/external17.zip)

A positive reference describes an assertion that a later outcome has occurred. A page published later may still forecast the outcome or explicitly deny it. Using third-party language diversifies the origin of the wording. The independence of the reference labels and representativeness of the sample remain open questions.

## Which cases remain pending?

Four disposition policies were replayed on the 48 constructed answers. Their input signals are **the 1.1 proposition rule and the archived exploratory reading**. The newly executed local reader is evaluated separately. The cascade keeps the rule’s decisions and consults the archived reading when the rule abstains. The agreement policy checks both signals on every case and closes only when they give the same determinate label. [Case-level routes](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/escalation/routes.csv) · [Policy summary](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/escalation/summary.json)

| Policy | Pending / 48 | Correct alerts / 18 | False alerts on controls | Ambiguous cases automatically closed / 6 |
|---|---:|---:|---:|---:|
| Frozen rule | 24 | 1 | 1 | 3 |
| Cascade | 3 | 18 | 1 | 3 |
| Agreement between both signals | 28 | 1 | 0 | 0 |
| Review all | 48 | 0 | 0 | 0 |

In **v038** the speaker repeats the premise that the expanded Panama Canal had opened, then says, in translation, “I do not accept that premise.” The rule flags the first sentence. The cascade retains the false alert. Under the agreement policy the disagreement keeps the case pending. All six ambiguous references remain open under agreement, together with 17 positives, four other controls and v038 itself. In this example a smaller queue admits closures whose correctness remains disputed. [Open the public case viewer](https://www.spetrace.com/research/temporal-audit/review-desk)

**Open human pilot.** The kit contains 16 cases for two bilingual readers working from separate packets, with a third person to adjudicate disagreements once their records are sealed. At launch there were **zero observed human decisions and zero observed human minutes**. The public viewer is for practice and can reveal solutions. Anyone who has seen a case should record that exposure before a blind review. No estimate of actual human agreement or review time is available. [Pilot kit and protocol](https://github.com/joinsnipe/SPE_AUDIT/tree/main/research/temporal-audit/post11/open-pilot)
