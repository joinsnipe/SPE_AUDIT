# Two independent reviews of a temporal claim

**Measurement status at release: zero human reviewers, zero observed human decisions and zero measured human minutes.** The tests create fictional cases and simulated timings in a temporary directory. The instrument can collect prospective observations. Its existence supplies no estimate of human accuracy, independence or workload.

## What the two readers decide

The question is whether the response **asserts that the named event had already happened when its documented occurrence was later than the cutoff**. Use the same calendar-day convention for both readers. For a same-day event of unknown time use day precision and flag the uncertainty in the rationale if ordering within the day matters. Event dates, source publication dates and legal effective dates can differ. The supplied retrospective reference helps identify the event. It does not establish what the model retrieved or what the public could know at a given hour.

| Label | Decision rule |
|---|---|
| `post_cutoff_assertion` | The response commits to the completed target event and the documented event date is after the cutoff. Record the words carrying that commitment. An explicit year is optional. |
| `other` | The completed event was on or before the cutoff under the date convention, or the speaker only predicts, denies, hypothesises, quotes without endorsing, asks, or declines to answer. Explain the reading with a short extract. |
| `indeterminate` | An ambiguity about the event, speaker commitment, identity or chronology prevents a defensible judgment. Say which evidence or distinction is missing. |

Read the prompt and response together. A copied question by itself makes no assertion. A quoted prediction followed by an explicit endorsement of completion can. A demonstrably wrong number and an event disclosed in the question can require separate investigation. Keep those observations in the evidence field and evaluate the specified proposition. If the supplied source cannot resolve ambiguity, record it. Freeze the source version or provide both readers the same dated, lawful reference copy before starting.

## Coordinator and reader workflow

Use Python 3.10+ and run these commands from the directory containing `review.py`. Paths in capitals are placeholders. The coordinator first records the method, cutoffs, evidence rules and exclusions outside the review directory and obtains its **previously committed** SHA-256. Supplying a new digest calculated after access would defeat prospective blinding. The program compares the digest before opening the case and event files. A JSON freeze declaring the case and event digests in its `sha256` map binds both inputs byte for byte before packet creation. A plain-text protocol remains usable and commits only to the protocol. The coordinator records the input byte digests with the assignments. A digest does not establish when or by whom a freeze was made.

1. **Prepare.** Cases are a JSON array of objects with `id,event_id,cutoff,language,prompt,text`. Events are an array with `id,name,event_date,source_url`. Both dates use YYYY-MM-DD. Only language, prompt, response, cutoff, event name, event date and the source URL enter a reader packet. Case IDs, rules, labels, predictions and other metadata are omitted. Inspect the allowed text and URLs separately for accidental answer keys, model names, template labels or identifiers. Do not change observed words to conceal a material fact. Exclude an affected row under the agreed rule or disclose the compromise. The program independently shuffles presentation order and generates unrelated random tickets per reader. For batches of more than one case the two orders differ.
2. **Distribute privately.** The batch directory contains `coordinator.json` and two independent SQLite files. Give each reader only their own packet, this protocol and the CLI. Keep the crosswalk with the coordinator and the two readers apart. Do not give readers access to the full dataset, method predictions, previous labels or one another’s work. Record any prior access or discussion as a protocol deviation. Publicly released cases cannot become genuinely unseen by hiding identifiers.
3. **Review.** `session` opens a pending item, starts a monotonic active timer, permits pause/resume, then saves a label, a reason and active seconds. The timer includes decision entry. Pause for interruptions. Quit discards that attempt including elapsed time. If resuming offline work from a separate timer, use `show` and `record`; enter the total active seconds for that item, including earlier interrupted work. A refusal and a pending or interrupted review are distinct. Empty reasons, duplicate responses, zero or invalid times are rejected. The local label and reason are stored as entered.
4. **Close independently.** Each reader gets a receipt digest from `seal` and returns their closed SQLite file separately and securely. `--allow-pending` explicitly permits a partial return. Restore each to its original name in the coordinator’s batch, verify each digest against the independently returned receipt, and retain both sealed originals. `status` displays counts and the verified receipt of a sealed packet without revealing labels. The CLI checks packet identity, order and isolated answer integrity before comparing the two responses. The receipts detect changes relative to trusted references. They do not authenticate a person.
5. **Adjudicate separately.** A third reader sees the two original reasons on paired disagreements and paired indeterminate judgments, reviews the original source, and records an independent final rationale and cumulative active seconds. The adjudication may itself be indeterminate. Repeat the adjudication commands until the queue is empty. Only the separate `adjudication.sqlite` file receives these decisions. A missing second judgment remains pending. Raw reader agreement stays fixed.

```sh
python3 review.py prepare --cases CASES.json --events EVENTS.json --freeze FROZEN_PROTOCOL --freeze-sha256 RECORDED_DIGEST --mode human_collection --out BATCH
python3 review.py session A.sqlite
python3 review.py show A.sqlite
python3 review.py record A.sqlite --ticket TICKET --label indeterminate --evidence "Which date applies is unclear" --seconds 70
python3 review.py status A.sqlite
python3 review.py seal A.sqlite
python3 review.py report BATCH
python3 review.py adjudicate BATCH
python3 review.py adjudicate BATCH --case CASE_ID --label other --evidence "Describe the decision and source" --seconds 95
python3 review.py report BATCH
python3 -B -m unittest discover -s . -p test_review.py
```

`session` and the `show` plus `record` pair are alternative ways to record an item. Repeat with the other reader’s packet on their own device. Treat the example seconds above as illustrations. During a rehearsal select `--mode simulation` and keep rehearsal batches separate from human observations.

## What to report

Publish the three-by-three matrix with A on rows and B on columns. Exact agreement is the diagonal divided by all paired cases. Unweighted Cohen’s κ is (observed agreement − expected agreement) / (1 − expected agreement), with expectation obtained from the two label marginals. Indeterminate forms its own category, including agreements on indeterminate. No paired cases yields null agreement and κ. Single-category constant marginals yield undefined κ if chance agreement is one. Keep pair completion and each reader’s pending count alongside the matrix.

The JSON report separates per-reader, paired and adjudication effort. It reports observed person-minutes, median and nearest-rank p90 active seconds, and timing method counts. Paired duration sums both readers’ active time on completed pairs. Total effort includes completed unpaired reviews and completed adjudications once each. Wall-clock delay, abandoned work, recruitment, training and future queue effort require separate measurement. Preserve unresolved final labels and publish the number of cases still without a disposition. Report cohort size, language and any exposure to public examples along with these figures.

## Rights and privacy in a deployment

A coordinator should determine the lawful basis and purpose for processing personal data, minimise what reviewers see, limit retention and control access. Use synthetic examples in a public demonstration. Raw notes or command histories can contain personal details. Enter only the minimum necessary content and share aggregate results after disclosure review. Pseudonymous tickets can still be linked using the private crosswalk. Under the AI Act a person with grounds to allege an infringement may complain to the competent market surveillance authority (Article 85). Article 86 provides qualifying affected people with an explanation from the deployer about AI’s role and the main elements of a decision. The underlying administrative or judicial route to challenge the decision remains relevant. GDPR Articles 77 and 79 concern data-protection complaints and judicial remedies. A reviewer’s label by itself establishes neither entitlement to redress nor the lawfulness of a deployment.

Official sources checked 21 November 2026. [Consolidated AI Act](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R1689-20260727) · [Article 85](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-85) · [Article 86](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-86) · [GDPR, especially Articles 5, 6, 32, 77 and 79](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng).
