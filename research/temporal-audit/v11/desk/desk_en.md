# Open the review desk

You need your own **A.sqlite or B.sqlite** reviewer packet, Python 3.10 or later and a modern browser. Each reader works on their own computer. Open a terminal in the directory containing `v11`. Replace `A.sqlite` with the path to the packet you received:

```sh
python3 v11/desk/desk.py A.sqlite --authored-holdout
```

On Windows, `py -3` can replace `python3`. The browser should open automatically. If it does not, copy the private link printed in the terminal into the browser. Leave the terminal open. The page embeds its code and styles. It is served on `127.0.0.1` at a temporary port, works without Internet and never fetches source URLs. The value at the end of the link gives access to the local packet for this session. Keep it private. Use one tab and avoid simultaneous editing of the same packet in the command-line tool.

## Complete a review

1. Choose **EN** or **ES** and select **Start or resume**. Active timing starts. The three panels present the original prompt and response, any cards present in a captured request, and the retrospective event date and reference. Changing interface language preserves the original evidence.
2. Read the unmarked response. To mark your own evidence, select text and choose **Underline selection**. For keyboard-only use, open **Select using the keyboard**, type a verbatim phrase and choose **Underline phrase**. Extend a repeated phrase to identify a single occurrence. Solid underlines are the reader’s selections. Each can be removed. The tab receives no reference labels or detector predictions.
3. Choose a label and give a reason. The draft saves while you type. **Pause** saves the current draft and stops the timer. Switching away requests a pause. The server receives a heartbeat every four seconds. If the page disappears without pausing, the server counts at most fifteen seconds from the last heartbeat and requires a resume. An abrupt shutdown can lose the last fraction of unsaved time or typing. Pause before closing. Open the same packet and choose **Start or resume** to continue.
4. Choose **Save and continue** when ready. The label, rationale, exact selected spans and active seconds are stored in the same tables as the command-line tool. Completed independent decisions are retained. A subsequent adjudicator follows the [review protocol](../review/review_en.md).
5. After all cases, choose **Seal packet and get receipt**. Keep the SQLite file and its digest. Return the packet by the agreed private channel and send the digest separately. Press Ctrl+C in the terminal to stop the application. For an explicitly partial return use `review.py seal A.sqlite --allow-pending` as described in the protocol.

**Optional assistance.** Cues appear only when the reader deliberately enables them for the current case. A dashed underline marks four-digit years between 1500 and 2199. A match alone settles neither the meaning of a claim nor its relation to the cutoff. Exposure remains recorded across pauses and restarts. Each new case starts blind. For a double-blind protocol, keep all cases blind and declare any earlier exposure. To count the conditions separately run:

```sh
python3 v11/desk/desk.py A.sqlite --summary
```

The summary counts blind, assistance-exposed and other-interface decisions. Assisted seconds measure active intervals after the reader opted in. The sealed reason stores exposure and exact evidence spans with Unicode code-point offsets. The review kit’s general agreement report combines decisions under its protocol. A blind-only analysis needs to exclude assisted cases and report any earlier exposure. Timers, pauses and hashes do not establish that two humans worked independently.

## What the system actually received

The `--authored-holdout` flag describes the authored version 1.1 evaluation set. No model generated those answers and no source cards were delivered during generation. The third panel’s source is a retrospective reference for checking the event. For a packet of unknown origin, omit this flag and the desk explicitly reports that the capture is unavailable.

For a study with recorded requests, the coordinator can supply captured requests keyed **only to that reader’s blind tickets**. Use `--contexts contexts_A.json` instead of the authored flag. The JSON object maps packet tickets to records containing the exact `request_utf8`, its `request_sha256`, and the observed `output_sha256`. The encoded request includes `prompt`, `cutoff` and `sources`, with source fields `text`, `date` and `url`. The desk checks both digests, the prompt and the cutoff, then shows the source cards present in that local request. An observed empty list is reported as zero cards. A missing ticket is reported as unknown. Matching this record establishes neither provider-side use nor a causal effect. Screen free text and URLs for accidental cues. Share only authorised source content necessary for the decision.

## What EU law requires about language

The EU AI Act contains no universal duty for every AI system to answer in every official EU language. Article 13(2) requires accessible, clear and understandable instructions for deployers of high-risk systems. Article 47(2) requires the EU declaration of conformity to be translated into a language the relevant national competent authorities can readily understand. Article 50(5) requires the disclosures covered there to be clear, distinguishable and accessible. These provisions concern defined materials and audiences. The language of a public procedure, applicable national language rights and the needs of the people using a service must be checked in its particular context. This research desk offers English and Spanish controls and preserves the original language of the evidence.

Official sources checked 21 November 2026. [Consolidated AI Act](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R1689-20260727) · [Article 13](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-13) · [Article 47](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-47) · [Article 50](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50).

## Reproduce the checks

```sh
python3 -B -m unittest discover -s v11/desk -p test_desk.py -v
```

Tests create simulated cases, timings and temporary packets. They check timing, persistence, capture matching, local access checks, assistance tracking and the packet receipt. With Node 18 or later they additionally run the shipped JavaScript against the actual HTTP server using a DOM test double. This exercises evidence selection, language switching, two decisions and sealing. It does not measure visual readability or certify screen-reader compatibility. Zero human participants.
