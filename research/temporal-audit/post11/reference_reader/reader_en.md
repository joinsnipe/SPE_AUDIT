# A reproducible local reference reader

This protocol records exactly what a local instruction model was asked, what bytes it returned, and how its decisions compared with a separately held reference. The model reads a question, an answer and one retrospective event card. It cannot establish where the answer's author learned a fact. Its use here is an experiment in classifying an author's commitment to a dated outcome.

The earlier exploratory AI reading remains a separate historical observation. Its archived instructions and answers support rescoring. Its deployed model, full input serialization, sampling and provider-side processing could not be recovered. The scientific prompt in this directory was written for a new experiment. Its exact bytes, including the trailing newline, are public. The raw request body in each receipt records how the template incorporates those bytes. [Exact prompt](prompt_v1.txt)

## Registered configuration

| Component | Exact setting for these executions |
|---|---|
| Model | SmolLM2-135M-Instruct. QuantFactory conversion at revision `476854d00ede130660aba430d15f9347ad2e7d0e`, file `SmolLM2-135M-Instruct.Q4_K_M.gguf`. The 105,454,144-byte file had SHA-256 `8030f04528538d47bda434f6f0bdf3952c40a58123e4d5e755332f23731a8684`. |
| Engine | Official llama.cpp b8058 Linux x86-64 binary. The executable reported commit `184c694f4`, GNU 11.4.0 and the Zen 4 CPU backend. Executable SHA-256 `36a0e300a5f827798fc4ad253ab35e6ceea2b82e4e060ef9fd73397fcf083b50`. Each plan lists the adjacent library hashes. |
| Inference | One CPU inference thread, one batch thread, one parallel slot, GPU layers 0, context 4,096 tokens. The runner starts its own server on an ephemeral loopback port. It accepts no remote inference URL. The first and second passes use separately launched server processes. |
| Sampling | Temperature 0, seed 20261121, at most 384 output tokens, no streaming, prompt caching disabled in each request. The HTTP response preserves the engine-reported sampling settings. |
| Prompt | `semantic-stance-chatml-v1`; SHA-256 `5378009285a27aee5fd9a6566dd6671d6ab236a036845dda657195c3d7fb9a9d`. One fixed English instruction applies to all languages. The model card identifies English as its primary language. |
| Inputs and output | E1 is the nominated event, its supplied date, the inclusive cutoff and a source locator. E2 is the question and E3 the answer. The model chooses `POST_ASSERTION`, `OTHER` or `REVIEW`, a verbatim E3 quote and allowed evidence IDs. Its inputs exclude the reference label, original ID, stratum, prior predictions and metrics. |

Sources for the published model and runtime are available directly from their maintainers. The quantized model is a third-party conversion. The optional downloader checks the public file digests before extracting or using either artifact. The protocol itself makes no model or case requests to an external service. [Upstream model](https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct) · [Pinned quantization](https://huggingface.co/QuantFactory/SmolLM2-135M-Instruct-GGUF/blob/476854d00ede130660aba430d15f9347ad2e7d0e/SmolLM2-135M-Instruct.Q4_K_M.gguf) · [Official engine release](https://github.com/ggml-org/llama.cpp/releases/tag/b8058) · [Engine completion protocol](https://github.com/ggml-org/llama.cpp/blob/b8058/tools/server/README.md)

## Run a prospective comparison

1. Have the reference author fix the interpretation rule and reference labels independently. Record a digest of that file with a third party or in a public repository before inference. Keep the labels with the scorer. Declare case provenance, inclusion criteria and any overlap with development.
2. Give the runner only the case and event files. The masking program copies a strict allowlist of fields, replaces case IDs with salted opaque keys and sorts by those keys. Keep its separate key mapping away from the model. The event dates are supplied to the retrospective reader; they do not establish what the original answer producer knew.
3. Seal the model identity, sampling settings, exact implementation, masked inputs and prompt in a new plan directory. Before inference, share the plan digest externally with a date if priority or independent timing matters. A locally generated digest alone does not prove publication time.
4. Execute the sealed plan twice, each time in a new output directory. The request body and raw response body are preserved per case. The engine can choose only from the supplied full answer and sentence-level quote options. A valid quote therefore demonstrates source-bounded extraction, while semantic validity depends on the decision. Quote offsets are zero-based, end-exclusive and identify the first matching occurrence.
5. Verify both manifests and compare the runs before opening the references. Retain every failure. A malformed response, an invalid quotation, a transport failure or an unavailable engine is recorded as an error. Such a case requires manual review and earns no correct decision. A semantic `REVIEW` remains distinct from a failed call. A failed run may be repeated in a new directory with the original retained.
6. Open the reference and mapping only after the records are fixed. The scoring command checks the run again, includes every input in the denominator, distinguishes `REVIEW` from `ERROR`, and reports coverage and accuracy on determinate references. Here a reference labelled `INDETERMINATE` maps to the review action. Report all three-way decisions as well as conditional metrics.

The commands below run from this directory under Python 3.12. They assume new output paths. The optional download retrieves approximately 125 MiB of public runtime and model files once. Set `ENGINE` to a local llama-server executable and `GGUF` to the checked local model file if they are already installed.

```sh
python download_reference.py /tmp/spe-reader-runtime
ENGINE=/tmp/spe-reader-runtime/engine/llama-b8058/llama-server
GGUF=/tmp/spe-reader-runtime/model.gguf
MODEL_ID=QuantFactory/SmolLM2-135M-Instruct-GGUF@476854d00ede130660aba430d15f9347ad2e7d0e/SmolLM2-135M-Instruct.Q4_K_M.gguf
python mask.py --cases cases.json --events events.json --out masked.json --mapping private-map.json
python protocol.py freeze --masked masked.json --backend llama.cpp --purpose prospective --engine "$ENGINE" --model "$GGUF" --model-id "$MODEL_ID" --output plan
cat plan/plan.sha256
python protocol.py run --plan plan --engine "$ENGINE" --model "$GGUF" --output run1
python protocol.py run --plan plan --engine "$ENGINE" --model "$GGUF" --output run2
python score.py compare --plan plan --run run1 --second run2 --out agreement.json
python score.py score --plan plan --run run1 --gold reference.json --mapping private-map.json --out score.json
```

`cases.json` is a list with `id`, `event_id`, `cutoff`, `language`, `prompt` and `text`. `events.json` is a list with `id`, `name`, `event_date` and optional `source_url`. Dates use YYYY-MM-DD. The reference is a JSON object mapping original case IDs to labels. Authorized scorers can use the published mapping after unblinding. For real sensitive data, publish the mapping and verbatim texts only with an appropriate basis for disclosure.

## Replays and engineering tests

The configured model scored 12/48 (25%) agreement on the earlier gold-labelled EN/ES challenge. All 48 outputs in each pass had the required JSON and a bounded quote. Of the 42 determinate references, it made a non-review decision on 26 and got 11 of those 26 correct. None of the 24 `OTHER` controls received the correct decision. Repeating the run reproduced every decision, quote and evidence ID. None of the 48 full response bodies were byte-identical: only the engine's `timings` field differed in those pairs. This replay measures the new, small quantized reader against an already published challenge. It provides no prospective generalization estimate. [Complete replay receipts](replay48.zip)

On the separate collection of 17 English third-party passages, all outputs again had valid JSON and an eligible quote on each pass. The reader assigned 16 cases to review. Its sole non-review decision was incorrect. Its one exact agreement in 17 was the correctly deferred indeterminate case. Coverage on determinate references was 1/16, with zero correct out of the one covered. In both passes, the five positive references received zero positive decisions, one OTHER and four REVIEW. All 11 OTHER controls and the one indeterminate reference received REVIEW. The 17 structured outputs matched across runs. Only the timings field differed across all 17 original response-body pairs. The same frozen scientific prompt, weights, executable and sampling settings were used for both datasets. The third-party reference was supplied to the scorer after both inference manifests had been sealed. The passages were historically published and editorially selected, so a genuinely prospective sample remains a different test. [Complete 17-passage receipts](external17.zip) · [Counts, coverage and digests](summary.csv) · [Confusion matrices](confusion.csv)

The reference collection and the model's respective units matter. For example, a grammar can require a correct verbatim quote even if the chosen label misreads it. Treat an ERROR as manual review operationally, while retaining it in the error column for statistical auditing. Repeated inference and valid JSON cannot justify autonomous adjudication of these passages.

Engineering tests use an explicitly identified fixture that always returns `OTHER`, or a deliberately failing transport. They verify masking, quote validation, error retention, manifest tamper detection, separate scoring and repetition. These tests require no weights and contribute no scientific predictions. To verify the archived real model runs, including every original request, response, manifest, score and reachable input digest, use the following commands. The ZIP inventory covers each member. Repacking the same receipt bytes uses fixed ZIP timestamps and ordering. [Protocol](protocol.py) · [Scoring](score.py) · [Engineering tests](test_protocol.py)

```sh
python test_protocol.py
python evidence.py verify replay48.zip
python evidence.py verify external17.zip
```
