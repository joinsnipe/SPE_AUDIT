# A local neural language model with 3,638 parameters

The prototype learns to predict the next character in English, Spanish, French and German development texts. A second phase fine-tunes its representations to classify the stance of an answer about a registered event. All weights were randomly initialized and trained from scratch on CPU. The weight file is 45,903 bytes. Inference uses the Python standard library and runs offline. The empirical scope is a small study of short responses authored for this project. [Inference](local_model.py) · [Weights](weights.json) · [Training report](training_report.json)

## Data and evaluation boundary

| Development input | Rows | Use |
|---|---:|---|
| Original public English responses | 96 | Character learning. Rows whose cutoff precedes the event also supply stance supervision. |
| Prior English and Spanish editorial calibration set | 48 | 24 per language about four development events. For this model these are training data. |
| French and German translations of the original 96 | 192 | 96 per language. The loader checks the ID, event, cutoff and label against each original. |
| **Total** | **336** | 120 English, 24 Spanish, 96 French and 96 German rows. The translations share both events and content with the originals. |

Prompts and responses became separate documents. Normalization and deduplication left 179 distinct strings and 13,099 next-character targets. Stance training used rows whose event fell after the cutoff. Once an event has taken place, a statement that it happened can receive the temporal label `OTHER` despite affirming the outcome. Excluding such rows from stance training avoids treating that temporal label as contrary stance supervision. Deduplication by language and answer yielded 129 supervised texts, including 64 assertions and 65 other answers. There were 50 English, 21 Spanish, 29 French and 29 German texts. [FR/DE development inputs](eu-development.json) · [Hashes of all five input files](training_report.json)

Results on the original 96 or their French and German translations are results on seen data. The 16 rewordings and their translations revisit already public ideas. The new 48-case challenge exists only in English and Spanish and was excluded from both training stages. The implementer had previously seen broad descriptions of the challenge while working on a different part of the project. We froze weights, code and thresholds before evaluating this model on those responses. This is a retrospective comparison with file-level separation and does not establish full researcher blinding. [Frozen manifest](freeze.sha256)

## Language learning and stance fine-tuning

The 60-symbol vocabulary includes left padding, an unknown character and an end-of-document symbol. After NFC normalization, case folding and whitespace normalization, the model receives the previous eight characters. Each supplies eight learned coordinates. The concatenated 64 coordinates feed a 24-unit tanh layer. A linear layer and softmax predict the next character or end of document. Each target uses only the preceding characters in its own document. Training ran for 18 epochs, batch size 128, using Adam at 0.003 and seed 20261121. Mean in-sample negative log likelihood was initially 4.100415 nats per target and fell to 1.319675 after character pretraining.

For stance, the model computes the mean and maximum of each of the 24 activations across the answer's windows. A linear layer takes these 48 values and produces two logits. This layer, character embeddings and context layer were fine-tuned using class-weighted cross entropy for 110 epochs, batch size 16, and Adam at 0.001. The next-character output layer stayed fixed during fine-tuning. As shared representations changed, the final model's next-character loss on the same data rose to 2.193646. These numbers describe training. General language competence has not been independently measured. [Training implementation](train.py) · [Losses and parameter counts by layer](training_report.json)

## What an auditor can inspect

The interface is `predict(case, event)`. A case supplies an event ID, language, cutoff, prompt and answer text. A registered event supplies an ID, named subject, event date, possible aliases, outcome phrases and a source locator. The function reads these values and the local weights. It does not fetch the source.

| Output | Meaning |
|---|---|
| `decision` | `POST_ASSERTION` for an answer classified as affirming an outcome after the cutoff, `OTHER` for the alternative, or `REVIEW` for manual review. Every outcome has a `reason` code. |
| `p_assertion` and `score` | The same raw softmax value for the answer. Both are null when a date or input check determines the outcome. The score has not been calibrated as a probability of correctness. |
| `trace` | Supplied subject, source locator, both dates, status, verbatim answer quote, character offsets of recognized names and registered outcome phrases, and the weight-file digest. Python character spans are zero-based and half-open. |

The boundaries were fixed by design. Before the event, a literal name or alias in the answer or prompt is required. A score ≥0.70 yields `POST_ASSERTION`, a score ≤0.30 yields `OTHER` and the interval between them yields `REVIEW`. A cutoff on or after the event day yields `OTHER` under the registered single-event assumption. Inconsistent or missing event identity or dates, an unsupported language, an empty answer or more than 512 normalized characters yields `REVIEW`. The stance head reads the answer alone. The prompt can supply the name anchor. Outcome-phrase spans are exposed for inspection and do not contribute to the neural score.

The constructed example preserves the exact text “North Museum opened.”, the subject “North Museum”, a 2000-12-31 cutoff and a registered 2001-01-02 event. The result was `POST_ASSERTION` with score 0.896369 for the fictional card. The record contains enough information to reproduce the quote, offsets and decision. A name in the prompt may identify the wrong referent. The model can misread quotations, negation, tense and language-specific idioms. It estimates neither S(t), A(t), Δ(t) nor the cause of a response. [Example input and trace](example_trace.json)

## Reproduction

From this directory, the following commands verify the manifest and run four offline contract tests. The reference training environment used Python 3.12, NumPy 2.3.5 and a CPU. The example writes the rebuilt files outside the published directory. Pass `--study-data` and `--method-dir` if the source files are arranged differently.

```sh
sha256sum -c freeze.sha256
python test_local_model.py
python train.py --output /tmp/spe-local-rebuild
cmp weights.json /tmp/spe-local-rebuild/weights.json
```

Two separate runs in the reference environment reproduced the weights and report byte for byte. The weight SHA-256 is `8f444d23138b39c16a2bce1ada44f17cc971c296ed6bb7fa04c4be7f8f6897e2`. Inference with the distributed weights requires Python 3.10 or later. The function `next_characters(prefix, count=5)` also exposes predictions from the language head. [Contract tests without trial data](test_local_model.py) · [Manifest](freeze.sha256)
