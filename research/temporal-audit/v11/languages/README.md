# Multilingual replay · Repetición multilingüe

Run from this directory with Python 3.10+ and the original package layout.

```sh
python -B replay_languages.py
python -B -m unittest -v test_languages
```

The first command recomputes and compares both stored artifacts. The optional `--write` flag explicitly regenerates them. `small_baseline.py` reconstructs its learned coefficients from two digest-pinned calibration input files and accepts `predict(case,event)`. No network access or credentials are required. French and German results for the learned and proposition models are reported as `UNSUPPORTED`.

[English chapter](languages_en.md) · [Capítulo en español](languages_es.md) · [Matrix](language_matrix.csv) · [Evidence](language_evidence.jsonl) · [Training inventory](learned_training.json)
