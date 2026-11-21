"""Rebuild frozen weights from the explicitly listed development files. Requires NumPy."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path

# Isolate the numerical reference run from host-dependent thread counts.
for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "VECLIB_MAXIMUM_THREADS", "BLIS_NUM_THREADS"):
    os.environ[name] = "1"

import numpy as np
from local_model import ROOT, character_windows, normalize

SEED = 20261121
WIDTH, EMBED, HIDDEN = 8, 8, 24
LM_EPOCHS, HEAD_EPOCHS = 18, 110


def write_json(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n", encoding="utf-8")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_data(study, method, eu_file):
    files = {
        "study/data/cases.json": study / "cases.json",
        "study/data/labels.json": study / "labels.json",
        "method/calibration.json": method / "calibration.json",
        "method/development_events.json": method / "development_events.json",
        "local_model/eu-development.json": eu_file,
    }
    objects = {k: json.loads(v.read_bytes()) for k, v in files.items()}
    events = {r["id"]: r for r in objects["method/development_events.json"]}
    labels = objects["study/data/labels.json"]
    legacy = [{"id": c["id"], "event_id": c["event"], "cutoff": c["cutoff"], "language": "en", "prompt": c["prompt"],
               "text": c["output"], "gold": labels[c["id"]]["label"]} for c in objects["study/data/cases.json"]]
    calibration = objects["method/calibration.json"]
    eu = objects["local_model/eu-development.json"]
    if len(legacy) != 96 or len(calibration) != 48 or len(eu) != 192:
        raise ValueError("Development-source sizes differ from the frozen design.")
    origins = {c["id"]: c for c in legacy}
    expected_ids = {language + "-" + cid for language in ("fr", "de") for cid in origins}
    if {row["id"] for row in eu} != expected_ids:
        raise ValueError("The translation file must cover only the original 96 rows per language.")
    for r in eu:
        src = origins[r["id"][3:]]
        if r["id"][:2] != r["language"] or any(r[k] != src[k] for k in ("cutoff", "event_id", "gold")):
            raise ValueError("Translation identity, date or label differs from its original.")
    cases = legacy + calibration + eu
    documents = sorted({value for r in cases for field in ("prompt", "text") if (value := normalize(r[field]))})
    supervised = {}
    eligible_counts = Counter()
    for row in cases:
        if row["cutoff"] >= events[row["event_id"]]["event_date"]:
            continue
        if row["gold"] not in ("POST_ASSERTION", "OTHER"):
            raise ValueError("Unrecognised development label.")
        eligible_counts[row["language"]] += 1
        key = (row["language"], normalize(row["text"]))
        label = int(row["gold"] == "POST_ASSERTION")
        if key in supervised and supervised[key] != label:
            raise ValueError("Conflicting stance for a deduplicated pre-cutoff answer.")
        supervised[key] = label
    samples = [(lang, t, v) for (lang, t), v in sorted(supervised.items())]
    counts = {"input_rows": len(cases), "case_language_counts": dict(Counter(r["language"] for r in cases)),
              "precutoff_rows_by_language": dict(eligible_counts), "unique_lm_documents": len(documents),
              "supervised_unique_by_language": dict(Counter(x[0] for x in samples)),
              "supervised_unique_by_label": dict(Counter("assertion" if x[2] else "other" for x in samples))}
    return documents, samples, counts, {k: digest(v) for k, v in files.items()}


class Adam:
    def __init__(self):
        self.m, self.v, self.step = {}, {}, 0

    def update(self, params, gradients, lr):
        self.step += 1
        for key, gradient in gradients.items():
            if key not in self.m:
                self.m[key], self.v[key] = np.zeros_like(gradient), np.zeros_like(gradient)
            self.m[key] = 0.9 * self.m[key] + 0.1 * gradient
            self.v[key] = 0.999 * self.v[key] + 0.001 * gradient**2
            first = self.m[key] / (1 - 0.9**self.step)
            second = self.v[key] / (1 - 0.999**self.step)
            params[key] -= lr * first / (np.sqrt(second) + 1e-8)


def probabilities(logits):
    exp = np.exp(logits - logits.max(axis=1, keepdims=True))
    return exp / exp.sum(axis=1, keepdims=True)


def forward(params, contexts):
    x = params["embedding"][contexts].reshape(len(contexts), -1)
    h = np.tanh(x @ params["context_w"] + params["context_b"])
    return x, h


def encoder_grad(params, contexts, x, h, dh):
    dz = dh * (1 - h*h)
    emb = np.zeros_like(params["embedding"])
    np.add.at(emb, contexts, (dz @ params["context_w"].T).reshape(len(contexts), WIDTH, EMBED))
    return {"embedding": emb, "context_w": x.T @ dz, "context_b": dz.sum(axis=0)}


def train(documents, samples):
    rng = np.random.default_rng(SEED)
    vocab = ["<PAD>", "<UNK>", "<END>", *sorted(set("".join(documents)))]
    alphabet = {s: i for i, s in enumerate(vocab)}
    p = {"embedding": rng.normal(0, .10, (len(vocab), EMBED)), "context_w": rng.normal(0, .11, (WIDTH*EMBED, HIDDEN)),
         "context_b": np.zeros(HIDDEN), "lm_w": rng.normal(0, .12, (HIDDEN, len(vocab))), "lm_b": np.zeros(len(vocab)),
         "stance_w": rng.normal(0, .08, (2*HIDDEN, 2)), "stance_b": np.zeros(2)}
    contexts, targets = [], []
    for document in documents:
        w, y = character_windows(document, alphabet, WIDTH)
        contexts.extend(w)
        targets.extend(y)
    contexts, targets = np.asarray(contexts), np.asarray(targets)
    def lm_loss():
        _, h = forward(p, contexts)
        prob = probabilities(h @ p["lm_w"] + p["lm_b"])
        return float(-np.log(prob[np.arange(len(targets)), targets]).mean())
    initial_loss = lm_loss()
    opt = Adam()
    for _ in range(LM_EPOCHS):
        order = rng.permutation(len(contexts))
        for begin in range(0, len(order), 128):
            idx = order[begin:begin+128]
            bx, by = contexts[idx], targets[idx]
            x, h = forward(p, bx)
            dl = probabilities(h @ p["lm_w"] + p["lm_b"])
            dl[np.arange(len(by)), by] -= 1
            dl /= len(by)
            grads = encoder_grad(p, bx, x, h, dl @ p["lm_w"].T)
            grads.update(lm_w=h.T @ dl, lm_b=dl.sum(axis=0))
            opt.update(p, grads, .003)
    pretrained_loss = lm_loss()
    spans = [np.asarray(character_windows(text, alphabet, WIDTH)[0]) for _, text, _ in samples]
    labels = np.asarray([y for _, _, y in samples])
    counts = np.bincount(labels, minlength=2)
    balance = len(labels) / (2 * counts)
    opt = Adam()
    for _ in range(HEAD_EPOCHS):
        order = rng.permutation(len(spans))
        for begin in range(0, len(order), 16):
            idx = order[begin:begin+16]
            lengths = [len(spans[i]) for i in idx]
            offsets = np.r_[0, np.cumsum(lengths)]
            ctx = np.concatenate([spans[i] for i in idx])
            x, hidden = forward(p, ctx)
            features, peaks = [], []
            for s, e in zip(offsets[:-1], offsets[1:]):
                seq = hidden[s:e]
                peaks.append(s + seq.argmax(axis=0))
                features.append(np.r_[seq.mean(axis=0), seq.max(axis=0)])
            features = np.asarray(features)
            by = labels[idx]
            dl = probabilities(features @ p["stance_w"] + p["stance_b"])
            dl[np.arange(len(by)), by] -= 1
            dl *= (balance[by]/len(by))[:, None]
            df = dl @ p["stance_w"].T
            dh = np.zeros_like(hidden)
            for j, (s, e) in enumerate(zip(offsets[:-1], offsets[1:])):
                dh[s:e] += df[j, :HIDDEN] / (e - s)
                dh[peaks[j], np.arange(HIDDEN)] += df[j, HIDDEN:]
            grads = encoder_grad(p, ctx, x, hidden, dh)
            grads.update(stance_w=features.T @ dl, stance_b=dl.sum(axis=0))
            opt.update(p, grads, .001)
    model = {"format": 1, "width": WIDTH, "vocabulary": vocab, "parameters": {k: a.round(9).tolist() for k, a in p.items()}}
    stats = {"numpy_version": np.__version__, "rng_seed": SEED, "context_characters": WIDTH,
             "embedding_dim": EMBED, "hidden_dim": HIDDEN, "vocabulary_size": len(vocab), "lm_targets": len(contexts),
             "lm_epochs": LM_EPOCHS, "supervised_epochs": HEAD_EPOCHS, "lm_train_nll_initial": round(initial_loss, 6),
             "lm_train_nll_after_pretraining": round(pretrained_loss, 6), "lm_train_nll_after_supervision": round(lm_loss(), 6),
             "parameter_counts": {k: int(v.size) for k, v in p.items()}, "total_parameters": int(sum(x.size for x in p.values()))}
    return model, stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-data", type=Path, default=ROOT.parent.parent / "study" / "data")
    parser.add_argument("--method-dir", type=Path, default=ROOT.parent / "method")
    parser.add_argument("--eu-data", type=Path, default=ROOT / "eu-development.json")
    parser.add_argument("--output", type=Path, required=True, help="Directory to write weights and report.")
    args = parser.parse_args()
    documents, samples, counts, hashes = source_data(args.study_data, args.method_dir, args.eu_data)
    model, stats = train(documents, samples)
    args.output.mkdir(parents=True, exist_ok=True)
    write_json(args.output / "weights.json", model)
    write_json(args.output / "training_report.json", {"source_sha256": hashes, "counts": counts, "fit": stats,
               "weights_sha256": digest(args.output / "weights.json")})


if __name__ == "__main__":
    main()
