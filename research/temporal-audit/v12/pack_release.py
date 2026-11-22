"""Build the deterministic, offline case-scoring archive for the Zenodo document release."""
import argparse
import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = HERE.parent
CONTEXT = ["study/data/cases.json", "study/data/challenge.json", "study/data/events.json",
           "study/results/capsules.jsonl", "study/results/predictions.csv",
           "study/results/summary.json", "study/results/interventions.json",
           "study/data/labels.json", "study/data/challenge_labels.json", "study/matcher.py",
           "study/reproduce.py", "study/capture.py", "study/REVIEW.md", "study/challenge_method.md",
           "post11/reference_reader/protocol.py", "post11/reference_reader/download_reference.py",
           "post11/reference_reader/mask.py", "post11/reference_reader/summary.csv",
           "post11/reference_reader/confusion.csv", "post11/reference_reader/reader_es.md",
           "post11/reference_reader/reader_en.md", "post11/generalization/cohorts.csv",
           "landscape/bibliography.csv", "landscape/bibliography_notes_es.csv", "landscape/legacy.csv",
           "v11/sources/dating_ledger.csv", "v11/sources/search_log.csv", "v11/sources/fuentes_es.md",
           "v11/results/decisions.csv", "post11/brief/BRIEF_ES.md", "post11/brief/BRIEF_EN.md"]
EDITION = ["PRIOR_PROTOCOL.md", "plan.json", "prompt.txt", "paired.py", "score.py", "plan.tsq", "plan.tsr",
           "receipts.zip", "paired_decisions.csv", "metrics.csv", "transitions.csv", "candidate_events.csv",
           "NEXT_STUDY.md", "README.md", "pack_release.py", "PAPER_ES.md", "PAPER_EN.md", "catalogue.py"]


def make(path):
    inputs = [REPO / "LICENSE", BASE / "LICENSE", *(HERE / s for s in EDITION), *(BASE / s for s in CONTEXT)]
    inputs.extend(sorted(p for p in (BASE / "study/vendor").rglob("*") if p.is_file() and "__pycache__" not in p.parts))
    entries = {str(p.relative_to(REPO)): p.read_bytes() for p in inputs}
    entries["START_HERE.txt"] = (
        "SPE Audit 1.2 / Rubén Abella / 2026-11-22\n"
        "DOI: 10.5281/zenodo.24447732\n\n"
        "Python 3.12, offline / sin conexión:\n"
        "  cd research/temporal-audit/v12\n  python -B score.py\n\n"
        "Results: metrics.csv, paired_decisions.csv, transitions.csv.\n"
        "Open README.md for the timestamp check and optional real-model rerun.\n"
        "The two typeset papers and the reference catalogue are separate files in the deposit.\n"
        "The paper and original figures are CC BY 4.0. Software terms: LICENSE (BSL 1.1).\n"
        "Third-party sources and trademarks retain their respective rights.\n"
    ).encode()
    entries["SHA256SUMS.txt"] = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                                         for name, data in sorted(entries.items())).encode()
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(entries.items()):
            info = ZipInfo(name, (2026, 11, 22, 0, 0, 0))
            info.external_attr = (0o100644 << 16)
            archive.writestr(info, data, compress_type=ZIP_DEFLATED, compresslevel=9)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output", type=Path)
    make(ap.parse_args().output)
