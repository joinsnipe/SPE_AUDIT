# SPE — Stateless Proof Engine

**Certify AI Outputs. Detect Temporal Violations. Verify Offline. Forever.**

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Ed25519](https://img.shields.io/badge/crypto-Ed25519-green.svg)](#cryptographic-stack)
[![SHA-256](https://img.shields.io/badge/hash-SHA--256-green.svg)](#cryptographic-stack)
[![Tests](https://img.shields.io/badge/tests-15%2F15%20passed-brightgreen.svg)](#tests)
[![White Paper](https://img.shields.io/badge/White%20Paper-v1.0-orange.svg)](docs/WHITE_PAPER.md)

---

## What is SPE?

**SPE (Stateless Proof Engine)** is an open cryptographic engine for **certifying AI outputs** — proving that what an LLM said, when it said it, and what context it had, has not been tampered with.

### 🤖 Built for the AI Era

- **Certify LLM outputs** — GPT-4, Claude, Gemini, Llama, or any model
- **Detect temporal violations** — TVOC: when an AI "knows" things it shouldn't
- **Prove context integrity** — Which RAG documents fed the AI response
- **Verify offline forever** — No server, no blockchain, no dependency on SPE

### 📄 Also Works For

- Digital forensics and legal evidence
- Compliance and regulatory auditing (GDPR, HIPAA, ISO 27001)
- Email and communication integrity

### Why Not Blockchain?

| Feature              | SPE                 | Blockchain Notaries          | Traditional Notaries       |
| -------------------- | ------------------- | ---------------------------- | -------------------------- |
| Offline Verification | ✅ Yes              | ❌ No (requires node)        | ❌ No (requires authority) |
| Data Custody         | ❌ None (stateless) | ⚠️ Public ledger             | ✅ Centralized             |
| Cost per Proof       | Free (self-hosted)  | €5–50                        | €20–100                    |
| Speed                | < 2 seconds         | Minutes (block confirmation) | Days (manual process)      |
| Privacy              | ✅ Stateless        | ❌ Public                    | ⚠️ Centralized logs        |
| Long-Term Viability  | ✅ Offline forever  | ⚠️ Depends on blockchain     | ⚠️ Depends on notary       |

---

## Core Design Philosophy

1. **No Custody** — SPE never stores your files. Processing is transient (in-memory only).
2. **No History** — No logs, no databases of user activity. Privacy by design.
3. **Portable** — Proofs are self-contained. You own the evidence, not the service.
4. **Hermetic Verification** — Proofs can be verified offline, forever, with zero dependencies on SPE infrastructure.

---

## Cryptographic Stack

| Component        | Technology           | Purpose                                     |
| ---------------- | -------------------- | ------------------------------------------- |
| Hashing          | SHA-256              | Cryptographic fingerprint of content        |
| Signing          | Ed25519 (Curve25519) | Digital signature ensuring proof origin     |
| Proof Structure  | Merkle Tree          | Tamper detection for context items          |
| Hash Chain       | SHA-256 Append-Only  | Sequential anti-tampering ledger            |
| Encoding         | Base64               | Portable binary-to-text for signatures      |
| Canonicalization | Deterministic JSON   | Reproducible hashing across implementations |

---

## Quick Start

### Installation

```bash
git clone https://github.com/joinsnipe/SPE_AUDIT.git
cd SPE_AUDIT
pip install -r requirements.txt
```

### Generate a Proof (Python API)

```python
from spe_engine import generate_proof

# Certify a file
result = generate_proof(file_path="document.pdf")
print(f"Proof generated: {result.zip_path}")
print(f"Capsule hash:    {result.capsule_hash}")

# Certify text content (e.g., AI output)
result = generate_proof(content="The answer to life is 42.")
print(f"Proof generated: {result.zip_path}")

# Certify a pre-computed hash (zero-upload mode)
result = generate_proof(hash_hex="a" * 64)
print(f"Proof generated: {result.zip_path}")
```

### Generate a Proof (CLI)

```bash
# Certify a text document
python -m cli attest \
  --t_target 2026 \
  --policy strict \
  --text_file my_document.txt \
  --out_dir my_proof/

# Export a human-readable proof block
python -m cli proof \
  --capsule my_proof/forensic_capsule.json \
  --ledger my_proof/ledger.sqlite
```

### Verify a Proof (CLI)

```bash
# Verify a proof bundle (offline)
cd my_proof/verify/
python verify_bundle.py \
  --capsule ../forensic_capsule.json \
  --ledger ../ledger.sqlite \
  --file ../original_document.pdf
```

**Output:**

```
LEDGER: VALID
CAPSULE_BINDING: VALID
PROOF_INPUT_HASH: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
SIGNATURE: VALID
ORIGIN_SPE: UNKNOWN
OBJECT: MATCH
```

### Verify a Proof (Python API)

```python
from spe_engine import verify_proof
from pathlib import Path

result = verify_proof(
    bundle_path=Path("SPE_Proof_20260216.zip"),
    original_file=Path("document.pdf"),
)
print(f"Valid: {result.valid}")
print(f"Match: {result.match_status}")  # "MATCH" or "MISMATCH"
```

---

## Verification Semantics

| Result                     | Meaning                                                                  |
| -------------------------- | ------------------------------------------------------------------------ |
| **LEDGER: VALID**          | The hash-chain is mathematically intact (no entries modified or removed) |
| **CAPSULE_BINDING: VALID** | The forensic capsule matches the ledger's recorded capsule hash          |
| **SIGNATURE: VALID**       | Ed25519 signature verified against the embedded public key               |
| **OBJECT: MATCH**          | The file is byte-for-byte identical to the certified version             |
| **OBJECT: MISMATCH**       | The file has been altered since certification                            |

### Important Disclaimers

- **VALID** means mathematical integrity ONLY
- **VALID** does NOT mean truth, authorship, intent, or legal authority
- SPE does not prove who created a file — only that it hasn't been altered
- The verifier is READ-ONLY; it never modifies files

---

## Architecture

```
SPE_AUDIT/
├── spe_engine/               # Core cryptographic engine
│   ├── core/                 # Capsule, Ledger, Context, Merkle, Temporal
│   ├── crypto/               # SHA-256 hashing, Ed25519 signing
│   ├── proof_input/          # Manifest canonicalization and signing
│   ├── tvoc/                 # Temporal Violation of Context detection
│   └── api.py                # High-level generate_proof / verify_proof
├── cli/                      # Command-line tools
│   ├── attest.py             # Generate attestation from text + context
│   ├── proof.py              # Export human-readable proof block
│   └── verify_object.py      # Verify file against capsule
├── verify_kit/               # Hermetic offline verifier
│   ├── verify_bundle.py      # Zero-dependency verification script
│   └── capsule_ledger/       # Portable data structures for verification
├── tests/                    # Test suite
├── docs/                     # Technical documentation
│   ├── WHITE_PAPER.md        # White Paper v1.0
│   ├── PROTOCOL_SPEC.md
│   ├── ARCHITECTURE.md
│   └── AI_CERTIFICATION_GUIDE.md
├── examples/                 # Usage examples
└── requirements.txt
```

---

## What's in a Proof Bundle?

A proof bundle (`.zip`) contains:

| File                    | Purpose                                                  |
| ----------------------- | -------------------------------------------------------- |
| `forensic_capsule.json` | The core attestation record (hashes, timestamps, policy) |
| `ledger.sqlite`         | Append-only hash-chain for anti-tampering                |
| `signature.json`        | Optional Ed25519 origin signature                        |
| `verify/`               | Self-contained verification kit (works offline forever)  |

### Forensic Capsule Structure

```json
{
  "t_run": 1708099200,
  "t_target": 2026,
  "gate_policy_id": "strict",
  "model_id": "gpt-4",
  "output_hash": "sha256:7f83b1657ff1fc53b92dc18148a1d65d...",
  "mode": "text",
  "hash_alg": "sha256",
  "artifact_type": "ai-output",
  "context_merkle_root": "a3b8d1b60b3b4b1a9c1a1a2b3c4d5e6f...",
  "proof_input": { ... },
  "proof_input_hash": "9c1a1a2b3c4d5e6f7a8b9c0d1e2f3a4b..."
}
```

---

## Use Cases

### 1. AI Output Certification

Certify what an AI said, when it said it, and what context it had:

```python
from spe_engine import generate_proof

# Certify an AI response
result = generate_proof(
    content="Based on the Q3 2025 report, revenue grew 15%.",
    model_id="gpt-4-turbo",
    artifact_type="ai-output",
    policy="strict",
    t_target=2025,
)
```

### 2. Document Integrity

Prove a file existed in a specific form at a specific time:

```python
result = generate_proof(
    file_path="contract_v2.pdf",
    artifact_type="legal-document",
)
```

### 3. TVOC Detection (Temporal Violation of Context)

Detect when an AI produces information it shouldn't know based on the declared time:

```python
from spe_engine.tvoc import detect_tvoc_strong

result = detect_tvoc_strong(
    output_text="In 2027, the EU passed new regulations...",
    t_target=2025,
    context_has_post_target=False,
)
# result: {"tvoc": "STRONG", "violating_years": [2027], "t_target": 2025}
```

---

## Public Key

SPE's production Ed25519 public key for signature verification:

```
G7aHboCJsVDCM5exNfewMAyFpbI6ulcy9a5lrIeonyk=
```

This key can be used to verify that a proof was generated by SPE's production infrastructure.

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Key areas for contribution:**

- Additional language implementations (Node.js, Go, Rust verifiers)
- Post-Quantum Cryptography integration (ML-DSA / Dilithium)
- Browser-based verification tools (WebCrypto API)
- Documentation and tutorials

---

## License

This project is licensed under the **Business Source License 1.1 (BSL 1.1)**.

- ✅ **Free for non-commercial use**, research, education, and personal projects
- ✅ **Free for internal evaluation** and testing
- ⚠️ **Commercial use requires a license** — contact contacto@speaudit.com
- 📅 **Change Date**: February 16, 2030 — after which the code becomes Apache 2.0

See [LICENSE](LICENSE) for full terms.

---

## Contact & Support

- **Website**: [speaudit.com](https://www.speaudit.com)
- **Email**: contacto@speaudit.com
- **Commercial Licensing**: contacto@speaudit.com
- **GitHub Issues**: [SPE_AUDIT Issues](https://github.com/joinsnipe/SPE_AUDIT/issues)

---

**SPE** — _Stateless. Portable. Verifiable._

_Patent Pending — © 2024-2026 SPE Audit / Joinsnipe_
