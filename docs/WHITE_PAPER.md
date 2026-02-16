# SPE — Stateless Proof Engine

## White Paper: Cryptographic Certification for AI Outputs

**Version 1.0 — February 2026**
**Patent Pending — © 2025–2026 SPE Audit**

---

## The Problem No One Has Solved

Every day, enterprises deploy AI systems that produce outputs affecting real decisions: legal summaries, financial analyses, compliance reports, medical triage, customer commitments. Yet there is no standard way to answer these questions after the fact:

- **Did the AI actually generate this response, or was it edited?**
- **What documents did the AI have access to when it answered?**
- **Could the AI have legitimately known this information at that time?**
- **When, exactly, was this output produced?**

Traditional audit logs can be falsified. Blockchain notarization is slow, expensive, and requires third-party infrastructure. Screenshots prove nothing. Existing solutions force a choice between **custody** (your data leaves your control) and **verifiability** (proofs require a live service to validate).

**SPE eliminates this trade-off.**

---

## What SPE Is

SPE (Stateless Proof Engine) is an open cryptographic engine that generates self-contained, tamper-evident proof bundles for AI outputs. It works with any LLM — GPT-4, Claude, Gemini, Llama, or any custom model — and produces proofs that can be verified **offline, forever**, with zero dependency on SPE infrastructure.

SPE is not a logging service. It is not a blockchain. It does not store your data. It is a cryptographic tool — **like a notary stamp that cannot be forged and never expires.**

---

## Core Guarantees

SPE provides **mathematical proof** — not claims, not logs:

| Guarantee               | What It Means                                                       |
| ----------------------- | ------------------------------------------------------------------- |
| **Output Integrity**    | This exact AI response has not been altered since certification     |
| **Temporal Proof**      | The proof was created at this specific moment in time               |
| **Model Attribution**   | This declared model ID was recorded at certification time           |
| **Context Attestation** | These specific documents were available to the AI when it responded |
| **TVOC Detection**      | The AI referenced events beyond its declared knowledge boundary     |

> SPE does not certify that the AI output is _true_, _unbiased_, or _unedited before certification_. It certifies **mathematical integrity from the moment of certification forward.**

---

## Key Innovation: TVOC Detection

**TVOC (Temporal Violation of Context)** is an original forensic signal developed by SPE. It detects when an AI model produces information about events beyond its declared temporal boundary — without any post-boundary context having been provided.

**Legal discovery:** An AI-generated document references events from a year beyond the system's declared knowledge cutoff, with no post-cutoff documents in its RAG index. TVOC flags this as a **Strong violation** — the output could not have been legitimately generated.

**Compliance auditing:** A financial institution needs to prove its AI advisor only used information available as of a specific quarter. TVOC provides a forensic signal examinable in regulatory review.

**RAG pipeline integrity:** Enterprises running Retrieval-Augmented Generation workflows need to prove their AI only accessed indexed documents from a specific period. SPE's context attestation combined with TVOC provides this guarantee.

---

## Architecture: How It Works

SPE's pipeline has five stages, each building on the last:

**Stage 1 — Temporal Gating:** Context documents are filtered by a declared `t_target` boundary. Only documents timestamped before the boundary are included.

**Stage 2 — Context Attestation:** All context documents are canonicalized and hashed into a Merkle tree. The Merkle root is a single hash representing the entire RAG document set — any change to any document changes the root.

**Stage 3 — Forensic Capsule:** An immutable attestation record is created containing the output hash, prompt hash, model ID, timestamp, context Merkle root, and gating policy. The capsule is hashed via SHA-256 of its canonical JSON.

**Stage 4 — Hash Chain Ledger:** The capsule hash is appended to an SQLite-based sequential hash chain. Each entry depends cryptographically on all prior entries. Any insertion, deletion, or reordering breaks the chain.

**Stage 5 — Optional Ed25519 Signature:** For origin attribution, the proof manifest is signed with an Ed25519 private key. Any verifier with the public key can confirm the proof's origin.

**The result is a portable ZIP bundle — a permanently verifiable unit of cryptographic evidence.**

---

## Integration: Two Lines to Certified

### Minimal (Output Only)

```python
from spe_engine import generate_proof

proof = generate_proof(
    content=ai_response,
    model_id="your-model-id",
    artifact_type="ai-output",
)
```

### Full RAG Pipeline

```python
proof = generate_proof(
    content=ai_response,
    model_id="gpt-4-turbo",
    artifact_type="ai-output",
    t_target=2025,
    context_items=rag_documents,
    policy="strict",
)
```

SPE also integrates as HTTP middleware, LangChain callbacks, or batch processors — certifying every response automatically with zero changes to your model or provider.

---

## The Proof Bundle

| File                      | Purpose                               |
| ------------------------- | ------------------------------------- |
| `forensic_capsule.json`   | Core attestation record               |
| `ledger.sqlite`           | Append-only hash chain                |
| `proof_input.json`        | Manifest + optional Ed25519 signature |
| `verify/verify_bundle.py` | Zero-dependency offline verifier      |

The bundle is **owned by the certifying party**. SPE retains nothing.

---

## Verification: Offline, Forever

```bash
python verify_bundle.py --capsule forensic_capsule.json --ledger ledger.sqlite
```

```
LEDGER:          VALID
CAPSULE_BINDING: VALID
SIGNATURE:       VALID
OBJECT:          MATCH
```

A proof generated today is verifiable in ten years, on an air-gapped machine, by a party that has never interacted with SPE.

---

## SPE vs. Alternatives

|                            | SPE        | Blockchain | Audit Log      | Notary  |
| -------------------------- | ---------- | ---------- | -------------- | ------- |
| **Offline verification**   | ✅ Forever | ❌         | ❌             | ❌      |
| **AI context attestation** | ✅ Native  | ❌         | ❌             | ❌      |
| **TVOC forensics**         | ✅ Native  | ❌         | ❌             | ❌      |
| **Data custody**           | ✅ Zero    | ⚠️ Public  | ⚠️ Centralized | ⚠️      |
| **Cost per proof**         | Free       | €5–50      | Variable       | €20–100 |
| **Speed**                  | < 2s       | Minutes    | Instant        | Days    |

---

## Use Cases

**AI-native companies** — certify every production LLM output for liability and auditability without infrastructure complexity.

**Enterprise RAG deployments** — prove which documents fed each AI response, at what time, under what policy. Essential for finance, healthcare, legal.

**AI compliance & regulatory reporting** — demonstrate to auditors that AI systems operated within declared knowledge boundaries.

**Legal & forensic** — cryptographically verifiable AI records for discovery, contracts, and dispute resolution, verifiable by opposing counsel with no server dependency.

---

## Security

- **SHA-256** (FIPS 180-4) — 128-bit collision resistance
- **Ed25519** (RFC 8032) — 128-bit signature security
- **Merkle Trees** — tamper detection across all context documents
- **Sequential Hash Chain** — 100% detection of any ledger modification
- **Zero-dependency verifier** — permanently auditable, no package dependencies

---

## Getting Started

**Repository:** [github.com/joinsnipe/SPE_AUDIT](https://github.com/joinsnipe/SPE_AUDIT)

**License:** BSL 1.1 — free for non-commercial use; Apache 2.0 on Feb 16, 2030

**Commercial licensing:** contacto@speaudit.com

**Website:** [speaudit.com](https://speaudit.com)

---

**SPE — Stateless. Portable. Verifiable.**

_Patent Pending — © 2025–2026 SPE Audit_
