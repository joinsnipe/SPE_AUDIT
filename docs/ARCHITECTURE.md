# SPE Architecture Overview

## System Components

SPE is composed of modular components that work together to create
tamper-evident cryptographic proofs for AI outputs and digital content.

---

## Core Pipeline

```
Input (AI Output / File / Hash)
       │
       ▼
┌─────────────────────────┐
│  Temporal Gating (TGP)  │  Filter context by time boundary
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Context Attestation    │  Canonicalize + Merkle hash
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Forensic Capsule       │  Create immutable audit record
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Attestation Ledger     │  Append to hash chain
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  TVOC Detection         │  Check for temporal violations
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Ed25519 Signature      │  Optional origin attribution
└──────────┬──────────────┘
           │
           ▼
      ZIP Bundle (Portable, Self-Contained)
```

---

## Module Map

### `spe_engine/core/`

| Module        | Purpose                                          |
| ------------- | ------------------------------------------------ |
| `capsule.py`  | ForensicCapsule — immutable attestation record   |
| `ledger.py`   | AttestationLedger — append-only hash chain       |
| `context.py`  | ContextItem + canonicalization for RAG workflows |
| `merkle.py`   | Merkle root computation for context attestation  |
| `temporal.py` | Temporal gating — filter by time boundary        |

### `spe_engine/crypto/`

| Module         | Purpose                                   |
| -------------- | ----------------------------------------- |
| `hash.py`      | SHA-256 hashing (content + files)         |
| `signature.py` | Ed25519 signing + verification (optional) |

### `spe_engine/proof_input/`

| Module         | Purpose                                 |
| -------------- | --------------------------------------- |
| `canonical.py` | Deterministic proof input serialization |
| `hash.py`      | Proof input hash computation            |
| `signature.py` | Sign/verify proof input manifests       |

### `spe_engine/tvoc/`

| Module        | Purpose                                              |
| ------------- | ---------------------------------------------------- |
| `detector.py` | Strong TVOC detection (temporal violation forensics) |
| `extract.py`  | Year extraction from AI output text                  |

### `spe_engine/api.py`

High-level API: `generate_proof()` and `verify_proof()`.

---

## Data Structures

### ForensicCapsule

The core attestation record. Each capsule captures:

| Field                 | Description                      |
| --------------------- | -------------------------------- |
| `t_target`            | Declared temporal boundary       |
| `gate_policy_id`      | Gating policy applied            |
| `context_merkle_root` | Hash of all context documents    |
| `model_id`            | AI model identifier              |
| `hash_prompt`         | SHA-256 of the prompt            |
| `t_run`               | Unix timestamp of certification  |
| `output_hash`         | SHA-256 of the certified content |

### AttestationLedger

Append-only hash chain stored in SQLite:

```
entry_hash = SHA-256(prev_hash | capsule_hash | t_run)
```

Genesis entry: `prev_hash = "0" * 64`

### Proof Bundle (ZIP)

```
SPE_Proof_YYYYMMDD_HHMMSS.zip
├── forensic_capsule.json     # Attestation record
├── ledger.sqlite             # Hash chain
└── proof_input.json          # Manifest + optional signature
```

---

## Security Properties

| Property                | Mechanism                  |
| ----------------------- | -------------------------- |
| Content integrity       | SHA-256 hash comparison    |
| Ledger tamper detection | Sequential hash chain      |
| Origin attribution      | Ed25519 digital signature  |
| Temporal forensics      | TVOC detection             |
| Offline verification    | Zero external dependencies |
| Portable evidence       | Self-contained ZIP bundle  |

---

## What is NOT in This Repository

| Component               | Reason                             |
| ----------------------- | ---------------------------------- |
| Private signing keys    | Security — never distributed       |
| Production API server   | Commercial infrastructure          |
| PDF/Visual certificates | Commercial bundler (SPE_LINK/SEAL) |
| Browser extension       | Distributed via Chrome Web Store   |
| Billing / Analytics     | Operational infrastructure         |

---

_© 2024-2026 SPE Audit — Patent Pending_
