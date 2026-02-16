# SPE Protocol Specification v2.6

## 1. Overview

The Stateless Proof Engine (SPE) generates tamper-evident cryptographic proof bundles for digital content. This document specifies the exact protocol that governs proof generation, structure, and verification.

---

## 2. Cryptographic Primitives

| Primitive         | Algorithm | Output Size | Standard               |
| ----------------- | --------- | ----------- | ---------------------- |
| Content Hash      | SHA-256   | 256 bits    | FIPS 180-4             |
| Digital Signature | Ed25519   | 512 bits    | RFC 8032               |
| Key Encoding      | Base64    | Variable    | RFC 4648               |
| Hash Chain        | SHA-256   | 256 bits    | Custom (defined below) |

---

## 3. Forensic Capsule Schema

The `forensic_capsule.json` is the core attestation record.

### Required Fields

| Field                 | Type   | Description                                 |
| --------------------- | ------ | ------------------------------------------- |
| `t_target`            | int    | Declared temporal boundary (Unix timestamp) |
| `gate_policy_id`      | string | Gating policy identifier                    |
| `context_merkle_root` | string | SHA-256 hash of canonicalized context       |
| `model_id`            | string | AI model or source identifier               |
| `hash_prompt`         | string | SHA-256 hash of the input prompt            |
| `t_run`               | int    | Unix timestamp of proof generation          |
| `output_hash`         | string | SHA-256 hash of the certified content       |

### Optional Fields

| Field                     | Type   | Description                               |
| ------------------------- | ------ | ----------------------------------------- |
| `artifact_type`           | string | Content type (`ai-output`, `pdf`, etc.)   |
| `mode`                    | string | Certification mode (`text`, `file`, etc.) |
| `hash_alg`                | string | Hash algorithm identifier (`sha256`)      |
| `snapshot_hash`           | string | Hash of any snapshot data                 |
| `normalization_params_id` | string | Normalization parameters identifier       |

### Canonicalization

Capsule JSON is canonicalized using:

- `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
- Encoding: UTF-8
- `None` fields are excluded from serialization

The `capsule_hash` is `SHA-256(canonical_json_bytes)`.

---

## 4. Hash Chain Ledger

The ledger provides sequential anti-tampering via an append-only hash chain stored in SQLite.

### Schema

```sql
CREATE TABLE ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    t_run INTEGER NOT NULL,
    capsule_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
```

### Chain Formula

```
entry_hash = SHA-256("{prev_hash}|{capsule_hash}|{t_run}")
```

### Genesis Entry

The first entry uses `prev_hash = "0" * 64` (64 zero characters).

### Verification Algorithm

```
expected_prev = "0" * 64
for each entry in ledger (ordered by id ASC):
    assert entry.prev_hash == expected_prev
    assert entry.entry_hash == SHA-256(f"{expected_prev}|{entry.capsule_hash}|{entry.t_run}")
    expected_prev = entry.entry_hash
```

---

## 5. Proof Input Manifest

The `proof_input.json` contains metadata about the certification request.

### Canonicalization Rule

**The `signature` field is ALWAYS excluded from canonical form.** This prevents circular dependency when signing.

```python
canonical_bytes = json.dumps(
    {k: v for k, v in proof_input.items() if k != "signature"},
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode("utf-8")
```

### Hash

```
proof_input_hash = SHA-256(canonical_bytes)
```

---

## 6. Ed25519 Signature (Optional)

### Signing

1. Canonicalize proof input (excluding `signature`)
2. Sign canonical bytes with Ed25519 private key (32-byte seed)
3. Produce signature block:

```json
{
  "algorithm": "ed25519",
  "public_key": "<base64-encoded-32-byte-verify-key>",
  "signature_value": "<base64-encoded-64-byte-signature>"
}
```

### Verification

1. Extract `signature` block from proof input
2. Canonicalize proof input (excluding `signature`)
3. Verify `signature_value` against canonical bytes using `public_key`
4. Return: `VALID`, `INVALID`, or `UNKNOWN`

---

## 7. Proof Bundle Structure

```
SPE_Proof_YYYYMMDD_HHMMSS.zip
├── forensic_capsule.json    # Core attestation record
├── ledger.sqlite            # Append-only hash chain
├── proof_input.json         # Certification manifest + optional signature
└── verify/                  # Hermetic verification kit (optional)
    ├── verify_bundle.py     # Zero-dependency verification script
    └── capsule_ledger/      # Portable data structures
```

---

## 8. Verification Verdicts

| Verdict                  | Condition                                             |
| ------------------------ | ----------------------------------------------------- |
| LEDGER: VALID            | All hash-chain entries are mathematically correct     |
| LEDGER: INVALID          | At least one entry's hash doesn't match recomputation |
| CAPSULE_BINDING: VALID   | Capsule hash matches the ledger's recorded hash       |
| CAPSULE_BINDING: INVALID | Capsule hash does not match                           |
| SIGNATURE: VALID         | Ed25519 signature verified against public key         |
| SIGNATURE: INVALID       | Signature does not match canonical content            |
| SIGNATURE: UNKNOWN       | Cannot verify (no PyNaCl or no signature present)     |
| OBJECT: MATCH            | File hash matches capsule's output_hash               |
| OBJECT: MISMATCH         | File hash differs from capsule's output_hash          |

---

## 9. TVOC (Temporal Violation of Context)

### Detection Rule

A **Strong TVOC** is declared when:

1. The output text contains year references > `t_target`
2. The context contains NO post-target information (`context_has_post_target = False`)

### Year Extraction Pattern

```regex
\b(19|20)\d{2}\b
```

Matches 4-digit years from 1900-2099 at word boundaries.

---

## 10. Security Guarantees

| Property                       | Guarantee |
| ------------------------------ | --------- |
| Collision resistance (SHA-256) | 2^128     |
| Signature forgery (Ed25519)    | 2^128     |
| Ledger tampering detection     | 100%      |
| Single-byte modification       | Detected  |
| False negatives                | 0%        |

---

_Protocol Specification v2.6 — February 2026_
_Patent Pending — © 2024-2026 SPE Audit / Joinsnipe_
