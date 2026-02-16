# AI Output Certification Guide

## How SPE Certifies AI Outputs

SPE provides **mathematical proof** that an AI-generated output existed in a specific form at a specific time, and optionally, what context (documents) the AI had access to.

---

## What Gets Certified

When you certify an AI output through SPE, the following is cryptographically recorded:

| Field                 | Description                                          | Example                  |
| --------------------- | ---------------------------------------------------- | ------------------------ |
| `output_hash`         | SHA-256 hash of the AI's response                    | `sha256:7f83b165...`     |
| `hash_prompt`         | SHA-256 hash of the prompt sent to the AI            | `a3b8d1b6...`            |
| `model_id`            | Identifier of the AI model used                      | `gpt-4`, `claude-3-opus` |
| `t_run`               | Unix timestamp of when the certification was created | `1708099200`             |
| `t_target`            | Declared time boundary for context validity          | `2025`                   |
| `context_merkle_root` | Hash of all context documents available to the AI    | `9c1a1a2b...`            |
| `gate_policy_id`      | The gating policy applied                            | `strict`                 |

---

## Integration Levels

### Level 1: Output Only (2 lines of code)

**What it proves:** "This exact response existed at this timestamp."

```python
from spe_engine import generate_proof

# After getting AI response
ai_response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Explain quantum computing"}]
)

# Certify the output
proof = generate_proof(
    content=ai_response.choices[0].message.content,
    model_id="gpt-4",
    artifact_type="ai-output",
)
print(f"Certified. Hash: {proof.capsule_hash}")
```

### Level 2: Prompt + Output (5 lines of code)

**What it proves:** "This exact question produced this exact answer at this time."

```python
prompt = "What is the capital of France?"
response = "The capital of France is Paris."

# Certify the full exchange
full_exchange = f"PROMPT: {prompt}\n\nRESPONSE: {response}"
proof = generate_proof(
    content=full_exchange,
    model_id="gpt-4",
    artifact_type="ai-output",
)
```

### Level 3: Context + Prompt + Output (RAG Workflows)

**What it proves:** "The AI had access to these specific documents when it generated this response."

```python
from spe_engine.core.context import ContextItem
from spe_engine.core.temporal import apply_temporal_gating
from spe_engine.core.context import canonicalize_context, serialize_canonical_context
from spe_engine.core.merkle import compute_context_merkle_root
from spe_engine.crypto.hash import sha256_hex

# Define the documents fed to the AI
context_items = [
    ContextItem(
        doc_id="q3-report-2025",
        content_hash=sha256_hex(open("q3_report.pdf", "rb").read()),
        timestamp=1727740800,  # 2024-10-01
        source_id="rag-index-v2",
    ),
    ContextItem(
        doc_id="policy-manual-v5",
        content_hash=sha256_hex(open("policy.pdf", "rb").read()),
        timestamp=1719792000,  # 2024-07-01
        source_id="rag-index-v2",
    ),
]

# Apply temporal gating (only include docs available at t_target)
gated = apply_temporal_gating(context_items, t_target=2025)

# Compute context merkle root
canonical = canonicalize_context(gated)
serialized = serialize_canonical_context(canonical)
merkle_root = compute_context_merkle_root(serialized)

print(f"Context Merkle Root: {merkle_root}")
# This root is recorded in the ForensicCapsule
```

---

## TVOC Detection (Novel Forensic Signal)

**TVOC (Temporal Violation of Context)** is an SPE-originated forensic signal that detects when an AI model produces information about events beyond its declared temporal boundary.

### How It Works

```python
from spe_engine.tvoc import detect_tvoc_strong

# Scenario: AI was asked about events up to 2025
# but its response mentions 2027
result = detect_tvoc_strong(
    output_text="In 2027, the European AI Act enforcement expanded to cover...",
    t_target=2025,
    context_has_post_target=False,  # AI had no post-2025 context
)

print(result)
# {
#   "tvoc": "STRONG",
#   "violating_years": [2027],
#   "t_target": 2025
# }
```

### TVOC Verdicts

| Verdict    | Meaning                                                  |
| ---------- | -------------------------------------------------------- |
| **STRONG** | AI referenced future years WITHOUT post-target context   |
| **NONE**   | All temporal references are within the declared boundary |

### Why TVOC Matters

- **Legal Evidence**: Proves an AI could not have legitimately known certain information
- **Compliance**: Demonstrates AI model behavior is temporally consistent
- **Forensics**: Detects potentially fabricated or manipulated AI outputs
- **Research**: Identifies AI hallucination patterns related to temporal knowledge

---

## Verification

### Verify Programmatically

```python
from spe_engine import verify_proof

result = verify_proof(bundle_path="SPE_Proof_20260216.zip")
print(f"Valid: {result.valid}")
print(f"Ledger: {result.checks['LEDGER']}")
print(f"Capsule Binding: {result.checks['CAPSULE_BINDING']}")
```

### Verify Offline (No Dependencies)

Every proof bundle includes a standalone verification script:

```bash
cd verify/
python verify_bundle.py \
    --capsule ../forensic_capsule.json \
    --ledger ../ledger.sqlite
```

This script uses **zero external dependencies** — it runs anywhere Python 3.9+ is installed.

---

## Ed25519 Signing (Optional)

Add origin attribution to your proofs:

```python
import base64
from nacl.signing import SigningKey

# Generate a key pair (do this once, store securely)
sk = SigningKey.generate()
private_key_b64 = base64.b64encode(sk.encode()).decode("ascii")
public_key_b64 = base64.b64encode(sk.verify_key.encode()).decode("ascii")

print(f"Public Key: {public_key_b64}")  # Share this
# NEVER share private_key_b64

# Generate a signed proof
proof = generate_proof(
    content="AI-certified response",
    model_id="gpt-4",
    artifact_type="ai-output",
    sign_key_b64=private_key_b64,
)
print(f"Signed: {proof.signed}")  # True
```

---

## Supported AI Models

SPE is model-agnostic. Use the `model_id` field to record any model:

| Provider  | model_id Examples                  |
| --------- | ---------------------------------- |
| OpenAI    | `gpt-4`, `gpt-4-turbo`, `gpt-4o`   |
| Anthropic | `claude-3-opus`, `claude-3-sonnet` |
| Google    | `gemini-pro`, `gemini-ultra`       |
| Meta      | `llama-3-70b`, `llama-3.1-405b`    |
| Mistral   | `mistral-large`, `mixtral-8x7b`    |
| Local     | `local-llama`, `self-hosted-model` |
| Custom    | Any string identifier you define   |

---

## Production Deployment Patterns

### Pattern 1: Middleware Certification

```python
# FastAPI middleware that auto-certifies every AI response
@app.middleware("http")
async def certify_ai_responses(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/ai/"):
        body = await response.body()
        proof = generate_proof(
            content=body.decode("utf-8"),
            model_id=request.headers.get("X-Model-ID", "unknown"),
            artifact_type="ai-output",
        )
        response.headers["X-SPE-Capsule-Hash"] = proof.capsule_hash
    return response
```

### Pattern 2: Batch Certification

```python
# Certify a batch of AI outputs from a log file
import json

with open("ai_outputs_log.jsonl") as f:
    for line in f:
        entry = json.loads(line)
        proof = generate_proof(
            content=entry["response"],
            model_id=entry["model"],
            artifact_type="ai-output",
            t_target=entry["timestamp"],
        )
        print(f"Certified: {entry['id']} -> {proof.capsule_hash[:16]}...")
```

### Pattern 3: LangChain Integration

```python
from langchain.callbacks.base import BaseCallbackHandler
from spe_engine import generate_proof

class SPECertificationCallback(BaseCallbackHandler):
    def on_llm_end(self, response, **kwargs):
        text = response.generations[0][0].text
        proof = generate_proof(
            content=text,
            model_id=kwargs.get("model_name", "langchain"),
            artifact_type="ai-output",
        )
        print(f"SPE Certified: {proof.capsule_hash[:16]}...")
```

---

## What SPE Does NOT Certify

| Claim                              | SPE Guarantees? |
| ---------------------------------- | --------------- |
| The AI output is TRUE              | ❌ No           |
| The AI was not biased              | ❌ No           |
| The human didn't edit it           | ❌ No           |
| The prompt was authentic           | ❌ No           |
| The AI actually ran                | ❌ No           |
| **The output hasn't been altered** | ✅ Yes          |
| **When the proof was created**     | ✅ Yes          |
| **Which model was declared**       | ✅ Yes          |
| **Which context was declared**     | ✅ Yes          |

SPE guarantees **mathematical integrity**, not truth. The proof certifies that
the content existed in a specific form at a specific time — nothing more, nothing less.

---

_SPE — Stateless. Portable. Verifiable._

_Patent Pending — © 2024-2026 SPE Audit / Joinsnipe_
