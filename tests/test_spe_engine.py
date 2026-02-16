"""
SPE Engine — Test Suite

Validates:
  1. Capsule hash determinism
  2. Ledger integrity (append + verify)
  3. Proof input canonicalization (key-order invariance)
  4. Proof input signature exclusion
  5. Proof input hashing (semantic sensitivity)
  6. Ed25519 signature roundtrip
  7. Ed25519 tampering detection
  8. TVOC detection (Strong)
  9. TVOC detection (no violation)
  10. Full proof generation (text mode)
  11. Full proof generation (hash-only mode)
  12. Full proof verification
"""

import base64
import json
import tempfile
from pathlib import Path

import pytest

from spe_engine.core.capsule import ForensicCapsule
from spe_engine.core.ledger import AttestationLedger
from spe_engine.proof_input.canonical import canonicalize_proof_input
from spe_engine.proof_input.hash import hash_proof_input
from spe_engine.tvoc.detector import detect_tvoc_strong
from spe_engine.tvoc.extract import extract_years
from spe_engine.api import generate_proof, verify_proof


# ── Capsule Tests ──────────────────────────────────────────────

def test_capsule_hash_is_deterministic():
    """Same inputs must always produce the same capsule hash."""
    c = ForensicCapsule(
        t_target=100,
        gate_policy_id="strict",
        context_merkle_root="abc",
        model_id="gpt-4",
        hash_prompt="p123",
        t_run=1234567890,
        output_hash="o456",
    )
    h1 = c.capsule_hash()
    h2 = c.capsule_hash()
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


# ── Ledger Tests ───────────────────────────────────────────────

def test_ledger_append_and_verify():
    """Ledger chain must verify after multiple appends."""
    work = Path(tempfile.mkdtemp(prefix="spe_test_"))
    db_path = work / "ledger.sqlite"
    ledger = AttestationLedger(str(db_path))

    c1 = ForensicCapsule(
        t_target=100, gate_policy_id="strict", context_merkle_root="r1",
        model_id="gpt-4", hash_prompt="p", t_run=111, output_hash="o1",
    )
    c2 = ForensicCapsule(
        t_target=200, gate_policy_id="strict", context_merkle_root="r2",
        model_id="claude-3", hash_prompt="p", t_run=222, output_hash="o2",
    )

    ledger.append(c1.capsule_hash(), t_run=c1.t_run)
    ledger.append(c2.capsule_hash(), t_run=c2.t_run)

    assert ledger.verify() is True
    assert ledger.count() == 2


# ── Proof Input Canonicalization ───────────────────────────────

def test_canonical_determinism_key_order():
    """Key order must not affect canonical output."""
    a = {
        "schema_version": "proof-input-hash-only/1.0",
        "hash_algorithm": "sha256",
        "hash_value": "a" * 64,
        "t_run": "2026-02-16T10:00:00Z",
        "context": {"domain": "ai-output", "purpose": "attestation"},
    }
    b = {
        "context": {"purpose": "attestation", "domain": "ai-output"},
        "t_run": "2026-02-16T10:00:00Z",
        "hash_value": "a" * 64,
        "hash_algorithm": "sha256",
        "schema_version": "proof-input-hash-only/1.0",
    }
    assert canonicalize_proof_input(a) == canonicalize_proof_input(b)


def test_signature_excluded_from_canonical():
    """Signature field must be excluded from canonical bytes."""
    base = {
        "schema_version": "proof-input-hash-only/1.0",
        "hash_algorithm": "sha256",
        "hash_value": "b" * 64,
        "t_run": "2026-02-16T10:00:00Z",
        "context": {"domain": "ai-output", "purpose": "attestation"},
    }
    with_sig = dict(base)
    with_sig["signature"] = {
        "algorithm": "ed25519",
        "public_key": "AAA=",
        "signature_value": "BBB=",
    }
    assert canonicalize_proof_input(base) == canonicalize_proof_input(with_sig)


# ── Proof Input Hashing ───────────────────────────────────────

def test_hash_changes_on_semantic_change():
    """Different hash_value must produce different proof input hashes."""
    base = {
        "schema_version": "proof-input-text/1.0",
        "hash_algorithm": "sha256",
        "hash_value": "c" * 64,
        "t_run": "2026-02-16T10:00:00Z",
        "context": {"domain": "ai-output", "purpose": "attestation"},
    }
    modified = dict(base)
    modified["hash_value"] = "d" * 64

    h1 = hash_proof_input(canonicalize_proof_input(base))
    h2 = hash_proof_input(canonicalize_proof_input(modified))
    assert h1 != h2


def test_hash_ignores_signature():
    """Signature field must not affect hash."""
    base = {
        "schema_version": "proof-input-text/1.0",
        "hash_algorithm": "sha256",
        "hash_value": "e" * 64,
        "t_run": "2026-02-16T10:00:00Z",
        "context": {"domain": "ai-output", "purpose": "attestation"},
    }
    with_sig = dict(base)
    with_sig["signature"] = {
        "algorithm": "ed25519",
        "public_key": "AAA=",
        "signature_value": "BBB=",
    }

    h1 = hash_proof_input(canonicalize_proof_input(base))
    h2 = hash_proof_input(canonicalize_proof_input(with_sig))
    assert h1 == h2


# ── Ed25519 Signature Tests ───────────────────────────────────

def test_signature_roundtrip():
    """Sign and verify must roundtrip correctly."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        pytest.skip("PyNaCl not installed")

    from spe_engine.proof_input.signature import sign_proof_input, verify_proof_input_signature

    sk = SigningKey.generate()
    private_b64 = base64.b64encode(sk.encode()).decode("ascii")

    proof_input = {
        "schema_version": "proof-input-text/1.0",
        "hash_algorithm": "sha256",
        "hash_value": "f" * 64,
        "t_run": "2026-02-16T10:00:00Z",
        "context": {"domain": "ai-output", "purpose": "attestation"},
    }

    sig = sign_proof_input(proof_input, private_b64)
    proof_input["signature"] = sig

    assert verify_proof_input_signature(proof_input) == "VALID"


def test_signature_detects_tampering():
    """Signature must fail if content is modified after signing."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        pytest.skip("PyNaCl not installed")

    from spe_engine.proof_input.signature import sign_proof_input, verify_proof_input_signature

    sk = SigningKey.generate()
    private_b64 = base64.b64encode(sk.encode()).decode("ascii")

    proof_input = {
        "schema_version": "proof-input-text/1.0",
        "hash_algorithm": "sha256",
        "hash_value": "f" * 64,
        "t_run": "2026-02-16T10:00:00Z",
        "context": {"domain": "ai-output", "purpose": "attestation"},
    }

    sig = sign_proof_input(proof_input, private_b64)

    # Tamper with the content
    tampered = dict(proof_input)
    tampered["hash_value"] = "0" * 64
    tampered["signature"] = sig

    assert verify_proof_input_signature(tampered) == "INVALID"


# ── TVOC Tests ─────────────────────────────────────────────────

def test_tvoc_strong_detection():
    """TVOC must detect when AI references future years."""
    result = detect_tvoc_strong(
        output_text="In 2027, the EU passed new AI regulations that expanded...",
        t_target=2025,
        context_has_post_target=False,
    )
    assert result["tvoc"] == "STRONG"
    assert 2027 in result["violating_years"]


def test_tvoc_no_violation():
    """TVOC must be NONE when all years are within bounds."""
    result = detect_tvoc_strong(
        output_text="In 2024, OpenAI released GPT-4o which improved on 2023 models.",
        t_target=2025,
        context_has_post_target=False,
    )
    assert result["tvoc"] == "NONE"
    assert result["violating_years"] == []


def test_year_extraction():
    """Year extraction must find all 19XX/20XX patterns."""
    years = extract_years("Founded in 1999, expanded in 2015, projected for 2030.")
    assert 1999 in years
    assert 2015 in years
    assert 2030 in years


# ── Integration Tests ──────────────────────────────────────────

def test_generate_proof_text_mode():
    """Full proof generation in text mode."""
    result = generate_proof(
        content="GPT-4 says: the answer to the ultimate question is 42.",
        model_id="gpt-4",
        artifact_type="ai-output",
    )
    assert Path(result.zip_path).exists()
    assert len(result.capsule_hash) == 64
    assert len(result.output_hash) == 64
    assert result.mode == "text"


def test_generate_proof_hash_only_mode():
    """Full proof generation in hash-only (zero-upload) mode."""
    result = generate_proof(
        hash_hex="a" * 64,
        artifact_type="ai-output",
        model_id="claude-3-opus",
    )
    assert Path(result.zip_path).exists()
    assert result.output_hash == "a" * 64
    assert result.mode == "hash-only"


def test_verify_proof_roundtrip():
    """Generate then verify — must be VALID."""
    result = generate_proof(
        content="Claude says: I think, therefore I certify.",
        model_id="claude-3-sonnet",
        artifact_type="ai-output",
    )

    verify = verify_proof(bundle_path=result.zip_path)

    assert verify.valid is True
    assert verify.ledger_valid is True
    assert verify.capsule_binding is True
    assert verify.checks["LEDGER"] == "VALID"
    assert verify.checks["CAPSULE_BINDING"] == "VALID"


def test_verify_detects_file_mismatch():
    """Verify must detect MISMATCH when file content differs."""
    work = Path(tempfile.mkdtemp(prefix="spe_test_"))
    original = work / "report.txt"
    original.write_text("Original AI report content.", encoding="utf-8")

    result = generate_proof(file_path=str(original))

    # Modify the file after certification
    original.write_text("TAMPERED AI report content!", encoding="utf-8")

    verify = verify_proof(
        bundle_path=result.zip_path,
        original_file=str(original),
    )

    assert verify.match_status == "MISMATCH"
