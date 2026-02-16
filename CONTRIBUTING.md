# Contributing to SPE

Thank you for your interest in contributing to SPE!

## Quick Start

```bash
git clone https://github.com/joinsnipe/SPE_AUDIT.git
cd SPE_AUDIT
pip install -r requirements.txt
pip install pytest  # For running tests
python -m pytest tests/ -v
```

## Areas for Contribution

### 🔧 Core Engine

- Performance optimizations
- Additional hash algorithms (SHA-3)
- Full Merkle tree implementation (replacing current MVP hash)

### 🌍 Language Implementations

We welcome ports of the SPE verification logic to other languages:

- **Node.js / TypeScript** — WebCrypto API based verifier
- **Go** — High-performance verification server
- **Rust** — WASM-compatible verifier for browsers

### 📝 Documentation

- Tutorials and integration guides
- Additional AI framework examples (LlamaIndex, Haystack, etc.)
- Translations

### 🔐 Post-Quantum Cryptography

- ML-DSA (Dilithium) integration research
- Hybrid signature schemes (Ed25519 + ML-DSA)

### 🧪 Testing

- Edge case discovery
- Fuzzing
- Cross-platform validation

## Code Guidelines

1. **Tests required** — All new features must include tests
2. **Determinism** — All cryptographic operations must be deterministic
3. **No external deps** — Core engine uses only Python stdlib + optional PyNaCl
4. **Hermetic verification** — The verify_kit must NEVER require external dependencies

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`python -m pytest tests/ -v`)
5. Submit a Pull Request

## License

By contributing, you agree that your contributions will be licensed under the BSL 1.1 license.

---

_Questions? Email contacto@speaudit.com_
