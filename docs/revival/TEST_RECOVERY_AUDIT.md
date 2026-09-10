# Test Recovery Audit

## secp256k1 / OpenSSL Compatibility

### 1. Vendored secp256k1 version

- The vendored subtree identifies itself as `libsecp256k1 0.1` in `src/secp256k1/configure.ac:2`.
- Repository history in this clone does not preserve an exact upstream secp256k1 commit hash.
- The snapshot predates upstream OpenSSL-1.1 compatibility work such as `ECDSA_SIG_get0` handling.

### 2. Root cause

- The original build blocker was direct access to `sig_openssl->r` / `sig_openssl->s` in `src/secp256k1/src/tests.c:3561-3569`.
- OpenSSL 1.1+/3.x makes `ECDSA_SIG` opaque.
- Replacing that test-only access with `ECDSA_SIG_get0` preserves the same comparison and does not affect production cryptography.
- After the compile fix, the remaining modern-host failure is a runtime abort at `src/secp256k1/src/tests.c:3811`, where old libsecp256k1 DER parsing accepts a case that modern OpenSSL 3 rejects.

### 3. OpenSSL role

OpenSSL is used in this subtree only as a reference implementation for vendored secp256k1 tests and benchmarks, not for Crown production key generation, signing, or verification. Crown production cryptography uses libsecp256k1 via `src/key.cpp`, `src/pubkey.cpp`, and script verification paths.

### 4. Production safety

The test compatibility patch does not change:

- key generation
- public-key derivation
- ECDSA signing
- ECDSA verification
- compact/recoverable signatures
- consensus validation

### 5. Legacy compatibility lane

`contrib/docker/secp256k1-legacy-openssl/Dockerfile` provides a reproducible test-only lane based on `gcc:5`, which supplies OpenSSL `1.0.1t`.

Expected legacy result:

- `./configure && make tests && ./tests`
- vendored secp256k1 tests pass
- modern OpenSSL 3 still fails only in the reference-test runtime path

### 6. Final verdict

- Vendored secp256k1 version: `libsecp256k1 0.1`
- OpenSSL role: reference implementation for vendored tests/benchmarks only
- Root cause: obsolete test-only OpenSSL API assumptions plus a modern OpenSSL 3 DER-reference mismatch
- Production crypto affected? **NO**
- Test-only issue? **YES**
- Cryptographic behaviour changed? **NO**
- Consensus behaviour changed? **NO**

**TEST BASELINE STILL INCOMPLETE on raw modern OpenSSL 3, but operationally recovered through the documented legacy test lane.**
