# Recovery Baseline — Phase 1B.4

This document consolidates the verified Crown recovery work onto `recovery/build-compatibility` and records the reproducible baseline used before any distributed-network testing.

## 1. Baseline snapshot

| Item | Value |
| --- | --- |
| Recovery branch | `recovery/build-compatibility` |
| Historical comparison baseline | `6a60c10a0e8f53ede56c3598bbe3370c61dc11ec` |
| Modern host | Ubuntu 24.04.4 LTS |
| Modern compiler | `gcc 13.3.0` |
| Modern OpenSSL | `OpenSSL 3.0.13 30 Jan 2024` |
| Legacy container image | `gcc:5` |
| Legacy compiler | `gcc 5.5.0` |
| Legacy OpenSSL | `OpenSSL 1.0.1t 3 May 2016` |

## 2. Recovery commit ledger

| Commit | Purpose |
| --- | --- |
| `4ac09f9fb` | Added `docs/revival/BUILD_RUNTIME_AUDIT.md`. |
| `c0f17d60a` | Added the vendored secp256k1 OpenSSL accessor compatibility patch in `src/secp256k1/src/tests.c`. |
| `e930e97d3` | Added `docs/revival/TEST_RECOVERY_AUDIT.md` for the secp256k1/OpenSSL compatibility audit. |
| consolidated recovery patch | Reapplies the verified build-compatibility and test-recovery changes missing from the shallow checkout: Boost.Asio/OpenSSL RPC compatibility, test harness PlatformDb setup, UNITTEST governance timing/total-budget recovery, bitcoin utility fixture repair, and regression tests. |

## 3. Production-source diff classification vs `6a60c10a0e8f53ede56c3598bbe3370c61dc11ec`

| File | Class | Change | Why required | Runtime behaviour changed? | Wire behaviour changed? | Consensus behaviour changed? | Wallet format changed? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `src/rpcprotocol.h` | BUILD COMPATIBILITY | Resolver construction now uses the stream executor context on Boost >= 1.70. | Modern Boost.Asio removed `get_io_service()`. | NO | NO | NO | NO |
| `src/crown-cli.cpp` | BUILD COMPATIBILITY | RPC SSL context now uses the modern constructor form. | Modern Boost.Asio removed the `io_service`-accepting `ssl::context` constructor. | NO | NO | NO | NO |
| `src/rpcserver.h` | BUILD COMPATIBILITY | Declares the shared RPC SSL cipher validation helper. | Needed so the recovered regression test can call the same production helper. | NO | NO | NO | NO |
| `src/rpcserver.cpp` | BUILD COMPATIBILITY / BUG FIX | RPC accept loop now uses the acceptor executor context on Boost >= 1.70, RPC SSL context uses the modern constructor, and invalid `-rpcsslciphers` now fails deterministically through a shared helper. | Modern Boost.Asio/OpenSSL wrappers removed the historical APIs; invalid cipher strings were previously ignored silently on this host. | YES, but RPC-local only for invalid `-rpcsslciphers` startup handling | NO | NO | NO |
| `src/masternode.cpp` | BUILD COMPATIBILITY | Duplicate-address lookup and DoS bookkeeping now use the correct local names. | Restores successful compilation without changing the duplicate-IP logic. | NO | NO | NO | NO |
| `src/systemnode.cpp` | BUILD COMPATIBILITY | Duplicate-address lookup and DoS bookkeeping now use the correct local names. | Restores successful compilation without changing the duplicate-IP logic. | NO | NO | NO | NO |
| `src/masternode-budget.cpp` | TEST-ONLY BEHAVIOUR | UNITTEST now reuses main-like budget cycle, submission threshold, voting threshold, and total-budget calculations. | The recovered governance fixtures expect main-like superblock timing and payout totals under UNITTEST. | YES, UNITTEST-only | NO | NO | NO |
| `src/secp256k1/src/tests.c` | TEST-ONLY BEHAVIOUR | Vendored OpenSSL-reference tests now use `ECDSA_SIG_get0` with an OpenSSL < 1.1 compatibility shim. | OpenSSL 1.1+/3.x made `ECDSA_SIG` opaque; this preserves the original comparison while leaving libsecp256k1 itself unchanged. | NO in production | NO | NO | NO |

## 4. Modern test baseline

Expected recovered lane:

```bash
./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui
make -C src -j4 crownd crown-cli crown_test crown-tx
./src/test/test_crown --run_test=TestBudgetDraft/* --log_level=test_suite
./src/test/test_crown --run_test=rpcprotocol_tests/* --log_level=test_suite
./src/test/test_crown --run_test=rpc_tests/* --log_level=test_suite
(cd src && srcdir=. python3 ./test/bitcoin-util-test.py)
```

## 5. Legacy secp256k1 / OpenSSL reference lane

Committed Docker configuration:

- `contrib/docker/secp256k1-legacy-openssl/Dockerfile`

Reference commands:

```bash
docker build -t crown-secp256k1-legacy -f contrib/docker/secp256k1-legacy-openssl/Dockerfile .
docker run --rm -v /home/runner/work/crown-core/crown-core:/work crown-secp256k1-legacy
```

Expected result: the vendored `src/secp256k1/tests` passes in the legacy lane with OpenSSL 1.0.1t and still fails only in modern OpenSSL 3 reference-test execution.

## 6. Verdict

- Production crypto affected? **NO**
- Test-only issue? **YES**
- Cryptographic behaviour changed? **NO**
- Consensus behaviour changed? **NO**

**RECOVERY BASELINE ESTABLISHED**
