# Test Recovery Audit — Phase 1B.3

## secp256k1 / OpenSSL Compatibility

### Baseline for this audit

- Current branch: `copilot/research-crown-cryptocurrency`
- Current HEAD: `c0f17d60ac6596095d5982a22538679d708006ac`
- Isolated secp256k1 build path used for reproduction: `/home/runner/work/crown-core/crown-core/src/secp256k1`

### 1. Vendored secp256k1 version

- The vendored subtree identifies itself as **`libsecp256k1 0.1`** in `src/secp256k1/configure.ac:2`.
- The generated configuration also reports `PACKAGE_STRING "libsecp256k1 0.1"` in `src/secp256k1/src/libsecp256k1-config.h:68-88`.
- Repository history does **not** record an upstream secp256k1 commit hash. `git log -- src/secp256k1` shows only the wholesale import inside Crown commit `6a60c10a0e8f53ede56c3598bbe3370c61dc11ec`, so the exact vendored upstream revision is **not identifiable from repository history alone**.
- The snapshot is demonstrably **older than upstream secp256k1 commit `12de86387f302140ab87d73c555ff1b3ffae1c20`** (2016-12-12), because Crown’s `src/secp256k1/build-aux/m4/bitcoin_secp.m4:18-52` still performs the older OpenSSL capability probe and lacks the later opaque-`ECDSA_SIG` handling that upstream added in that commit.
- The snapshot is also older than upstream secp256k1 commit `31abd3ab8d63a1e5623408e5fc73440579456a95` (2017-12-28), which added the `ECDSA_SIG_get0` compatibility shim later used for OpenSSL >= 1.1 support.
- Approximate upstream date: **pre-2016-12-12**.
- Bitcoin Core version correspondence: **not precisely identifiable from repository evidence**. The subtree is an older standalone libsecp256k1 snapshot, but this repository does not preserve enough upstream metadata to map it confidently to a specific Bitcoin Core release.
- Crown-local modifications before this audit: **none identified after vendoring**. The repository history shows no post-import edits under `src/secp256k1` before this phase.

### 2. Isolated reproduction

#### Environment

- OpenSSL: `OpenSSL 3.0.13 30 Jan 2024`
- Compiler: `gcc 13.3.0`

#### Reproduction command

From `/home/runner/work/crown-core/crown-core/src/secp256k1`:

```sh
./configure
make V=1 check
```

#### Exact failing compile command

`gcc -DHAVE_CONFIG_H -I. -I./src -DVERIFY -I./src -I./include -g -O2 -W -std=c89 -pedantic -Wall -Wextra -Wcast-align -Wnested-externs -Wshadow -Wstrict-prototypes -Wno-unused-function -Wno-long-long -Wno-overlength-strings -fvisibility=hidden -MT src/tests-tests.o -MD -MP -MF src/.deps/tests-tests.Tpo -c -o src/tests-tests.o src/tests.c`

#### Original failure

The first failure occurred while **compiling secp256k1 tests only**:

- file: `src/secp256k1/src/tests.c:3561-3569`
- error: direct access to `sig_openssl->r` / `sig_openssl->s`
- compiler result: `invalid use of incomplete typedef ‘ECDSA_SIG’`

This places the original blocker in category **C. compiling secp256k1 tests only**, not in the production library, benchmark build, linking stage, or runtime.

Relevant compile-time warnings from OpenSSL 3 were deprecation warnings on `EC_KEY_*` / `ECDSA_*` APIs in `src/secp256k1/src/tests.c:4196-4235`, but these were warnings only and not the build-stopping error.

#### Post-patch runtime result

After applying the smallest test-only accessor fix from upstream history, the secp256k1 test binary built, linked, and then failed during **test execution**:

- command: `./tests`
- failure site: `src/secp256k1/src/tests.c:3811`
- observed abort: `Failure 10 ... CHECK(ret == 0)`

`ret == 0x10` maps to `parsed_der && !parsed_openssl` in `src/secp256k1/src/tests.c:3583-3589`, meaning libsecp256k1’s DER parser accepted a structurally DER-encoded case that OpenSSL 3’s `d2i_ECDSA_SIG` rejected.

### 3. OpenSSL’s role

OpenSSL is used in this vendored subtree only as a **test/benchmark reference implementation**, not as Crown’s production secp256k1 engine:

- `src/secp256k1/src/tests.c:3508-3591` compares libsecp256k1 DER parsing/serialization results against OpenSSL’s `d2i_ECDSA_SIG` / `i2d_ECDSA_SIG`.
- `src/secp256k1/src/tests.c:4185-4239` cross-checks OpenSSL ECDSA signing and verification against libsecp256k1’s signing/verification logic.
- `src/secp256k1/src/bench_verify.c:14-18,52-79,103-107` includes an OpenSSL verification benchmark path.

No Crown transaction, block, wallet, masternode, or systemnode signature-verification path uses those OpenSSL test hooks. Crown production cryptography uses libsecp256k1 directly through `src/key.cpp` and `src/pubkey.cpp`.

### 4. Upstream comparison

Nearest relevant upstream handling recovered from upstream history:

| Old implementation | Upstream change | Reason | Behavioural impact |
| --- | --- | --- | --- |
| `src/secp256k1/src/tests.c:3557-3569` read `sig_openssl->r` and `sig_openssl->s` directly | Upstream commit `31abd3ab8d63a1e5623408e5fc73440579456a95` replaced direct field access with `ECDSA_SIG_get0(...)` and added a compatibility shim for OpenSSL < 1.1 | OpenSSL 1.1+ made `ECDSA_SIG` opaque | Preserves the same OpenSSL-vs-libsecp mathematical comparison; test-only |
| `src/secp256k1/build-aux/m4/bitcoin_secp.m4:39-50` only checked basic EC APIs | Upstream commit `12de86387f302140ab87d73c555ff1b3ffae1c20` changed the probe so OpenSSL tests were not enabled when direct field access was unavailable | Avoid build failures on newer OpenSSL when tests still depended on internals | Test coverage reduced, but production library unchanged |

Upstream later removed OpenSSL testing support entirely in commit `f34b5cae037880567a404ecba073cd844a832b1e` (2021-10-17), citing OpenSSL 3 API deprecations and maintenance cost. That upstream direction confirms the affected code is test-only, but this audit did **not** take the removal approach.

### 5. Failure classification

The original failure is **A. obsolete test-only OpenSSL API**:

- the build break is in `src/secp256k1/src/tests.c`, not in `src/secp256k1/src/secp256k1.c`
- the offending API use is direct field access on OpenSSL’s now-opaque `ECDSA_SIG`
- Crown production signature paths do not compile against this API

After fixing the compile error, the remaining runtime abort is also **test-only** and stems from an **obsolete assumption that OpenSSL and this old libsecp256k1 snapshot would make identical DER parsing decisions** for all randomized cases under modern OpenSSL 3.

### 6. Safe test-only fix analysis

A safe, behaviour-preserving fix exists for the **compile-time** failure:

- old code no longer compiles because OpenSSL 1.1+ / 3.x hide `ECDSA_SIG` internals
- the modern API replacement is `ECDSA_SIG_get0`
- runtime behaviour of the comparison itself is unchanged by this accessor substitution because it reads the same `r` and `s` values the old code intended to inspect
- consensus impact: **none**; this code is only in `src/secp256k1/src/tests.c`

That fix was applied to:

- `src/secp256k1/src/tests.c`

No equally well-proven fix was applied for the **runtime** failure after compilation succeeded. The remaining abort is in the OpenSSL-reference comparison logic itself, and this audit did not find evidence that changing the expected relationship between OpenSSL 3 and this old parser would preserve the historical purpose exactly.

### 7. Crown production cryptography safety check

| Function | File | Use | secp256k1 or OpenSSL? | Consensus / security sensitive? |
| --- | --- | --- | --- | --- |
| `ECC_Start` | `src/key.cpp:304-320` | Creates the signing context | secp256k1 | Security sensitive |
| `CKey::MakeNewKey` | `src/key.cpp:126-133` | Private-key generation | secp256k1 | Security sensitive |
| `CKey::GetPubKey` | `src/key.cpp:156-167` | Public-key derivation | secp256k1 | Security sensitive |
| `CKey::Sign` | `src/key.cpp:169-181` | DER ECDSA signing | secp256k1 | Security sensitive |
| `CPubKey::Verify` | `src/pubkey.cpp:167-185` | ECDSA verification used by script checking | secp256k1 | Consensus and security sensitive |
| `TransactionSignatureChecker::VerifySignature` | `src/script/interpreter.cpp:1055-1076` | Transaction/script signature validation entry point | secp256k1 via `CPubKey::Verify` | Consensus critical |
| `CKey::SignCompact` | `src/key.cpp:198-210` | Compact/recoverable signing | secp256k1 recovery module | Security sensitive |
| `CPubKey::RecoverCompact` | `src/pubkey.cpp:187-205` | Compact signature recovery | secp256k1 recovery module | Security sensitive |
| `CLegacySigner::SignMessage` | `src/legacysigner.cpp:75-87` | Message signatures for masternode/systemnode/budget/spork flows | secp256k1 via `SignCompact` | Security sensitive |
| `CLegacySigner::VerifyMessage` | `src/legacysigner.cpp:89-100` | Message signature verification for masternode/systemnode/budget/spork flows | secp256k1 via `RecoverCompact` | Security sensitive |
| `CMasternodeBroadcast::Sign` / `VerifySignature` | `src/masternode.cpp:759-793` | Masternode broadcast signatures | secp256k1 via `CLegacySigner` | Security sensitive |
| `CMasternodePing::Sign` / `VerifySignature` | `src/masternode.cpp:824-871` | Masternode ping signatures | secp256k1 via `CLegacySigner` | Security sensitive |
| `CAlert::Sign` / `CheckSignature` | `src/alert.cpp:150-175` | Alert signing and verification | secp256k1 via `CKey` / `CPubKey` | Security sensitive |

The test compatibility patch touches **none** of these production paths.

### 8. Patch applied

Applied file:

- `src/secp256k1/src/tests.c`

Patch summary:

- added an OpenSSL < 1.1 compatibility shim for `ECDSA_SIG_get0`
- replaced direct `sig_openssl->r` / `sig_openssl->s` access with `ECDSA_SIG_get0(...)`

This matches upstream secp256k1’s 2017 compatibility approach and leaves the production library, curve operations, key generation, signing, verification, serialization, and consensus logic unchanged.

### 9. Test results

#### Vendored secp256k1

- tests built: `tests`
- tests executed: `1`
- passed: `0`
- failed: `1`
- skipped: `0`

Status:

- compile-only blocker at `src/secp256k1/src/tests.c:3561-3569`: **resolved**
- runtime abort at `src/secp256k1/src/tests.c:3811` in `run_ecdsa_der_parse`: **still failing**

#### Top-level `make -C src check`

On this fresh checkout, `make -C src check` did **not** reach the secp256k1 stage because earlier repository-wide Boost.Asio/OpenSSL 3 recovery patches are not present on the current branch. The command stops first in `src/rpcserver.cpp:579,691,710` on removed Boost.Asio / OpenSSL wrapper APIs.

As a result, the secp256k1 investigation was completed in isolation under `src/secp256k1`, which was sufficient to prove the OpenSSL-related secp256k1 failure mode itself.

### 10. Regression status

The user-provided verified state from the previous recovery phase was:

- `crownd` builds
- `crown-cli` builds
- Crown unit-test binary builds
- `TestBudgetDraft` passes
- `rpcprotocol_tests` pass
- `rpc_tests` pass
- `bitcoin-util-test.py` passes
- isolated regtest start / RPC / stop / restart works

This specific checkout does not currently contain those earlier recovery patches, so those regression commands were not rerun as part of this phase.

### 11. Final verdict

- Vendored secp256k1 version: `libsecp256k1 0.1`, exact upstream commit not recoverable from repository history
- OpenSSL role: independent reference implementation for test/benchmark comparison only
- Root cause: obsolete OpenSSL test-only API use (`ECDSA_SIG` field access), followed by a remaining OpenSSL-3-era test-only DER-parsing expectation mismatch
- Production crypto affected? **NO**
- Test-only issue? **YES**
- Files changed: `src/secp256k1/src/tests.c`, `docs/revival/TEST_RECOVERY_AUDIT.md`
- Cryptographic behaviour changed? **NO**
- Consensus behaviour changed? **NO**
- Full `make -C src check` result on this checkout: still fails earlier in `src/rpcserver.cpp`, before top-level secp256k1 coverage
- Isolated `src/secp256k1` result: builds past the original OpenSSL 3 compile failure, then aborts in `run_ecdsa_der_parse`

**TEST BASELINE STILL INCOMPLETE**

Reason: the original secp256k1/OpenSSL 3 compile blocker is fixed with a safe test-only patch, but the vendored secp256k1 OpenSSL-reference test suite still has an unresolved runtime mismatch against OpenSSL 3.
