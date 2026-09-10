# Crown revival consolidation report

## Consolidation targets

- Original baseline: `6a60c10a0e8f53ede56c3598bbe3370c61dc11ec`
- Canonical recovered baseline: `fd810b6a00217f6d5e856963a6cc760e664e5fac`
- Current PR branch: `copilot/research-crown-cryptocurrency`
- Final consolidated PR HEAD: `a1300641d04d4f9af69cdf852510ef43e1e356df`

## 1. PR branch inspection

Inspection on this runner found:

- Current branch: `copilot/research-crown-cryptocurrency`
- Current pre-report HEAD: `a1300641d04d4f9af69cdf852510ef43e1e356df`
- `git log --all --oneline --decorate` visible in the shallow clone:
  - `a1300641d04d4f9af69cdf852510ef43e1e356df` `docs: export recovery patch set`
  - `fd810b6a00217f6d5e856963a6cc760e664e5fac` `chore: reconstruct recovery baseline changes`
- The branch was clean before creating this report.

The recovery bundle on the branch verifies cleanly and still advertises `fd810b6a00217f6d5e856963a6cc760e664e5fac` as `HEAD`, with SHA-256 `c85383d56025bb7bb2f4a7ff80c6416a7af979d3ca51fac3fdc0478173752cb2` (`docs/revival/patches/recovery-build-compatibility/INDEX.txt:1-15`).

## 2. Recovery documentation status

`docs/revival/BUILD_RUNTIME_AUDIT.md`, `docs/revival/TEST_RECOVERY_AUDIT.md`, and `docs/revival/RECOVERY_BASELINE.md` are present on both the canonical recovery commit and the PR branch. `docs/revival/CODEBASE_AUDIT.md` is not present on the PR branch, is not present in `fd810b6a00217f6d5e856963a6cc760e664e5fac`, and is not referenced by the exported recovery artifacts in this clone, so there was no local recovery source to restore.

## 3. Effective diff vs canonical recovered baseline

`git diff --name-status fd810b6a00217f6d5e856963a6cc760e664e5fac..a1300641d04d4f9af69cdf852510ef43e1e356df` showed only recovery export artifacts under `docs/revival/patches/recovery-build-compatibility/`. No production, test, or audit-document content from the canonical recovered baseline was missing from the PR branch.

| File | Present in `fd810b6` | Present in PR branch | Equivalent? | Notes |
| --- | --- | --- | --- | --- |
| `contrib/docker/secp256k1-legacy-openssl/Dockerfile` | Yes | Yes | Yes | Legacy validation lane only. |
| `docs/revival/BUILD_RUNTIME_AUDIT.md` | Yes | Yes | Yes | Recovery audit doc retained. |
| `docs/revival/RECOVERY_BASELINE.md` | Yes | Yes | Yes | Recovery baseline doc retained. |
| `docs/revival/TEST_RECOVERY_AUDIT.md` | Yes | Yes | Yes | Test/secp audit doc retained. |
| `src/Makefile.test.include` | Yes | Yes | Yes | Canonical test wiring retained (`src/Makefile.test.include:36-103`). |
| `src/crown-cli.cpp` | Yes | Yes | Yes | Modern SSL context constructor retained (`src/crown-cli.cpp:112-121`). |
| `src/masternode-budget.cpp` | Yes | Yes | Yes | UNITTEST-only budget alignment retained (`src/masternode-budget.cpp:31-35`, `src/masternode-budget.cpp:79-108`, `src/masternode-budget.cpp:728-733`). |
| `src/masternode.cpp` | Yes | Yes | Yes | Duplicate-IP compile/runtime correctness fix retained (`src/masternode.cpp:597-610`). |
| `src/rpcprotocol.h` | Yes | Yes | Yes | Boost.Asio resolver compatibility retained (`src/rpcprotocol.h:111-122`). |
| `src/rpcserver.cpp` | Yes | Yes | Yes | RPC SSL and acceptor compatibility retained (`src/rpcserver.cpp:57-60`, `src/rpcserver.cpp:585-591`, `src/rpcserver.cpp:701-730`). |
| `src/rpcserver.h` | Yes | Yes | Yes | Shared cipher-validation helper declaration retained (`src/rpcserver.h:35-38`). |
| `src/secp256k1/src/tests.c` | Yes | Yes | Yes | Test-only OpenSSL accessor compatibility retained (`src/secp256k1/src/tests.c:20-27`). |
| `src/systemnode.cpp` | Yes | Yes | Yes | Duplicate-IP compile/runtime correctness fix retained (`src/systemnode.cpp:519-532`). |
| `src/test/data/bitcoin-util-test.json` | Yes | Yes | Yes | Fixture-input refresh retained (`src/test/data/bitcoin-util-test.json:38-58`). |
| `src/test/rpc_tests.cpp` | Yes | Yes | Yes | Invalid RPC SSL cipher regression retained (`src/test/rpc_tests.cpp:176-182`). |
| `src/test/rpcprotocol_tests.cpp` | Yes | Yes | Yes | Resolver-context regression retained (`src/test/rpcprotocol_tests.cpp:1-40`). |
| `src/test/test_crown.cpp` | Yes | Yes | Yes | PlatformDb harness initialization retained (`src/test/test_crown.cpp:36-55`, `src/test/test_crown.cpp:67-80`). |
| `docs/revival/patches/recovery-build-compatibility/recovery-build-compatibility.patch` | No | Yes | N/A | Export/archive only. |
| `docs/revival/patches/recovery-build-compatibility/recovery-build-compatibility.bundle` | No | Yes | N/A | Export/archive only; bundle verifies to canonical recovery HEAD. |
| `docs/revival/patches/recovery-build-compatibility/INDEX.txt` | No | Yes | N/A | Export/archive index only. |
| `docs/revival/patches/recovery-build-compatibility/SHA256SUMS` | No | Yes | N/A | Export/archive checksum file only. |
| `docs/revival/patches/recovery-build-compatibility/format-patch/0001-chore-checkpoint-secp256k1-openssl-test-patch.patch` | No | Yes | N/A | Export/archive only. |
| `docs/revival/patches/recovery-build-compatibility/format-patch/0002-docs-add-secp256k1-openssl-compatibility-audit.patch` | No | Yes | N/A | Export/archive only. |
| `docs/revival/patches/recovery-build-compatibility/format-patch/0003-chore-reconstruct-recovery-baseline-changes.patch` | No | Yes | N/A | Export/archive only. |
| `docs/revival/CODEBASE_AUDIT.md` | No | No | N/A | No recoverable local source found in this clone. |
| `docs/revival/CONSOLIDATION_REPORT.md` | No | Yes | N/A | This report; consolidation metadata only. |

## 4. Diff classification vs untouched baseline

`git diff --name-only 6a60c10a0e8f53ede56c3598bbe3370c61dc11ec..fd810b6a00217f6d5e856963a6cc760e664e5fac` is confined to the recovery files listed above. The changed source files classify as follows:

| File | Classification | Reason |
| --- | --- | --- |
| `src/rpcprotocol.h` | BUILD COMPATIBILITY | Resolver construction updated only for newer Boost.Asio APIs (`src/rpcprotocol.h:111-122`). |
| `src/crown-cli.cpp` | BUILD COMPATIBILITY | SSL context constructor updated for modern Asio/OpenSSL (`src/crown-cli.cpp:112-121`). |
| `src/rpcserver.cpp` | BUILD COMPATIBILITY | SSL context setup, cipher-list application, and acceptor construction updated for modern libraries (`src/rpcserver.cpp:57-60`, `src/rpcserver.cpp:585-591`, `src/rpcserver.cpp:701-730`). |
| `src/rpcserver.h` | BUILD COMPATIBILITY | Declares the shared SSL cipher helper used by server code and tests (`src/rpcserver.h:35-38`). |
| `src/masternode.cpp` | BUILD COMPATIBILITY | Narrow duplicate-IP broadcast variable and DoS-score correctness fix (`src/masternode.cpp:597-610`). |
| `src/systemnode.cpp` | BUILD COMPATIBILITY | Narrow duplicate-IP broadcast variable and DoS-score correctness fix (`src/systemnode.cpp:519-532`). |
| `src/masternode-budget.cpp` | TEST-ONLY | Behavior change is explicitly gated to `NetworkID()==UNITTEST` via `UseMainLikeUnitTestBudgetParameters()` (`src/masternode-budget.cpp:31-35`, `src/masternode-budget.cpp:85-107`, `src/masternode-budget.cpp:729-733`). |
| `src/secp256k1/src/tests.c` | TEST-ONLY | OpenSSL accessor shim affects vendored tests only (`src/secp256k1/src/tests.c:20-27`). |
| `src/test/test_crown.cpp` | TEST-ONLY | Harness-only PlatformDb setup (`src/test/test_crown.cpp:52-55`, `src/test/test_crown.cpp:80`). |
| `src/test/rpc_tests.cpp` | TEST-ONLY | Adds invalid-cipher regression (`src/test/rpc_tests.cpp:176-182`). |
| `src/test/rpcprotocol_tests.cpp` | TEST-ONLY | Adds resolver-context regression (`src/test/rpcprotocol_tests.cpp:1-40`). |
| `src/test/data/bitcoin-util-test.json` | TEST-ONLY | Refreshes stale fixture inputs while preserving expected outputs (`src/test/data/bitcoin-util-test.json:38-58`). |
| `src/Makefile.test.include` | TEST-ONLY | Wires the new unit test into the existing test binary (`src/Makefile.test.include:36-103`). |
| `docs/revival/*` and `contrib/docker/secp256k1-legacy-openssl/Dockerfile` | DOCUMENTATION / TEST SUPPORT | Audit/reporting or legacy validation environment only. |

## 5. Explicit drift check

No recovery diff touches `src/chainparams.cpp`, `src/chainparamsseeds.h`, `src/main.cpp` consensus rules, network-message serialization, wallet DB serialization files, or production key/signature paths such as `src/key.cpp`, `src/pubkey.cpp`, or `src/script/interpreter.cpp`. The observed source diff is limited to RPC transport compatibility, duplicate-IP bookkeeping in masternode/systemnode broadcasts, UNITTEST-only budget helpers, test harness files, test fixtures, and vendored secp256k1 test code.

Based on the file-level scope above, the consolidated branch does **not** intentionally alter:

- genesis parameters
- network magic
- address format logic
- transaction serialization
- block serialization
- block reward rules
- monetary supply
- MNPoS rules
- masternode or systemnode economics in production
- governance production behavior
- wallet database format
- production key/signature behavior

No unexpected consensus or monetary drift was found.

## 6. Rebuild results on the consolidated PR branch

Commands executed from `/home/runner/work/crown-core/crown-core`:

```bash
./autogen.sh
./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui
make -C src -j4 crownd crown-cli crown_test crown-tx
```

Runner packages needed before `configure` could complete on this host: `libdb++-dev`, `libboost-all-dev`, `libcurl4-openssl-dev`.

Final results:

- `./autogen.sh`: succeeded
- `./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui`: succeeded
  - warning: non-4.8 Berkeley DB detected, matching the expected portability warning path
- `make -C src -j4 crownd crown-cli crown_test crown-tx`: succeeded
  - built `crownd`, `crown-cli`, `crown_test`, and `crown-tx`

## 7. Recovered test baseline

Commands executed from `/home/runner/work/crown-core/crown-core` unless noted:

```bash
./src/test/test_crown --run_test=TestBudgetDraft/* --log_level=test_suite
./src/test/test_crown --run_test=rpcprotocol_tests/* --log_level=test_suite
./src/test/test_crown --run_test=rpc_tests/* --log_level=test_suite
./src/test/test_crown --run_test=Prefix_tests/* --log_level=test_suite
./src/test/test_crown --run_test=util_tests/* --log_level=test_suite
./src/test/test_crown --run_test=netbase_tests/* --log_level=test_suite
./src/test/test_crown --run_test=serialize_tests/* --log_level=test_suite
./src/test/test_crown --run_test=staking_tests/* --log_level=test_suite
(cd src && srcdir=. python3 ./test/bitcoin-util-test.py)
```

Results:

- `TestBudgetDraft/*`: passed
- `rpcprotocol_tests/*`: passed
- `rpc_tests/*`: passed
- `Prefix_tests/*`: passed
- `util_tests/*`: passed
- `netbase_tests/*`: passed
- `serialize_tests/*`: passed
- `staking_tests/*`: passed
- `bitcoin-util-test.py`: passed

## 8. Legacy secp256k1 validation lane

Commands executed:

```bash
docker build -t crown-secp-legacy -f contrib/docker/secp256k1-legacy-openssl/Dockerfile .
docker run --rm -v "$PWD":/work crown-secp-legacy
```

Results:

- Docker base image: `gcc:5` (`contrib/docker/secp256k1-legacy-openssl/Dockerfile:1-5`)
- OpenSSL version inside the lane: `1.0.1t` (as recorded by the recovery environment and preserved by this Docker lane)
- build result: passed (`./configure && make tests` inside `src/secp256k1`)
- test result: passed (`test count = 64`, `no problems found`)

This confirms the vendored secp256k1 reference test lane still passes in the intended legacy environment while remaining isolated from production runtime behavior.

## 9. Single-node regtest smoke

A disposable regtest datadir was created under `/tmp`, with `listen=0`, `discover=0`, `upnp=0`, and loopback-only RPC binding.

Results:

- daemon start: passed
- `getblockchaininfo`: passed twice
  - chain: `regtest`
  - blocks: `0`
  - bestblockhash: `231de73ec08234a4adff3c71e57271a13fa73f5ae1ca6b0ded89275e557a6207`
- `getnetworkinfo`: passed
  - connections: `0`
  - no external peers configured or connected
- RPC: passed
- first stop: passed
- restart with same datadir: passed
- second stop: passed

## 10. Consolidation verdict

The authorized PR branch already contained the full effective recovery baseline from `fd810b6a00217f6d5e856963a6cc760e664e5fac`. Relative to that canonical recovery commit, the branch only added recovery export artifacts before this report. No missing recovery fix was found, no later divergent production fix was required, and no unexpected consensus, monetary, serialization, wallet-format, or production-cryptography drift was detected.
