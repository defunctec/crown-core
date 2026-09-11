# Crown Phase 0B Build / Runtime Audit

This document records **executed** evidence gathered on the repository at the exact baseline below. It does **not** attempt to repair Crown. Failed commands are included as audit results.

Repository working tree used for all commands: `/home/runner/work/crown-core/crown-core`

## 1. Exact baseline

| Item | Value |
| --- | --- |
| Task repository | `defunctec/crown-core` |
| `origin` remote URL | `http://localhost:26831/defunctec/crown-core` |
| Branch | `copilot/research-crown-cryptocurrency` |
| Exact commit SHA | `6a60c10a0e8f53ede56c3598bbe3370c61dc11ec` |
| Git status before starting | Clean (`## copilot/research-crown-cryptocurrency...origin/copilot/research-crown-cryptocurrency`) |
| Operating system | Ubuntu 24.04.4 LTS (`Linux 6.17.0-1022-azure`) |
| Architecture | `x86_64` |
| CPU available | 4 vCPUs (`AMD EPYC 9V74 80-Core Processor`) |
| RAM available | 15 GiB total, ~13 GiB available at capture time |
| Compiler | `gcc/g++ 13.3.0`, `clang 18.1.3` |
| Autotools | `autoconf 2.71`, `automake 1.16.5`, `libtoolize 2.4.7`, `aclocal 1.16.5` |
| Python | `Python 3.12.3` |
| CMake | `3.31.6` |

Exact baseline command outputs:

```text
REMOTE_URL=http://localhost:26831/defunctec/crown-core
BRANCH=copilot/research-crown-cryptocurrency
SHA=6a60c10a0e8f53ede56c3598bbe3370c61dc11ec
GIT_STATUS_BEGIN
## copilot/research-crown-cryptocurrency...origin/copilot/research-crown-cryptocurrency
GIT_STATUS_END
```

```text
Architecture: x86_64
CPU(s): 4
Model name: AMD EPYC 9V74 80-Core Processor
Mem: 15Gi total / 13Gi available
```

## 2. Clean Autotools build

`doc/build-unix.md` presents `./autogen.sh`, `./configure`, `make` as the primary Unix build flow (`/home/runner/work/crown-core/crown-core/doc/build-unix.md:15-25`).

### 2.1 Exact commands executed

```bash
cd /home/runner/work/crown-core/crown-core
/usr/bin/time -v ./autogen.sh
/usr/bin/time -v ./configure
sudo apt-get update
sudo apt-get install -y libdb4.8-dev libdb4.8++-dev
sudo apt-get install -y build-essential libtool autotools-dev autoconf automake pkg-config libssl-dev libboost-all-dev libdb5.3-dev libdb5.3++-dev libevent-dev libminiupnpc-dev qtbase5-dev qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler libqrencode-dev
sudo apt-get install -y libcurl4-openssl-dev
/usr/bin/time -v ./configure
/usr/bin/time -v ./configure --with-incompatible-bdb
/usr/bin/time -v ./configure --with-incompatible-bdb --with-unsupported-ssl
/usr/bin/time -v make
/usr/bin/time -v make -C src crown-cli
/usr/bin/time -v make -C src crownd
/usr/bin/time -v make -C src crown_test
```

### 2.2 Autogen result

`./autogen.sh` completed successfully in **~9 seconds**.

Notable warnings:

- `configure.ac:28: warning: The macro 'AC_PROG_CC_C89' is obsolete.`
- `Makefile.am` overrides Automake `GZIP_ENV` and `distcleancheck`.
- `src/Makefile.am` overrides the `.mm.o` target.

### 2.3 Configure sequence and blockers

#### Attempt A: plain `./configure`

Failed in **~14.6 seconds**:

```text
checking for Berkeley DB C++ headers... no
configure: error: libdb_cxx headers missing
```

#### Attempt B: install historical Berkeley DB 4.8 packages

The normal Ubuntu 24.04 package set does **not** provide the historical wallet dependency:

```text
E: Package 'libdb4.8-dev' has no installation candidate
E: Package 'libdb4.8++-dev' has no installation candidate
```

#### Attempt C: install available build dependencies, then plain `./configure`

Failed in **~3.8 seconds**:

```text
configure: error: Found Berkeley DB other than 4.8, required for portable wallets (--with-incompatible-bdb to ignore or --disable-wallet to disable wallet functionality)
```

#### Attempt D: `./configure --with-incompatible-bdb`

Failed in **~10.4 seconds** after getting further:

```text
checking for CURL... no
configure: error: libcurl  not found.
```

#### Attempt E: install `libcurl4-openssl-dev`, then `./configure --with-incompatible-bdb`

Failed in **~9.8 seconds**:

```text
configure: error: Detected unsupported SSL version: This is NOT supported, and may break consensus compatibility! Use '--with-unsupported-ssl' if you don't care
```

#### Attempt F: `./configure --with-incompatible-bdb --with-unsupported-ssl`

Completed successfully in **~13.9 seconds**, but only with two explicit audit-bypass flags:

- `--with-incompatible-bdb`
- `--with-unsupported-ssl`

Notable configure warnings:

```text
configure: WARNING: Found Berkeley DB other than 4.8; wallets opened by this build will not be portable!
configure: WARNING: Detected unsupported SSL version: This is NOT supported, and may break consensus compatibility! Use '--with-unsupported-ssl' if you don't care
configure: WARNING: "xgettext is required to update qt translations"
```

Configure summary excerpt:

```text
checking whether to build crownd... yes
checking whether to build utils (crown-cli crown-tx)... yes
checking whether to build libraries... yes
checking if wallet should be enabled... yes
checking whether to build with support for UPnP... yes
checking whether to build GUI with support for D-Bus... yes
checking whether to build GUI with support for QR codes... yes
checking whether to build test_crown-qt... yes
checking whether to build test_crown... yes
```

### 2.4 `make` result

Full `make` ran for **~2m57s** and failed during `src/rpcserver.cpp` compilation.

First build failure:

```text
rpcserver.cpp:691:77: error: no matching function for call to ‘boost::asio::ssl::context::context(boost::asio::io_service&, boost::asio::ssl::context_base::method)’
rpcserver.cpp:710:50: error: ‘class boost::asio::ssl::context’ has no member named ‘impl’
rpcserver.cpp:579:111: error: ‘class boost::asio::basic_socket_acceptor<boost::asio::ip::tcp>’ has no member named ‘get_io_service’
make[2]: *** [Makefile:4626: libbitcoin_server_a-rpcserver.o] Error 1
```

This is a direct incompatibility with the host Boost.Asio API rather than a missing package.

### 2.5 Independent target checks

#### `crownd`

Explicit target build also failed on the same `rpcserver.cpp` Boost.Asio API break:

```text
/usr/bin/time -v make -C src crownd
...
make: *** [Makefile:4626: libbitcoin_server_a-rpcserver.o] Error 1
```

#### `crown-cli`

Explicit target build failed independently in `crown-cli.cpp` with the same Asio-era assumptions:

```text
/usr/bin/time -v make -C src crown-cli
...
crown-cli.cpp:115:58: error: no matching function for call to ‘boost::asio::ssl::context::context(boost::asio::io_service&, boost::asio::ssl::context_base::method)’
rpcprotocol.h:114:39: error: ‘class boost::asio::ssl::stream<...>’ has no member named ‘get_io_service’
```

#### `crown-qt`

The configure stage enabled Qt5 support, but no `crown-qt` binary was produced because the overall build stopped before GUI linkage. The generated build metadata still expects a Qt test/runtime path (`test/test_crown`, `qt/test/test_crown-qt`) rather than the older names in `src/test/Makefile.am`.

#### test binaries

Autotools generated targets expect `test/test_crown` and `qt/test/test_crown-qt`, but `make -C src crown_test` failed on the same `rpcserver.cpp` compile blocker before a unit test binary was linked.

### 2.6 Warnings observed during compilation

Recurring warnings included:

- deprecated implicit copy/assignment behavior in transaction/script types
- `boost::filesystem::path::is_complete()` deprecation
- `std::auto_ptr` deprecation in InstantX/InstantSend code
- unrecognized `-Wno-self-assign` on this compiler
- deprecated Boost global bind placeholders

### 2.7 Autotools verdict

| Artifact | Result |
| --- | --- |
| `crownd` | **Did not build** |
| `crown-cli` | **Did not build** |
| `crown-qt` | **Did not build** |
| unit test binary | **Did not build** |
| Qt test binary | **Did not build** |

## 3. Depends build

### 3.1 Exact command executed

```bash
cd /home/runner/work/crown-core/crown-core/depends
/usr/bin/time -v make HOST=x86_64-pc-linux-gnu NO_QT=1
```

### 3.2 Result

The depends build failed quickly in **~7.7 seconds** while fetching `native_ccache`.

Observed download attempts:

```text
Fetching ccache-3.3.3.tar.bz2 from httpd://samba.org/ftp/ccache
curl: (1) Protocol "httpd" not supported or disabled in libcurl
Fetching ccache-3.3.3.tar.bz2 from https://bitcoincore.org/depends-sources
curl: (6) Could not resolve host: bitcoincore.org
make: *** [funcs.mk:303: /home/runner/work/crown-core/crown-core/depends/sources/download-stamps/.stamp_fetched-native_ccache-ccache-3.3.3.tar.bz2.hash] Error 6
```

Executed evidence:

- `depends/packages/native_ccache.mk` contains a malformed primary URL: `httpd://samba.org/ftp/ccache` (`/home/runner/work/crown-core/crown-core/depends/packages/native_ccache.mk:1-5`).
- The fallback mirror requires external DNS/network reachability to `bitcoincore.org`, which was unavailable in this environment.
- Because `native_ccache` failed first, no later packages reached checksum or compile stages in this run.

### 3.3 Successful packages

None in this executed attempt; the failure occurred before the first package completed.

## 4. CMake build

CMake is a secondary build path in this repository. `src/CMakeLists.txt` defines `crownd`, `crown-cli`, `crown_wallet`, `crown_platform`, `crown_pos`, and `crown_test`, while `src/qt/CMakeLists.txt` defines `crown_qt` (`/home/runner/work/crown-core/crown-core/src/CMakeLists.txt:379-477`, `/home/runner/work/crown-core/crown-core/src/qt/CMakeLists.txt:196-216`).

### 4.1 Exact commands executed

```bash
rm -rf /tmp/crown-audit/cmake-build
mkdir -p /tmp/crown-audit/cmake-build
cd /tmp/crown-audit/cmake-build
/usr/bin/time -v cmake /home/runner/work/crown-core/crown-core
/usr/bin/time -v cmake --build . -j4
/usr/bin/time -v cmake --build . --target crownd -j4
/usr/bin/time -v cmake --build . --target crown_test -j4
/usr/bin/time -v cmake --build . --target crown_qt -j4
ctest -N
```

### 4.2 Configure result

CMake configuration succeeded in **~1.7 seconds**, but emitted important drift warnings:

- no explicit top-level `project()` command
- very old `cmake_minimum_required()` compatibility level
- policy warnings for `FindBoost` and `AUTOMOC` handling of generated files

### 4.3 Build result

Full `cmake --build . -j4` ran for **~41.7 seconds** and failed first on `crown-cli.cpp` with the same Boost.Asio API mismatch seen under Autotools:

```text
/home/runner/work/crown-core/crown-core/src/crown-cli.cpp:115:58: error: no matching function for call to ‘boost::asio::ssl::context::context(boost::asio::io_service&, boost::asio::ssl::context_base::method)’
/home/runner/work/crown-core/crown-core/src/rpcprotocol.h:114:39: error: ‘class boost::asio::ssl::stream<...>’ has no member named ‘get_io_service’
```

Unlike the Autotools build, CMake compiled farther into some static libraries before failing. Partial artifacts produced included:

- `/tmp/crown-audit/cmake-build/src/libcrown_common.a` — `7,619,296` bytes
- `/tmp/crown-audit/cmake-build/src/libcrown_platform.a` — `15,309,964` bytes

### 4.4 Independent CMake target results

#### `crownd`

`cmake --build . --target crownd -j4` failed in **~20.2 seconds** in `masternode.cpp`:

```text
/home/runner/work/crown-core/crown-core/src/masternode.cpp:610:17: error: ‘nDoS’ was not declared in this scope; did you mean ‘nDos’?
/home/runner/work/crown-core/crown-core/src/masternode.cpp:618:18: error: redeclaration of ‘CMasternode* pmn’
```

#### `crown_test`

`cmake --build . --target crown_test -j4` failed on the same `masternode.cpp` errors before a test binary was linked.

#### `crown_qt`

`cmake --build . --target crown_qt -j4` also failed on the same `masternode.cpp` errors after Qt autogen work began.

### 4.5 CMake vs Autotools differences

| Area | Autotools evidence | CMake evidence |
| --- | --- | --- |
| Project status | Historically primary (`doc/build-unix.md:15-25`) | Secondary / drift warnings present |
| Configure outcome | Requires `--with-incompatible-bdb --with-unsupported-ssl` to finish | Configures without those explicit gate checks |
| First full-build failure | `src/rpcserver.cpp` | `src/crown-cli.cpp` |
| Further targeted failure | `src/rpcserver.cpp` for `crownd`/tests | `src/masternode.cpp` for `crownd`/`crown_test`/`crown_qt` |
| Final binaries produced | none | none |
| Registered CTest tests | n/a | `ctest -N` reported **0 tests** |

## 5. Unit tests

### 5.1 Relationship between `test_crown`, `test_crowncoin`, and `crown_test`

Inspection-only conclusion:

- `src/test/README.md` says the unit test executable should be called **`test_crown`** (`/home/runner/work/crown-core/crown-core/src/test/README.md:8-10`).
- `src/test/Makefile.am` still declares **`test_crowncoin`** as `bin_PROGRAMS` and `TESTS` (`/home/runner/work/crown-core/crown-core/src/test/Makefile.am:5-7`, `34-78`).
- `src/test/CMakeLists.txt` declares the CMake test executable as **`crown_test`** (`/home/runner/work/crown-core/crown-core/src/test/CMakeLists.txt:1-50`).
- The generated Autotools make metadata in this environment resolves `crown_test` to the actual binary path **`test/test_crown`** and `crown_test_check` to running that binary.

This indicates naming drift across documentation, Autotools sources, generated rules, and CMake.

### 5.2 Tests discovered

Executed list extraction found:

- **43** unit-test source files in `src/test/CMakeLists.txt`
- **35** unit-test source files in `src/test/Makefile.am`

Notable drift examples:

- present in CMake but not the old Automake list: `coins_tests.cpp`, `crypto_tests.cpp`, `hash_tests.cpp`, `mempool_tests.cpp`, `prevector_tests.cpp`, `sanity_tests.cpp`, `skiplist_tests.cpp`, `timedata_tests.cpp`, `univalue_tests.cpp`, `mnbudget-test.cpp`, `db_tests.cpp`
- present in Automake but absent from CMake list: `bignum_tests.cpp`, `canonical_tests.cpp`, `name_tests.cpp`, `uint256_tests.cpp`

### 5.3 Execution attempt

Commands attempted:

```bash
cd /home/runner/work/crown-core/crown-core
/usr/bin/time -v make -C src crown_test
cd /tmp/crown-audit/cmake-build
/usr/bin/time -v cmake --build . --target crown_test -j4
ctest -N
```

### 5.4 Results

| Metric | Result |
| --- | --- |
| Tests discovered | 43 in CMake list; 35 in Automake list |
| Tests built | 0 |
| Tests executed | 0 |
| Passed | 0 |
| Failed | 0 executed; build stage failed |
| Skipped | All execution blocked by build failures |

Relevant failures:

- Autotools unit-test target blocked by `src/rpcserver.cpp` Boost.Asio API errors.
- CMake unit-test target blocked by `src/masternode.cpp` compile errors.
- `ctest -N` reported **0 tests**, so even a successful CMake binary build would still need test registration work.

## 6. RPC / functional tests

Relevant files:

- `qa/pull-tester/rpc-tests.sh` lists the intended active RPC suite (`/home/runner/work/crown-core/crown-core/qa/pull-tester/rpc-tests.sh:18-29`).
- `qa/rpc-tests/README.md` still describes a Bitcoin-era regtest cache flow (`/home/runner/work/crown-core/crown-core/qa/rpc-tests/README.md:28-35`).
- `qa/pull-tester/pull-tester.py` uses `/usr/bin/python` and Python 2 era imports (`from urllib import urlopen`) (`/home/runner/work/crown-core/crown-core/qa/pull-tester/pull-tester.py:1-8`).

### 6.1 Functional tests discovered from the runner

Active commands in `qa/pull-tester/rpc-tests.sh`:

1. `wallet.py`
2. `listtransactions.py`
3. `mempool_resurrect_test.py`
4. `txn_doublespend.py`
5. `txn_doublespend.py --mineblock`
6. `getchaintips.py`
7. `rest.py`
8. `mempool_spendcoinbase.py`
9. `httpbasics.py`
10. `mempool_coinbase_spends.py`

### 6.2 Python compatibility evidence

Python 2 is not installed on the host:

```text
$ python2 --version
/bin/bash: line 1: python2: command not found
```

Ubuntu 24.04 package metadata also reported no normal `python2` or `python-is-python2` candidate.

Direct execution attempt under Python 3:

```bash
cd /home/runner/work/crown-core/crown-core
python3 qa/rpc-tests/wallet.py --srcdir /home/runner/work/crown-core/crown-core/src
```

Result:

```text
File "/home/runner/work/crown-core/crown-core/qa/rpc-tests/wallet.py", line 40
  print "Mining blocks..."
  ^^^^^^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?
```

Additional Python-2-only markers found by inspection include `xrange(...)`, classic `print` statements, and `from urllib import urlopen`.

### 6.3 Functional test verdict

| Metric | Result |
| --- | --- |
| Individual tests attempted | 1 direct execution probe (`wallet.py` under Python 3) |
| Passed | 0 |
| Failed | 1 |
| Skipped / blocked | Remaining suite blocked by Python 2 requirement and missing `crownd` build |

## 7. Regtest node

Not attempted.

Reason: no `crownd` binary was successfully produced by either build system.

Status: **NOT TESTED**.

## 8. Multi-node regtest

Not attempted.

Reason: no `crownd` binary was successfully produced by either build system.

Status: **NOT TESTED**.

## 9. Wallet compatibility

Not attempted.

Reason: no working daemon or wallet binary was produced, and the audit rule forbids using a real user wallet.

Status: **NOT TESTED**.

## 10. Mainnet chain sync feasibility

Preflight only.

The hardcoded mainnet DNS seed list in `src/chainparams.cpp` is:

- `europe-01seedns.crowncoin.org`
- `europe-02seedns.crowncoin.net`
- `canada-01seedns.crowncoin.org`
- `latam-01seedns.crowncoin.net`
- `SEAsia-01seedns.crowncoin.org`
- `pacific-01seedns.crowncoin.net`

Source: `/home/runner/work/crown-core/crown-core/src/chainparams.cpp:279-284`.

Executed host DNS lookups returned no addresses for any of these names:

```text
HOST europe-01seedns.crowncoin.org
UNRESOLVED
HOST europe-02seedns.crowncoin.net
UNRESOLVED
HOST canada-01seedns.crowncoin.org
UNRESOLVED
HOST latam-01seedns.crowncoin.net
UNRESOLVED
HOST SEAsia-01seedns.crowncoin.org
UNRESOLVED
HOST pacific-01seedns.crowncoin.net
UNRESOLVED
```

No peer-discovery or header-sync attempt was made because no daemon binary was available.

Status: **NOT TESTED** (runtime blocked), with a negative seed-resolution preflight.

## 11. Performance baseline

| Item | Observation |
| --- | --- |
| `./autogen.sh` duration | ~9.1 s |
| First failing plain `./configure` duration | ~14.6 s |
| Successful configured audit bypass run | ~13.9 s |
| Full Autotools `make` duration before failure | ~2m57s |
| Depends `make` duration before failure | ~7.7 s |
| CMake configure duration | ~1.7 s |
| Full CMake build duration before failure | ~41.7 s |
| Final binary sizes | none; no final executables were produced |
| Partial CMake static libs | `libcrown_common.a` 7.6 MB; `libcrown_platform.a` 15.3 MB |
| Idle daemon RAM | not available; daemon did not build |
| Regtest daemon RAM | not available; daemon did not build |
| Datadir size created by tests | not available; tests did not run |

## 12. Build blocker register

| ID | Component | Blocker | Severity | Evidence | Workaround required? | Production code change required? | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B-001 | Wallet dependency | Historical Berkeley DB 4.8 dev packages unavailable in normal Ubuntu 24.04 repos | HIGH | `apt-get install libdb4.8-dev libdb4.8++-dev` failed with no installation candidate | Yes | No | Modern host packaging no longer matches expected wallet dependency |
| B-002 | Autotools configure | Plain configure rejects non-4.8 Berkeley DB | HIGH | `configure: error: Found Berkeley DB other than 4.8...` | Yes (`--with-incompatible-bdb` or disable wallet) | No | Explicitly warns resulting wallets are not portable |
| B-003 | Autotools configure | Missing libcurl dev package on host | MEDIUM | `configure: error: libcurl  not found.` | Yes | No | Solved by host package install only |
| B-004 | SSL dependency gate | Configure rejects host OpenSSL 3.x as unsupported | HIGH | `configure: error: Detected unsupported SSL version...` | Yes (`--with-unsupported-ssl`) | No | Bypass weakens confidence in consensus/network compatibility |
| B-005 | Autotools source build | Boost.Asio API incompatibility in `rpcserver.cpp` | CRITICAL | `context(io_service, ...)`, `.impl()`, `.get_io_service()` compile failures | No practical safe workaround in this audit | **Yes** | Blocks `crownd`, tests, and full build |
| B-006 | CLI source build | Boost.Asio API incompatibility in `crown-cli.cpp` / `rpcprotocol.h` | CRITICAL | same old Asio constructor / `get_io_service()` failures | No practical safe workaround in this audit | **Yes** | Blocks `crown-cli` independently of daemon build |
| B-007 | Depends system | Malformed `native_ccache` URL plus unreachable fallback mirror | HIGH | `httpd://samba.org/...` + `Could not resolve host: bitcoincore.org` | Yes | No for URL typo fix in build metadata; environment/network also matters | Prevented depends from progressing beyond first fetch |
| B-008 | CMake source build | `masternode.cpp` does not compile (`nDoS` typo / `pmn` redeclaration) | HIGH | `masternode.cpp:610`, `:618` errors during `crownd`, `crown_test`, `crown_qt` targets | No practical safe workaround in this audit | **Yes** | Seen in CMake-targeted builds after partial library success |
| B-009 | Functional tests | RPC suite requires Python 2 and fails immediately under Python 3 | HIGH | `SyntaxError: Missing parentheses in call to 'print'` in `wallet.py`; `python2` absent | Yes | Potentially yes, unless a historical Python 2 runtime is restored | Blocks current Ubuntu execution |
| B-010 | CMake test harness | `ctest -N` registers zero tests | MEDIUM | `Total Tests: 0` | Yes | No for registration alone | Test binary build is already blocked separately |

## 13. Modernisation boundary

Based strictly on executed evidence:

### A. Things that still work unchanged

- `./autogen.sh` bootstrap completes.
- A heavily warned CMake configure pass completes.
- Some non-final CMake static libraries (`crown_common`, `crown_platform`) still build on the host toolchain.

### B. Things that require build-system repair only

- Depends metadata contains at least one malformed source URL (`httpd://...`).
- CMake metadata is stale enough to emit policy/project warnings.
- CMake test registration is absent (`ctest -N` => 0 tests).
- Host package prerequisites such as `libcurl4-openssl-dev` are not all preinstalled by default.

### C. Things that require dependency replacement

- Historical Berkeley DB 4.8 is no longer normally installable on Ubuntu 24.04.
- The build’s supported SSL expectation is OpenSSL 1.0-era, while the host provides OpenSSL 3.x.
- Functional tests currently expect a Python 2 runtime that is not part of the normal host toolchain.

### D. Things that appear to require source changes

- RPC/CLI networking code depends on obsolete Boost.Asio interfaces.
- CMake-path compilation exposes `masternode.cpp` source errors (`nDoS` / redeclared `pmn`).
- These are source-level compile blockers, not just packaging problems.

### E. Things that remain unknown

- Whether a historically matched environment (old Boost/OpenSSL/BDB/Python toolchain) would allow a full successful build.
- Runtime behavior on regtest or mainnet.
- Wallet creation/encryption/backup/restore behavior.
- Multi-node propagation behavior.

## 14. Final status

| Area | Status |
| --- | --- |
| Autotools build | **RED** |
| CMake build | **RED** |
| Daemon | **RED** |
| CLI | **RED** |
| Qt wallet | **RED** |
| Unit tests | **RED** |
| Functional tests | **RED** |
| Regtest | **NOT TESTED** |
| Multi-node regtest | **NOT TESTED** |
| Wallet creation/restoration | **NOT TESTED** |
| Mainnet connectivity | **NOT TESTED** |

Overall: **NOT CURRENTLY REPRODUCIBLE**.

## Appendix: command summary

### Commands that completed successfully

- `./autogen.sh`
- `./configure --with-incompatible-bdb --with-unsupported-ssl`
- `cmake /home/runner/work/crown-core/crown-core`
- host DNS preflight checks

### Commands that failed materially

- `./configure` (missing Berkeley DB C++ headers)
- `./configure` after package install (rejects non-4.8 Berkeley DB)
- `./configure --with-incompatible-bdb` (missing libcurl, then unsupported SSL)
- `make`
- `make -C src crownd`
- `make -C src crown-cli`
- `make -C src crown_test`
- `make HOST=x86_64-pc-linux-gnu NO_QT=1` in `depends/`
- `cmake --build . -j4`
- `cmake --build . --target crownd -j4`
- `cmake --build . --target crown_test -j4`
- `cmake --build . --target crown_qt -j4`
- `python3 qa/rpc-tests/wallet.py --srcdir /home/runner/work/crown-core/crown-core/src`
