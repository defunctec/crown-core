# Crown static codebase audit (reconstructed)

This document reconstructs the findings of the earlier static audit from verified audit outputs. The original CODEBASE_AUDIT.md was not present in the recoverable repository history.

Recoverability note: the consolidation audit already recorded that `docs/revival/CODEBASE_AUDIT.md` was absent from both the canonical recovered baseline and the local recovery artifacts (`docs/revival/CONSOLIDATION_REPORT.md:23-29`, `docs/revival/CONSOLIDATION_REPORT.md:57`).

## 1. Repository baseline and upstream lineage

The recoverable source tree still shows the expected Bitcoin -> Dash -> Crown lineage. Core files retain Satoshi/Bitcoin/Dash/Crown copyright headers (`src/main.cpp:1-6`), while Dash-era subsystems such as masternode payments remain explicitly identified as Dash-derived (`src/masternode-payments.h:1-4`). Crown-specific layers are then added on top through masternodes, systemnodes, MNPoS, platform governance, and NFT-special-transaction code (`README.md:17-18`, `src/platform/specialtx.cpp:20-39`).

The architectural foundation is still recognizably Bitcoin Core 0.10-era rather than modern post-validation-interface Bitcoin Core: validation, mempool admission, block acceptance, and P2P message dispatch still live in the monolithic `src/main.cpp` translation unit (`src/main.cpp:1091-1270`, `src/main.cpp:3337-3460`, `src/main.cpp:3573-3650`, `src/main.cpp:5757-5866`).

## 2. Build structure

Autotools remains the documented primary Unix build flow: `doc/build-unix.md` still prescribes `./autogen.sh`, `./configure`, and `make` as the main path (`doc/build-unix.md:15-25`). The repository also carries a secondary CMake build description that manually finds Boost, OpenSSL, Berkeley DB, CURL, Qt5, and Protobuf before adding subdirectories (`CMakeLists.txt:1-14`, `CMakeLists.txt:78-80`).

The test/build definitions are split across two systems, which is a persistent drift risk. Autotools includes tests indirectly through `src/Makefile.am` -> `src/Makefile.test.include` (`src/Makefile.am:515-517`, `src/Makefile.test.include:36-103`), while CMake keeps a separate explicit `crown_test` source list in `src/test/CMakeLists.txt` (`src/test/CMakeLists.txt:1-46`).

## 3. Dependency inventory and age signals

The build metadata still expects an older C++/crypto stack centered on Boost, OpenSSL, Berkeley DB, CURL, Qt, Protobuf, and optional QRencode (`configure.ac:700-718`, `CMakeLists.txt:6-13`). The wallet remains Berkeley-DB-backed (`src/walletdb.h:75-131`). Vendored legacy components are still present, notably `libsecp256k1` identified as version `0.1` (`src/secp256k1/configure.ac:1-2`) and a separately built LevelDB subtree (`src/leveldb/CMakeLists.txt:1-16`).

These files support the earlier conclusion that dependency age is a major characteristic of the codebase: the repository mixes modern Crown-specific features with old Bitcoin/Dash-era build and storage assumptions.

## 4. Core validation and networking architecture

`src/main.cpp` remains the central execution hub. Transaction admission flows through `AcceptToMemoryPool`, which applies basic transaction checks, special-transaction checks, standardness checks, mempool conflict checks, fee policy, and script verification (`src/main.cpp:1091-1270`). Block validation flows through `CheckBlock` and `ContextualCheckBlock`, which enforce merkle correctness, block shape, coinbase/coinstake placement, InstantSend lock checks, and masternode/systemnode payment validity (`src/main.cpp:3337-3460`, `src/main.cpp:3548-3570`). Block acceptance then attaches proof-of-stake handling once the chain is past the configured PoS start height (`src/main.cpp:3648-3663`).

Networking is likewise concentrated in `main.cpp`: incoming messages are checked for network magic, header validity, checksum, and then dispatched through `ProcessMessage`; extension modules for masternodes, systemnodes, budgets, payments, InstantSend, sporks, and sync managers are called from the same message-processing path (`src/main.cpp:5738-5866`).

## 5. Consensus architecture and chain identity

Mainnet parameters in `src/chainparams.cpp` establish Crown's chain identity: message-start bytes `b8 eb b3 df`, default port `9340`, the Crown genesis block assertions, and Crown-specific address prefixes including `CRW` pubkey addresses, `CRM` script addresses, `CRP` identity addresses, `CRA` app-service addresses, and `CRT` title addresses (`src/chainparams.cpp:217-303`).

Mainnet proof-of-stake activation is configured at block height `2,330,000` (`src/chainparams.cpp:233-239`). After that point, accepted blocks must also pass stake validation (`src/main.cpp:3648-3663`). The MNPoS implementation lives under `src/mn-pos/` and the stake-validation path uses stake pointers plus distinct collateral weights for masternodes and systemnodes (`src/mn-pos/stakevalidation.cpp:18-58`; see also `doc/Crown-MNPoS.md:62-90`).

## 6. Masternodes, systemnodes, payments, governance, and sporks

Crown's node-tier design is explicit in repository documentation: masternodes process instant transactions and require 10,000 CRW collateral, while systemnodes host application services and require 500 CRW collateral (`README.md:17-18`, `README.md:39-52`). Those collateral values also exist directly in wallet code as `MASTERNODE_COLLATERAL = 10000` and `SYSTEMNODE_COLLATERAL = 500` (`src/wallet.h:54-55`), and are reused by coin-selection and stake-validation logic (`src/wallet.cpp:1237-1245`, `src/mn-pos/stakevalidation.cpp:31-42`).

Dash-derived payment, governance, and spork systems remain first-class subsystems. Masternode payment logic is still defined in Dash/Crown payment managers (`src/masternode-payments.h:1-35`), systemnode rewards mirror that pattern (`src/systemnode-payments.h:15-31`), and the spork table still contains Dash-style runtime switches for InstantSend, masternode budgets, superblocks, enforcement, and Crown's later NFT transaction switch (`src/spork.h:22-59`). In block and message handling, `main.cpp` still routes to masternode, systemnode, budget, payment, InstantSend, and spork managers as peer subsystems (`src/main.cpp:3415-3450`, `src/main.cpp:5738-5748`).

## 7. Wallet architecture

The wallet remains the classic Berkeley DB wallet model centered on `wallet.dat`. `CWalletDB` is still a `CDB`-derived database wrapper for keys, transactions, scripts, watch-only entries, account records, transaction ordering, and wallet recovery routines (`src/walletdb.h:75-131`). This is consistent with the older Bitcoin-family wallet architecture rather than descriptor wallets or SQLite-backed designs.

Wallet-side node support is also still embedded in the classic wallet code: available-coin selection has dedicated modes for masternode and systemnode collateral outputs (`src/wallet.h:76-84`, `src/wallet.cpp:1212-1255`).

## 8. Platform and NFT subsystem

The recoverable tree includes a substantial post-Bitcoin/Dash platform layer. `src/platform/specialtx.cpp` wires governance-vote transactions, non-fungible token registration, and NFT protocol registration into special-transaction validation and processing (`src/platform/specialtx.cpp:20-79`). RPC endpoints for the NFT subsystem are implemented under `src/platform/rpc/`, and `rpc-nf-token.cpp` exposes `nftoken register`, `issue`, `list`, `get`, `totalsupply`, `balanceof`, and `ownerof` commands gated by `SPORK_17_NFT_TX` (`src/platform/rpc/rpc-nf-token.cpp:16-40`).

This matches the broader repository positioning of Crown as a blockchain application platform rather than a pure payments coin (`README.md:9-19`).

## 9. Test suite and build-system drift

The test suite is still largely unit-test and harness driven, but its maintenance state is uneven. Autotools owns the active unit-test source list in `src/Makefile.test.include` (`src/Makefile.test.include:36-103`), while CMake owns a different static list in `src/test/CMakeLists.txt` (`src/test/CMakeLists.txt:1-46`). This split is the concrete basis for the earlier observation that test-suite and build-system drift had accumulated over time.

The same pattern appears more broadly in the repository: old build instructions, mixed dependency expectations, and multiple subsystem overlays coexist without a single obviously authoritative build description beyond the Autotools path documented in `doc/build-unix.md:15-25`.

## 10. Known unfinished, partial, or legacy areas

Several files still show direct signs of partially modernized or unfinished code:

- `src/platform/specialtx.cpp` carries an inline TODO stating that handler registration should be refactored so special-transaction code does not need explicit knowledge of every handler (`src/platform/specialtx.cpp:11-16`).
- The vendored secp256k1 subtree is still version `0.1`, which is a strong legacy signal (`src/secp256k1/configure.ac:1-2`).
- The dual Autotools/CMake test definitions remain structurally duplicated (`src/Makefile.am:515-517`, `src/Makefile.test.include:36-103`, `src/test/CMakeLists.txt:1-46`).

The reconstructed audit therefore still supports the earlier classification that the repository contains a working but historically layered codebase with legacy build assumptions and partially integrated newer platform features.

## 11. Preliminary technical conclusions

The earlier static audit's high-level conclusions remain supportable from the recoverable tree:

1. Crown is best understood as a Bitcoin-family codebase with a strong Dash inheritance and substantial Crown-specific extensions, not as a clean-sheet platform implementation (`src/main.cpp:1-6`, `src/masternode-payments.h:1-4`, `src/platform/specialtx.cpp:20-39`).
2. The base architecture is still old-school and centralized around `main.cpp`, the classic wallet, Berkeley DB, and legacy build tooling (`src/main.cpp:1091-1270`, `src/main.cpp:3337-3460`, `src/walletdb.h:75-131`, `doc/build-unix.md:15-25`).
3. Crown-specific differentiation comes from MNPoS, masternode/systemnode economics, platform governance, and NFT/special-transaction layers (`src/chainparams.cpp:233-239`, `src/mn-pos/stakevalidation.cpp:18-58`, `README.md:39-52`, `src/platform/specialtx.cpp:20-79`, `src/platform/rpc/rpc-nf-token.cpp:16-40`).
4. Revival work must continue to preserve chain identity and consensus rules while treating build metadata, dependency age, and test/build drift as major operational risks (`src/chainparams.cpp:217-303`, `configure.ac:700-718`, `src/secp256k1/configure.ac:1-2`, `src/Makefile.am:515-517`, `src/test/CMakeLists.txt:1-46`).
