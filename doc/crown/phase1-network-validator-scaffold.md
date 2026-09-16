# Crown Successor PoC Phase 1

## Scope

Phase 1 keeps Bitcoin Core v31.1 proof-of-work block production and chain selection unchanged while adding only:

- an isolated experimental `crown` chain profile
- a static four-validator scaffold
- explicit non-validator default behavior
- test-only validator keys
- exact voting-power and quorum helpers

No Tendermint-style consensus logic is introduced here.

## Why `ChainType::CROWN`

Bitcoin Core v31.1 already routes chain selection through `ChainType`, `CreateBaseChainParams()`, and `CreateChainParams()`. Reusing that path keeps the Crown network identity isolated to a narrow set of upstream hooks instead of overloading signet or regtest with Crown-specific validator arguments and semantics.

Signet was considered as the only nearby alternative, but it is not materially less invasive for this scaffold: Crown still needs separate datadir, ports, message magic, address HRP, and validator startup options. A dedicated `ChainType::CROWN` is therefore the smallest clear integration point.

## Experimental network identity

The experimental chain uses:

- chain/datadir name: `crown`
- message magic: `ce f1 db fa`
- P2P port: `28444`
- RPC port: `28443`
- Bech32 HRP: `ccrt` (moved from the provisional `crt` value to avoid overlap with regtest address encoding)

Its consensus parameters intentionally stay regtest-like for PoC work:

- minimum-difficulty blocks enabled
- no PoW retargeting
- no DNS or fixed seeds
- Bitcoin-style genesis and proof-of-work validation remain intact

## Static validator scaffold

The validator scaffold lives under `src/crown/` and defines:

- `validator-a`
- `validator-b`
- `validator-c`
- `validator-d`

Each validator has:

- a static identifier
- a compressed secp256k1 consensus public key
- voting power `25`

Total voting power is `100`. The quorum threshold is computed exactly as:

- `floor(2 * total_power / 3) + 1`

For this static set:

- quorum = `67`
- maximum faulty voting power without quorum loss = `33`

That means any three validators (75 power) can form quorum, while any two (50 power) cannot.

## Validator startup lifecycle

Argument registration and early validation only check:

- whether Crown-only options are used on the Crown chain
- whether validator mode is explicitly enabled
- whether validator id and private-key strings are present and structurally valid

Cryptographic initialization is deferred until `AppInitMain()` after `bitcoind` has created `node.ecc_context` in `AppInit()`. That stage is safe for:

- secp256k1 private-key validation
- public-key derivation
- matching the configured validator id to the derived consensus public key

This avoids creating any parallel Crown-specific ECC lifecycle.

## Test-only keys

The committed validator private keys are:

- TEST ONLY
- PUBLICLY KNOWN
- NEVER USE FOR MAINNET

They are the fixed 32-byte hex scalars `1`, `2`, `3`, and `4`, mapped to validators `a` through `d`.

## Phase 1 patch surface

Phase 1 uses two kinds of changes:

- new Crown-owned files under `src/crown/`, `src/test/crown_tests.cpp`, and `test/functional/feature_crown_phase1.py`
- narrow edits to existing upstream Bitcoin Core files so the new chain can be selected, started, displayed, and tested

No Bitcoin PoW or chain-selection consensus code is disabled or redefined.

### New Crown-owned files

| File | Reason | Classification | Permanence | Merge risk |
| --- | --- | --- | --- | --- |
| `src/crown/options.h` | Declares Crown runtime options and local validator metadata. | Isolated Crown module | Intended long-term home for Crown node-mode state. | Low |
| `src/crown/options.cpp` | Registers Crown validator args, performs early structural validation, and performs ECC-safe runtime initialization after Bitcoin startup reaches a safe stage. | Isolated Crown module | Likely permanent, though later phases may add fields or split responsibilities. | Low |
| `src/crown/validator.h` | Declares the static validator model and quorum helpers. | Isolated Crown module | Likely permanent until dynamic validator sets replace the static scaffold. | Low |
| `src/crown/validator.cpp` | Defines the four static validators, test-only keys, key decoding, and exact quorum math. | Isolated Crown module | Phase 1 scaffold expected to evolve in later consensus phases. | Low |
| `src/test/crown_tests.cpp` | Adds unit coverage for validator math, option validation, and ECC-safe runtime initialization. | New Crown-specific test | Test-only and expected to remain as coverage expands. | Low |
| `test/functional/feature_crown_phase1.py` | Adds startup and configuration coverage for the experimental Crown chain. | New Crown-specific functional test | Test-only and expected to remain as later phases add behavior. | Low |
| `doc/crown/phase1-network-validator-scaffold.md` | Documents Phase 1 scope, lifecycle, and patch surface. | Crown documentation | Permanent documentation that should evolve with later phases. | Low |

### Existing upstream Bitcoin files modified in Phase 1

| File | Reason | Classification | Permanence | Merge risk |
| --- | --- | --- | --- | --- |
| `src/CMakeLists.txt` | Links the new `src/crown` implementation into `bitcoin_common`. | Build wiring | Permanent while Crown code remains in-tree. | Low |
| `src/bitcoin-cli.cpp` | Exposes Crown-specific RPC port defaults and chain name text for the existing CLI network-selection surface. | CLI chain identity plumbing | Permanent unless the Crown chain is removed or CLI chain handling is redesigned upstream. | Low |
| `src/chainparams.cpp` | Extends the top-level chain factory switch so `ChainType::CROWN` resolves to the new kernel chain params. | Chain factory hook | Permanent core hook for any dedicated Crown chain. | Low |
| `src/chainparamsbase.cpp` | Adds `-crown` base-chain selection and the Crown RPC/datadir defaults. | Base chain selection hook | Permanent while a dedicated Crown chain exists. | Low |
| `src/chainparamsbase.h` | Adds `crown` to the advertised chain-name list. | Public chain-selection constant | Permanent while a dedicated Crown chain exists. | Low |
| `src/common/args.cpp` | Teaches generic argument parsing about the new Crown config section and conflict checks with other chain selectors. | Shared argument parser hook | Permanent while `-crown` exists. | Medium |
| `src/init.cpp` | Registers Crown server args, surfaces Crown defaults in help text, runs early non-ECC validation, and initializes Crown runtime state after ECC is ready. | Node startup lifecycle hook | Permanent entry point, though later phases may expand the runtime work done here. | Medium |
| `src/kernel/chainparams.cpp` | Defines the experimental Crown network identity, regtest-like PoW parameters, genesis choice, ports, message magic, and address HRP. | Core chain-identity definition | Permanent for the dedicated Crown chain, though values may still evolve during PoC work. | Medium |
| `src/kernel/chainparams.h` | Declares the Crown chain-param constructor/factory surface. | Chain-params interface hook | Permanent while the dedicated Crown chain exists. | Low |
| `src/node/context.cpp` | Pulls in the Crown runtime type so node context lifetime can own it. | Runtime state plumbing | Permanent while node context carries Crown state. | Low |
| `src/node/context.h` | Adds `node.crown` storage for post-ECC Crown runtime options. | Runtime state plumbing | Permanent while later phases need Crown runtime state attached to the node. | Medium |
| `src/qt/guiconstants.h` | Adds the Crown-specific Qt application name constant. | Qt identity plumbing | Permanent while Qt supports the Crown chain. | Low |
| `src/qt/guiutil.cpp` | Adds a Crown dummy address placeholder used by the Qt address widget validation path. | Qt address-format plumbing | Permanent while Qt supports Crown addresses. | Low |
| `src/qt/guiutil.h` | Exposes the chain-specific Qt dummy-address helper for direct test coverage. | Qt testability hook | Probably permanent unless Qt helper structure changes upstream. | Low |
| `src/qt/networkstyle.cpp` | Adds a Crown network style entry so the Qt UI can distinguish the network. | Qt identity plumbing | Permanent while Qt supports the Crown chain. | Low |
| `src/qt/test/uritests.cpp` | Adds Qt coverage for the Crown dummy-address invariant. | Existing Qt test expansion | Test-only and likely permanent. | Low |
| `src/qt/test/uritests.h` | Declares the added Crown Qt test slot. | Existing Qt test expansion | Test-only and likely permanent. | Low |
| `src/test/CMakeLists.txt` | Registers the new Crown unit test file with the CMake test binary. | Test build wiring | Permanent while Crown unit tests exist. | Low |
| `src/test/argsman_tests.cpp` | Extends chain-selection tests for `-crown` and updates the chain-merge golden hash after adding a new network selector. | Existing unit-test expansion | Test-only and likely permanent. | Medium |
| `src/test/key_io_tests.cpp` | Verifies invalid key and destination handling still behaves correctly on the Crown chain alongside the existing networks. | Existing unit-test expansion | Test-only and likely permanent. | Low |
| `src/test/pow_tests.cpp` | Adds sanity coverage that the new chain params remain compatible with existing PoW assumptions. | Existing unit-test expansion | Test-only and likely permanent. | Low |
| `src/test/versionbits_tests.cpp` | Extends chain iteration coverage to include the Crown chain. | Existing unit-test expansion | Test-only and likely permanent. | Low |
| `src/util/chaintype.cpp` | Maps `ChainType::CROWN` to and from its string form. | Shared chain identity plumbing | Permanent while the dedicated Crown chain exists. | Low |
| `src/util/chaintype.h` | Declares the new `ChainType::CROWN` enum member. | Shared chain identity plumbing | Permanent while the dedicated Crown chain exists. | Low |
| `test/functional/test_framework/messages.py` | Adds Crown message magic so the functional harness can identify the experimental network. | Functional test harness hook | Permanent while functional tests start Crown nodes. | Low |
| `test/functional/test_runner.py` | Registers the new Crown Phase 1 functional test in the upstream runner list. | Functional test harness hook | Test-only and likely permanent. | Low |

### Permanence and merge-risk interpretation

- **Low merge risk**: localized enum/string/help/test wiring that is unlikely to conflict beyond routine upstream churn.
- **Medium merge risk**: shared startup, argument parsing, or chain-parameter files that Bitcoin Core regularly changes upstream and will need careful rebasing.
- No file in Phase 1 should be considered high-risk because PoW, validation, chainwork, and best-chain selection semantics were intentionally left unchanged.
