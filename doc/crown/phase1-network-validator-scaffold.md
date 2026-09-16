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
- Bech32 HRP: `ccrt`

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

The intended patch surface is:

- `src/crown/*` for Crown-specific validator and option logic
- chain-selection plumbing in `src/util/chaintype.*`, `src/chainparamsbase.*`, `src/chainparams.cpp`, and `src/kernel/chainparams.*`
- small startup hooks in `src/init.cpp`
- targeted test updates plus new Crown unit/functional coverage

No Bitcoin PoW or chain-selection consensus code is disabled or redefined.
