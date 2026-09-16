# Crown Successor PoC Patch Surface

## Scope

This file tracks the incremental patch surface beyond the Phase 1 baseline documented in `doc/crown/phase1-network-validator-scaffold.md`.

Phase 2 remains overwhelmingly isolated to new Crown-owned files plus minimal build/test wiring.

## New Crown-owned files added in Phase 2

| File | Reason | Classification | Merge risk |
| --- | --- | --- | --- |
| `src/crown/consensus/types.h` | Declares Phase 2 consensus message/state types, `BlockID`, timeout enums, equivocation evidence, and commit results. | New isolated Crown module | Low |
| `src/crown/consensus/types.cpp` | Implements deterministic signing hashes plus proposal/vote signing and verification against the static validator set. | New isolated Crown module | Low |
| `src/crown/consensus/engine.h` | Declares the event-driven one-height consensus engine, state, and emitted actions. | New isolated Crown module | Low |
| `src/crown/consensus/engine.cpp` | Implements proposer checks, quorum handling, locking, valid-round handling, equivocation detection, round changes, and local double-sign guard logic. | New isolated Crown module | Low |
| `src/test/crown_consensus_tests.cpp` | Adds deterministic multi-validator simulation and Phase 2 unit coverage. | Crown-specific test | Low |
| `doc/crown/PHASE2_CONSENSUS_STATE_MACHINE.md` | Documents the implemented Phase 2 consensus behavior and deferred items. | Crown documentation | Low |
| `doc/crown/SUCCESSOR_POC_PATCH_SURFACE.md` | Tracks the cumulative PoC patch surface starting from the Phase 1 baseline. | Crown documentation | Low |

## Existing upstream Bitcoin files modified in Phase 2

| File | Reason | Classification | Merge risk |
| --- | --- | --- | --- |
| `src/CMakeLists.txt` | Links the new isolated Crown consensus sources into existing common build targets. | Build wiring only | Low |
| `src/test/CMakeLists.txt` | Registers the new Crown consensus unit-test file with `test_bitcoin`. | Test build wiring only | Low |

## Files intentionally left untouched in Phase 2

- `src/validation.cpp`
- `src/net_processing.cpp`
- chainstate
- mempool
- miner
- wallet
- script validation
- fork-choice logic

## Merge-risk summary

Phase 2 introduces no meaningful new upstream consensus-coupled surface. The only upstream edits are localized build/test registration changes, so rebasing risk should remain low relative to the larger Phase 1 chain-selection and startup plumbing already present.
