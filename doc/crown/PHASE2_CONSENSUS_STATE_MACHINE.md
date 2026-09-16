# Crown Successor PoC Phase 2

## Scope

Phase 2 adds an isolated native Crown consensus state machine that operates on abstract `BlockID` values (`uint256`) and remains disconnected from live Bitcoin block production, fork choice, validation, and P2P message handling.

Implemented:

- deterministic proposer rotation over the four static Phase 1 validators
- signed proposals and signed `PREVOTE` / `PRECOMMIT` messages
- explicit `NIL` voting via absent vote `block_id`
- exact voting-power quorum reuse from Phase 1
- one-height event-driven round progression across `PROPOSE`, `PREVOTE`, `PRECOMMIT`, and `COMMIT`
- Tendermint-style lock tracking with `locked_block` / `locked_round`
- `valid_block` / `valid_round` tracking and proposal handling
- equivocation detection for conflicting votes
- logical local double-sign protection for the in-process signer
- deterministic in-process multi-validator simulation tests

Deferred:

- live Bitcoin `CBlock` proposal and validation integration
- `net_processing.cpp` or live consensus P2P messages
- production finality certificates
- persistent crash-safe signing state
- staking, delegation, dynamic validator sets, and slashing economics

## State machine

Each engine models a single consensus height with:

- `height`
- `round`
- `step`
- `locked_block`
- `locked_round`
- `valid_block`
- `valid_round`
- the current round proposal
- an optional `CommitDecision`

Round changes do not reset the height. `PRECOMMIT_TIMEOUT` advances from round `r` to round `r+1` while preserving lock and valid-round state.

## Proposals

`Proposal` contains:

- `height`
- `round`
- proposer validator id
- proposed `BlockID`
- `valid_round`
- signature

The provisional proposer rule is deterministic rotation in static validator order:

1. `validator-a`
2. `validator-b`
3. `validator-c`
4. `validator-d`

Round `r` uses proposer index `r mod 4`.

The engine rejects proposals with:

- unknown proposer id
- proposer mismatch for the round
- invalid signature
- wrong height
- wrong round
- missing `BlockID`
- malformed `valid_round`

## Votes

`Vote` contains:

- vote type (`PREVOTE` or `PRECOMMIT`)
- `height`
- `round`
- validator id
- `BlockID` or explicit `NIL`
- signature

Canonical signing bytes are deterministic hash inputs over message domain, vote/proposal metadata, validator identity, and the optional block value. Unknown validators and invalid signatures contribute zero voting power.

## NIL semantics

`NIL` is a first-class consensus value used when:

- a proposal is missing
- a proposal is externally marked invalid
- a proposal conflicts with the local lock and does not carry sufficient `valid_round` proof
- timeout progression requires voting without a valid block

`PREVOTE(NIL)` and `PRECOMMIT(NIL)` advance the protocol without committing a block.

## Quorum rule

Phase 2 reuses the Phase 1 exact power model:

- total power = `100`
- quorum threshold = `floor(2 * total_power / 3) + 1 = 67`

Any three validators provide `75` power and satisfy quorum. Two validators provide `50` power and do not.

Duplicate identical votes are counted once. Conflicting votes from the same validator never both count.

## Locking semantics

The engine locks when it observes `>2/3` `PREVOTE`s for a concrete block in the current round and then emits `PRECOMMIT(block)`.

While locked on block `X`, the engine:

- may `PREVOTE(X)` again in later rounds
- must not `PREVOTE(Y)` for conflicting `Y` without sufficient `valid_round` evidence
- may `PREVOTE(NIL)` if a conflicting proposal lacks such evidence

The lock changes only after the engine sees a later-round `PREVOTE` quorum for another block and then emits `PRECOMMIT` for that later block.

## `valid_round` semantics

When the engine observes `>2/3` `PREVOTE`s for block `B` in round `r`, it stores:

- `valid_block = B`
- `valid_round = r`

A later proposal for `B` may reference that `valid_round`. If the local node is locked on another block from an earlier round, and it has stored proof of the referenced `PREVOTE` quorum, it may safely `PREVOTE(B)` in the later round.

## Timeout events

Phase 2 uses deterministic timeout events instead of real clocks:

- `PROPOSE_TIMEOUT`
- `PREVOTE_TIMEOUT`
- `PRECOMMIT_TIMEOUT`

`PROPOSE_TIMEOUT` drives `PREVOTE(NIL)` when needed. `PREVOTE_TIMEOUT` drives `PRECOMMIT(NIL)` when needed. `PRECOMMIT_TIMEOUT` starts the next round.

## Equivocation detection

The engine records evidence when a validator sends conflicting votes for the same:

- height
- round
- vote type

Evidence is exposed as paired conflicting votes and is suitable for later slashing integration. Phase 2 does not implement economics or punishment.

## Local double-sign protection

The local in-process signer refuses to produce two different votes for the same:

- height
- round
- vote type

This is a logical guard only. Persistent crash-safe signing state is deferred. Production validator safety still requires durable signing-state persistence before any live multi-process deployment.

## Simulator and tests

The Phase 2 unit tests instantiate four local engines and deliver:

- proposals
- votes
- timeouts
- delayed messages
- dropped messages
- 3/1 and 2/2 partitions
- conflicting Byzantine vote messages
- deterministic message-order permutations

The simulator enforces the invariant that no two honest engines may commit different block ids at the same height.

Tested scenarios include:

- 4/4, 3/4, and 2/4 availability thresholds
- offline proposer round change
- invalid proposals
- duplicate, stale, wrong-height, unknown-validator, and bad-signature votes
- `NIL` quorum handling
- prevote and precommit equivocation
- lock retention and valid-round transitions
- partition behavior
- deterministic message-order permutations

## Known Phase 2 limitations

- Consensus operates on abstract `BlockID` values only.
- No Bitcoin chainstate, mempool, miner, wallet, or script code is modified.
- No live proposal/vote networking exists.
- No persistent signer state exists yet.
- Only the static Phase 1 validator set is supported.
