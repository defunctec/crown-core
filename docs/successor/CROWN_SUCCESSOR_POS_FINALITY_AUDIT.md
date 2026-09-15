# Crown Successor — Bitcoin Core + PoS/Finality Architecture Audit

## Scope and baseline

This document is a staged architecture study for a **new Crown successor implementation** built from modern Bitcoin Core concepts, not a legacy Crown consensus extension.

**Pinned Bitcoin baseline for all source-level conclusions**

- Repository: https://github.com/bitcoin/bitcoin
- Tag: `v31.1`
- Commit: `9be056a8a72b624dae9623b2f7bded92c2a21c91`
- Date: `2026-07-06`
- Commit URL: https://github.com/bitcoin/bitcoin/commit/9be056a8a72b624dae9623b2f7bded92c2a21c91

**All patch-surface and merge-burden conclusions below refer to this exact baseline.**

---

## Pass history and current status

### FIRST-PASS RESULT

- **LEADING CANDIDATE:** Tendermint-style BFT/finality
- **MAIN ALTERNATIVE:** HotStuff-style BFT/finality
- **Reason:** deterministic finality, clear 4-validator behavior, and apparent better fit for independent full-node verification.

### SECOND-PASS RESULT

- Pinned Bitcoin Core baseline and added source-anchored PoW/chainwork dependency map.
- Recommendation remained **supported but still hypothesis-level**, not implementation-level decision.

### THIRD-PASS ENGINEERING VALIDATION (this pass)

- Removed ambiguity between **Tendermint protocol concepts** and **CometBFT software**.
- Added function-level Bitcoin patch-surface matrix (Tendermint-style vs HotStuff-style).
- Defined Crown validator consensus state and UTXO-bond mapping options.
- Mapped both finalists into Bitcoin header/index/chainstate/P2P/restart/AssumeUTXO realities.
- Quantified likely patch surface and 5–10 year maintenance burden for both finalists.

### CURRENT STATUS

**PROVISIONAL ARCHITECTURE RECOMMENDATION**

> **Native Crown C++ implementation of Tendermint-style BFT/finality, integrated directly into a modern Bitcoin Core-derived node while preserving Bitcoin’s UTXO, transaction, wallet, mempool, P2P transport, storage and independent full-node validation architecture.**

### CONFIDENCE

- **Medium-high** on architecture direction (Tendermint-style vs HotStuff-style).
- **Medium** on exact serialization/wire-format details pending PoC.

### REMAINING OPEN QUESTIONS

1. Exact block header extension format for consensus commitments.
2. Whether to commit full vote sets on-chain or commit compact QC/certificate only.
3. Validator-set transition cadence and unbonding/slashing policy specificity.
4. Exact anti-DoS adaptation replacing chainwork-based presync guards.

---

## 1) Tendermint protocol vs CometBFT software (ambiguity removed)

### A. What Tendermint-style means here

A BFT protocol model (height/round/proposal/prevote/precommit/commit, >2/3 voting power finality), **implemented natively in Crown/Bitcoin-derived code**.

### B. What CometBFT software is

[VERIFIED SOURCE FACT] CometBFT describes itself as a **BFT middleware / consensus engine** replicating an application state machine through ABCI, with its own consensus and networking stack (CometBFT repo README; ABCI docs).

- Source: https://github.com/cometbft/cometbft/blob/main/README.md
- Source: https://github.com/cometbft/cometbft/blob/main/spec/abci/abci++_basic_concepts.md

[VERIFIED SOURCE FACT] ABCI 2.0 exposes consensus/block execution hooks (`PrepareProposal`, `ProcessProposal`, `ExtendVote`, `VerifyVoteExtension`) and CometBFT-side mempool/consensus lifecycle behavior.

### C. Crown conclusion

[ENGINEERING INFERENCE] Running Bitcoin Core as an app behind standalone CometBFT would duplicate/replace too much of Bitcoin’s integrated node architecture (mempool path, block propagation semantics, consensus networking state machine, node lifecycle coupling), creating a deeper fork boundary than required.

[PROVISIONAL DECISION] Crown should **not** adopt standalone CometBFT software as the primary node runtime. Crown should adopt **native Tendermint-style protocol concepts** inside the Bitcoin-derived node.

---

## 2) Finalists and objective for this pass

This pass compares only:

- **Finalist A:** Native Tendermint-style integration.
- **Finalist B:** Native HotStuff-style integration.

Decision objective:

> Smallest sustainable Bitcoin Core patch surface that still satisfies Crown’s validator/service/archive/full-node model and independent verification requirement.

---

## 3) Function-level Bitcoin patch-surface matrix (v31.1)

Classification values:

- `UNCHANGED`
- `PARAMETER / CHAINPARAM CHANGE`
- `SMALL CONSENSUS HOOK`
- `NEW CROWN MODULE BESIDE BITCOIN`
- `PERMANENT UPSTREAM FILE MODIFICATION`
- `DEEP FORK`

| Bitcoin file | Symbol | Current upstream responsibility | Tendermint-style required change | HotStuff-style required change | Classification | Merge risk | Reason |
|---|---|---|---|---|---|---|---|
| `src/primitives/block.h` | `CBlockHeader` (`nBits`, `nNonce`) | Canonical PoW-oriented header fields/serialization | Add/repurpose commitment path for finality metadata (epoch/round/cert ref) without breaking tx model | Add/repurpose commitment path for view/QC metadata | PERMANENT UPSTREAM FILE MODIFICATION | HIGH | Header struct is consensus-critical and broadly referenced |
| `src/chain.h` | `CBlockIndex::nChainWork`, `GetBlockProof` | Work-based chain scoring and comparisons | Retain for anti-DoS metric if useful, but fork choice cannot be chainwork-primary after finality | Same; likely need QC-aware comparator | PERMANENT UPSTREAM FILE MODIFICATION | HIGH | Affects branch selection and peer sync heuristics |
| `src/node/blockstorage.h/.cpp` | `BlockManager`, `AddToBlockIndex`, `LoadBlockIndex` | Block index/storage maintenance, index metadata rebuild | Add Crown consensus metadata load/store hooks and snapshot consistency checks | Same plus QC/highest-QC metadata wiring | SMALL CONSENSUS HOOK + NEW CROWN MODULE BESIDE BITCOIN | MEDIUM | Storage code can stay mostly intact with metadata sidecar |
| `src/validation.h` | `Chainstate`, `ChainstateManager`, `Assumeutxo` state | Validation/activation interfaces and chainstate management | Add consensus-validator interfaces (certificate checks, branch comparator hook) | Same, with richer view-change safety interface | SMALL CONSENSUS HOOK | HIGH | Public validation interfaces are high-churn upstream zones |
| `src/validation.cpp` | `AcceptBlockHeader` | Header acceptance and basic chain linking | Require proposer/finality metadata verification hooks | Require proposer/QC linkage and view progression checks | PERMANENT UPSTREAM FILE MODIFICATION | HIGH | Central consensus gate |
| `src/validation.cpp` | `AcceptBlock` / `ProcessNewBlock` | Block acceptance and pipeline entry | Integrate consensus object validation path before activation | Same, plus HotStuff sync-info/QC constraints | PERMANENT UPSTREAM FILE MODIFICATION | HIGH | Main entry path for new blocks |
| `src/validation.cpp` | `ConnectBlock` / `DisconnectBlock` | UTXO state transitions, undo/reorg mechanics | Keep Bitcoin tx/script logic; add validator-set transition apply/undo hooks | Same; apply/undo QC-relevant epoch transition hooks | SMALL CONSENSUS HOOK | MEDIUM | Hookable without rewriting script/UTXO rules |
| `src/validation.cpp` | `FindMostWorkChain` | Candidate tip selection by best work | Replace/augment comparator: pre-finality preference + post-finality hard constraints | Replace/augment comparator using highest QC / commit rule | PERMANENT UPSTREAM FILE MODIFICATION | HIGH | Directly replaces PoW fork-choice assumption |
| `src/validation.cpp` | `ActivateBestChain`, `ActivateBestChainStep` | Reorg/activation engine | Reuse machinery but gate against finalized checkpoint regressions and cert validity | Reuse machinery with locked/highest-QC rules and finality guards | PERMANENT UPSTREAM FILE MODIFICATION | HIGH | Core chain activation hotspot |
| `src/pow.cpp` | `GetNextWorkRequired`, `CheckProofOfWorkImpl`, `DeriveTarget` | Difficulty and PoW validity | Deactivate/replace for production Crown consensus | Deactivate/replace for production Crown consensus | DEEP FORK (PoW subsystem) | MEDIUM | Full PoW replacement is unavoidable but isolated |
| `src/net_processing.cpp` | `ProcessHeadersMessage` | Header-message handling and presync transitions | Add consensus metadata propagation validation and cert-aware progression checks | Add QC/new-view sync handling and stricter view-sync checks | PERMANENT UPSTREAM FILE MODIFICATION | HIGH | Net processing is frequently updated upstream |
| `src/net_processing.cpp` | `FindNextBlocksToDownload`, peer chain-sync state | Download scheduling and chainwork/anti-DoS assumptions | Replace chainwork-centric gating with finalized-height + certificate-aware gating | Same with additional QC freshness/view progression heuristics | PERMANENT UPSTREAM FILE MODIFICATION | HIGH | Strongly coupled to chain scoring assumptions |
| `src/headerssync.h/.cpp` + integration in `net_processing` | header presync pipeline | Work-threshold presync + redownload logic | Adapt pre-validation target from work-threshold to consensus-cert threshold | Similar but likely more sync-info complexity | PERMANENT UPSTREAM FILE MODIFICATION | HIGH | Security-critical sync hardening path |
| `src/kernel/chainparams.cpp` | `nMinimumChainWork`, `defaultAssumeValid`, `m_assumeutxo_data` | Hardcoded trust anchors and AssumeUTXO metadata | Add Crown finalized checkpoint roots and consensus-state snapshot anchors | Same | PARAMETER / CHAINPARAM CHANGE + SMALL CONSENSUS HOOK | LOW | Mostly parameterized if commitment format stable |
| `src/node/utxo_snapshot.h/.cpp` | `SnapshotMetadata`, `WriteSnapshotBaseBlockhash` | UTXO snapshot format and local snapshot metadata | Extend metadata to include consensus-state commitment root(s) | Same | SMALL CONSENSUS HOOK | MEDIUM | Snapshot format extension is contained |
| `src/rpc/blockchain.cpp` | `chainwork` exposure, chain state RPCs | Reports work-centric confidence metrics | Add Crown finality fields (finalized height/hash/epoch/set root) | Same | PERMANENT UPSTREAM FILE MODIFICATION | MEDIUM | RPC schema evolves; maintain compat carefully |
| `src/rpc/mining.cpp` | `getblocktemplate` | Miner-oriented block assembly API | Replace with validator proposal/status APIs; keep admin style | Same | DEEP FORK (mining API) | LOW | Mining API can diverge without touching wallet/script |
| `src/versionbits.cpp` | `VersionBitsCache`, `ComputeBlockVersion` | Miner-signaled activation tracking | Keep for non-consensus feature signaling or replace with validator signaling | Same | SMALL CONSENSUS HOOK / PARAMETER CHANGE | MEDIUM | Optional retention based on Crown governance model |
| `src/node/miner.cpp` | `BlockAssembler`, generation loops | Block construction/mining pipeline | Reuse tx selection/assembly internals, replace PoW generation loop with validator proposer flow | Same | NEW CROWN MODULE BESIDE BITCOIN + SMALL CONSENSUS HOOK | MEDIUM | Block assembly reusable; proposer policy is new |
| `src/test/pow_tests.cpp`, `src/test/fuzz/pow.cpp` | PoW correctness tests | Validate PoW math/transition checks | Replace/retire with Crown consensus validity tests | Same | PERMANENT UPSTREAM FILE MODIFICATION | MEDIUM | Test suite must track consensus replacement |
| `src/test/headers_sync_chainwork_tests.cpp`, `src/test/fuzz/p2p_headers_presync.cpp` | Chainwork-based sync hardening tests | Presync anti-DoS and chainwork thresholds | Rewrite around certificate/finality-driven sync thresholds | Same, likely broader for view-sync | PERMANENT UPSTREAM FILE MODIFICATION | HIGH | Critical anti-DoS behavior changes |
| `src/test/versionbits_tests.cpp`, `src/test/fuzz/versionbits.cpp` | Deployment state-machine tests | Miner-signal activation semantics | Either retain or refit to validator signaling policy | Same | PARAMETER / CHAINPARAM CHANGE | LOW-MEDIUM | Depends on whether versionbits kept |

### Matrix outcome

[ENGINEERING INFERENCE] Both finalists touch nearly the same upstream hotspots. The main divergence is **consensus-state complexity in networking and restart safety**:

- Tendermint-style: more vote-step message types (prevote/precommit), simpler commit intuition.
- HotStuff-style: fewer message families but more subtle QC/view-sync/safety-state machinery.

---

## 4) Touchpoint classification summary by subsystem

### Likely unchanged (or near-unchanged)

- Script engine and witness handling (`src/script/*`) — **UNCHANGED**
- Transaction structure/serialization (`src/primitives/transaction*`) — **UNCHANGED**
- Wallet core internals for normal users (`src/wallet/*`) — **UNCHANGED** with optional isolated validator tooling
- PSBT/descriptors stack — **UNCHANGED**
- secp256k1 integration — **UNCHANGED**

### Must be permanently modified

- Validation/activation/fork-choice core (`validation.cpp`, `validation.h`)
- Headers sync and peer sync logic (`net_processing.cpp`, headers sync path)
- Header/index consensus fields and interpretation (`primitives/block.h`, `chain.h`)
- Mining RPC and generation paths (`rpc/mining.cpp`, proposer flow)

### Best isolated into new Crown modules beside Bitcoin

- Validator set state machine
- Vote/certificate verification
- Branch comparator / finality rule engine
- Consensus P2P message codec/relay policy
- Durable consensus safety DB

---

## 5) Quantified Crown patch-surface estimate (finalists)

### Finalist A — Native Tendermint-style

- Permanent upstream file modifications: **~14–22 files**
- Small integration hooks: **~10–16 files**
- New Crown-specific files/modules: **~28–45 files**
- Highest-conflict upstream files:
  - `src/validation.cpp`
  - `src/net_processing.cpp`
  - `src/validation.h`
  - `src/chain.h`
  - `src/primitives/block.h`
- Major permanently affected subsystems:
  - chain activation/fork choice
  - headers sync and peer chain-progress checks
  - header/index consensus metadata
  - mining/proposer RPC layer

### Finalist B — Native HotStuff-style

- Permanent upstream file modifications: **~16–26 files**
- Small integration hooks: **~12–20 files**
- New Crown-specific files/modules: **~34–55 files**
- Highest-conflict upstream files: same core set as above, with larger risk in:
  - `src/net_processing.cpp`
  - consensus safety/restart interfaces in `validation.*`
- Major permanently affected subsystems: same as Tendermint-style, with extra complexity in view-change and sync-info handling.

### Comparative result

[ENGINEERING INFERENCE] HotStuff likely increases Crown-only module count and integration complexity more than it reduces invasive Bitcoin edits; both still require similar upstream file touchpoints.

---

## 6) Crown validator consensus state model

### State elements and data-location classification

| Field / mechanism | Preferred representation | Classification |
|---|---|---|
| validator identity | deterministic validator ID (pubkey hash or validator script hash) | ON-CHAIN CONSENSUS STATE |
| validator consensus pubkey | explicit key in validator registration payload | ON-CHAIN CONSENSUS STATE |
| bonded stake amount | value locked in bond UTXO | DERIVED FROM UTXO STATE |
| voting power | deterministic function of bonded stake and policy | DERIVED FROM UTXO STATE + CONSENSUS METADATA |
| activation height/epoch | queued activation record with delay | ON-CHAIN CONSENSUS STATE |
| activation delay | network consensus parameter | CONSENSUS METADATA |
| exit request | validator-exit transaction/event | ON-CHAIN CONSENSUS STATE |
| unbonding period end | computed from exit height + policy | DERIVED FROM UTXO STATE + CONSENSUS METADATA |
| forced removal | slashing/administrative consensus action with evidence | ON-CHAIN CONSENSUS STATE |
| inactivity tracking | missed-vote counters per epoch/window | LOCAL NODE STATE (derived), optionally committed summaries |
| equivocation evidence | signed conflicting votes/QCs references | ON-CHAIN CONSENSUS STATE |
| slashing outcome | spend/penalty state transition of bond UTXO | ON-CHAIN CONSENSUS STATE + DERIVED FROM UTXO STATE |
| reward eligibility | epoch participation + no disqualifying evidence | DERIVED FROM UTXO STATE + CONSENSUS METADATA |
| key rotation | explicit validator key-update transaction with delay | ON-CHAIN CONSENSUS STATE |
| validator-set version | monotonically increasing epoch/set id | ON-CHAIN CONSENSUS STATE |
| validator-set commitment | Merkle root (or canonical hash) of active set | ON-CHAIN CONSENSUS STATE |
| transition plan (pending set) | delayed-transition queue | ON-CHAIN CONSENSUS STATE |
| operator contact/runbook metadata | optional registry off-chain | OFF-CHAIN OPERATOR METADATA |

### Can validator bonds fit UTXO cleanly?

**Candidate model:** validator bond is a constrained output type in a standard Bitcoin-like transaction flow.

[CROWN DESIGN PROPOSAL] `bond-create`, `bond-update`, `bond-exit`, `bond-slash` transitions are represented as transaction patterns validated by Crown consensus rules while preserving base tx/script formats.

**Advantages**

- Keeps staking economics anchored in Bitcoin-like spend semantics.
- Preserves ordinary wallet/accounting model separation.
- Full nodes can derive stake/voting power from chainstate deterministically.

**Disadvantages / cautions**

- Requires new consensus validation rules around bond script templates and transition legality.
- Needs careful replay and reorg handling for pending activation/unbond queues.

---

## 7) Keep normal wallet code out of validator consensus

[CROWN DESIGN PROPOSAL] keep validator operations in dedicated tooling paths, not ordinary wallet behavior.

- Ordinary wallet coin selection: **UNCHANGED** (except optional “exclude bond UTXOs” policy flags).
- Wallet DB schema: avoid consensus-state embedding; use separate validator operator store.
- PSBT/descriptors: keep standard flows; validator transactions can use standard signatures/scripts with known templates.
- User balance logic: exclude bonded funds via script/label classification, not global wallet architecture rewrite.

Result: validator logic should live primarily in Crown consensus module + optional validator operator module, not across all wallet codepaths.

---

## 8) Tendermint-style round-state mapping to Bitcoin-derived node

### Mapping table

| Tendermint concept | Where it should live |
|---|---|
| height | existing block height / `CBlockIndex::nHeight` |
| round | consensus metadata in Crown consensus DB; round committed in block commitment only when needed |
| proposal | block body + consensus proposal metadata object (hash-linked) |
| prevote | ephemeral network message; persist only if needed for evidence or cert construction |
| precommit | ephemeral message; aggregate into commit certificate |
| locked block / lock round | durable validator safety state (validator-local DB), optional chain evidence refs |
| valid block / valid round hints | local in-memory consensus state |
| commit certificate | committed consensus object referenced by block (header/body commitment) |

### Persistence guidance

- Persist permanently on chain: finalized certificate commitments, validator-set transitions, slash/evidence outcomes.
- Persist in Crown consensus DB: certificate bodies, restart-critical safety state, round transition checkpoints.
- Keep ephemeral: transient vote gossip that is not required for later verification.

### Full-node finality proof shape

[CROWN DESIGN PROPOSAL] For block `H`, full node receives:

1. Block + normal Bitcoin-valid tx data.
2. Consensus certificate object (or reference) containing validator signatures over `(chain-id, H, block-hash, round, set-version)`.
3. Validator-set commitment for that height/epoch.

Node verifies:

- proposer eligibility,
- validator set and voting power,
- >2/3 signature quorum,
- certificate references parent/finality invariants.

### Pruning impact

- Pruning can drop historical full block bodies while retaining enough finalized commitment chain and headers.
- Historical detailed vote gossip is not required if compact cert/evidence objects are preserved or reconstructable from archival peers.

---

## 9) HotStuff-style mapping at equal depth

### Mapping table

| HotStuff concept | Where it should live |
|---|---|
| view number | Crown consensus DB + optional compact on-chain commitment |
| leader/proposer | derived from validator set and deterministic election function |
| proposal block | normal block + QC reference |
| vote | validator signed vote messages (ephemeral, cert-aggregated) |
| quorum certificate (QC) | consensus object committed/referenced by blocks |
| locked QC / highest QC | durable validator safety state and chain-consensus metadata |
| view-change/new-view | consensus P2P messages + durable safety checkpoints |
| commit/finality rule | Crown consensus module using QC chain rule |

### Tendermint vs HotStuff integration implications

- **Could QC map cleanly to Bitcoin structures?** Yes, for both; HotStuff’s QC-centric model is naturally compact.
- **Less persistent metadata?** Sometimes yes for message families, but durable safety tracking (`highest_qc`, locked state, last voted/view) remains mandatory.
- **More complex networking?** Usually yes in practice due to view-sync/new-view handling subtleties.
- **Benefit at 4–500 validators?** Real but moderate; largest gains appear at bigger validator counts than Crown’s likely near/mid-term range.

---

## 10) Minimal Crown consensus serialization format (both finalists)

### Proposed minimal committed fields

| Field | Tendermint-style placement | HotStuff-style placement | Why |
|---|---|---|---|
| proposer ID | block body consensus metadata (or header commit) | same | proposer eligibility verification |
| epoch / set-version | header commitment and/or body metadata | same | validator-set lookup determinism |
| round/view | body metadata + cert object | body metadata + QC | replay/safety context |
| validator-set commitment root | header-committed | header-committed | light/full verification anchor |
| finality certificate hash/QC hash | header-committed reference | header-committed reference | compact immutable commitment |
| full certificate payload | separate consensus object in block body or sidecar object store | same | avoid bloating header |
| parent finality reference | certificate payload | certificate payload | chain-of-finality linkage |

[CROWN DESIGN PROPOSAL] Keep header divergence minimal: commit only compact roots/hashes, keep heavy cert payload in block body/consensus object store.

---

## 11) Temporary fork choice vs finality (both finalists)

### Shared model

- Multiple candidate tips may exist pre-finality.
- Comparator should prioritize chain that is consistent with highest valid consensus certificate and finalized checkpoint.
- Once finalized, conflicting branches beyond finalized height are invalid for activation.

### Tendermint-style

- Pre-finality preference: highest justified round with valid proposer/certificate progression.
- Finality point: block with valid >2/3 precommit-derived commit certificate.

### HotStuff-style

- Pre-finality preference: highest valid QC chain with safety-rule conformity.
- Finality point: per chosen HotStuff commit rule (e.g., 2-chain/3-chain profile) once QC relation satisfies commit condition.

### Reuse of Bitcoin activation machinery

[ENGINEERING INFERENCE] `ActivateBestChain`/`ConnectBlock`/`DisconnectBlock` machinery can largely remain, with comparator and finality-gate replacement. This is a major reason to prefer native integration over standalone consensus engine architecture.

---

## 12) New node bootstrap (e.g., install in 2032)

A new node must independently derive:

- canonical finalized history,
- validator-set transition history,
- current validator set,
- finality state,
- UTXO state.

### Verification path without trusted server

1. Sync headers and consensus commitments.
2. Validate consensus certificates and set transitions from genesis (or from trusted software-shipped checkpoints + subsequent validation).
3. Validate blocks/UTXO transitions and consensus links.
4. Reach active tip only if both execution validity and consensus-finality validity hold.

### Must replay from genesis?

- Strict mode: yes, eventually replay all consensus transitions for full historical assurance.
- Fast mode with AssumeUTXO-like bootstrap: start from authenticated snapshot including consensus-state commitments, then background-validate history.

---

## 13) AssumeUTXO with PoS/finality state

Bitcoin AssumeUTXO snapshot metadata is UTXO-centric. Crown must add consensus anchors.

### Required snapshot commitments (Crown)

- finalized block hash/height,
- validator-set version and root,
- consensus-state root/hash (pending exits/unbonding/slashing queue commitments as needed),
- finality certificate reference for snapshot base.

### Trust model

- Service nodes distribute files/chunks only.
- Snapshot trust comes from consensus-committed roots and/or software-shipped authenticated checkpoints.
- Background validation must be able to detect mismatch; if mismatch occurs, snapshot chainstate is invalidated and node falls back to validated chainstate path.

---

## 14) Restart and crash recovery requirements

### Validator crash mid-round/view

Must durably store before/at signing:

- last signed height+round/view,
- lock state (`locked_block_id`, lock round/view),
- highest known cert/QC,
- validator-set version and local signer key version,
- anti-rollback signing counter.

If these roll back, equivocation risk increases.

[CROWN DESIGN PROPOSAL] Use a small **Crown consensus DB** separate from UTXO chainstate DB for safety-critical validator state.

---

## 15) P2P message design (preliminary)

### Tendermint-style candidate messages

- `crown_proposal`
- `crown_prevote`
- `crown_precommit`
- `crown_commit_cert`
- `crown_consensus_state` (sync hint)
- `crown_evidence`

### HotStuff-style candidate messages

- `crown_proposal`
- `crown_vote`
- `crown_qc`
- `crown_new_view` / timeout certificate
- `crown_sync_info`
- `crown_evidence`

### Delivery/persistence notes

- Consensus-critical: proposal/vote/cert/QC/evidence.
- Full nodes need: blocks + final cert/QC path + validator-set commitments; do not need every transient gossip message persisted.
- Transport can reuse Bitcoin P2P sockets/discovery/Tor/I2P/addrman/anti-DoS framework.
- `net_processing.cpp` still needs awareness for validation and DoS policy, but codec/logic should be delegated to isolated Crown consensus peer module where possible.

---

## 16) Ordinary full-node independent verification path

For each candidate block + consensus update, an unpaid full node verifies:

1. Bitcoin-style block/tx/script/UTXO validity.
2. Proposer eligibility at that height/epoch.
3. Validator-set commitment and transition legality.
4. Signature validity and quorum threshold (>2/3 voting power).
5. Finality rule correctness (Tendermint commit cert or HotStuff QC commit rule).
6. No conflict with previously finalized checkpoints.

No trusted validator RPC is required.

---

## 17) Bootstrap failure matrix (4 validators, 1 operator)

Assume equal voting power; threshold >2/3 => 3/4 required.

| Scenario | Tendermint-style | HotStuff-style | Safety | Liveness | Finality |
|---|---|---|---|---|---|
| 4/4 online | normal | normal | holds | holds | deterministic |
| 3/4 online | normal | normal | holds | holds | deterministic |
| 2/4 online | cannot finalize | cannot finalize | holds | halted | none/new |
| 1/4 online | halted | halted | holds | halted | none/new |
| partition 3/1 | 3-side progresses | 3-side progresses | holds | partial | deterministic on 3-side |
| partition 2/2 | safe halt | safe halt | holds | halted | none/new |
| one equivocates (<1/3) | slashable evidence; chain can continue | slashable evidence; chain can continue | holds if <1/3 Byzantine | usually holds with 3 honest | deterministic if quorum forms |
| conflicting history signatures by one validator | insufficient alone for final conflicting commit | same | holds | may degrade | final forks prevented under threshold assumptions |
| validator restart | must restore lock/sign state | must restore highest-QC/sign state | holds if state persisted | depends on recovery speed | unchanged if no equivocation |
| validator key loss | continue if 3 active; schedule set update | same | holds | may hold | deterministic if quorum remains |

**Centralization note:** 4 processes under one operator is operational redundancy, not decentralization.

---

## 18) Mature-network scaling comparison

| Validator count | Tendermint-style (prevote+precommit path) | HotStuff-style (vote/QC view path) | Practical Crown note |
|---|---|---|---|
| ~10 | low overhead | low overhead | both easy |
| ~25 | moderate signature traffic | moderate, slightly cleaner vote path | both viable |
| ~100 | noticeable vote dissemination cost | better message scaling profile | HotStuff advantage begins to matter |
| ~250 | high without aggregation/optimization | high but generally more favorable | both may need aggregation |
| ~500 | heavy; careful engineering needed | heavy; still complex | likely need aggregation and tighter gossip policy |

[ENGINEERING INFERENCE] For Crown’s likely early/mid range (4–100, possibly 250), Tendermint-style remains acceptable; HotStuff scaling advantages become stronger at higher set sizes but with added implementation complexity.

---

## 19) 5–10 year Bitcoin upstream maintenance test

| Upstream category | Tendermint-style burden | HotStuff-style burden | Why |
|---|---|---|---|
| validation architecture | DIFFICULT | DIFFICULT to PERMANENT MANUAL PORT | both modify core activation/fork-choice |
| chainstate internals | MANAGEABLE | MANAGEABLE | hooks can remain localized |
| net_processing / headers sync | DIFFICULT | PERMANENT MANUAL PORT risk higher | HotStuff view-sync integration complexity |
| wallet | EASY | EASY | if validator logic isolated |
| script/taproot/sighash | EASY | EASY | unchanged execution layer |
| mempool policy | EASY-MANAGEABLE | EASY-MANAGEABLE | mostly reusable |
| block storage/pruning | MANAGEABLE | MANAGEABLE | metadata extension needed |
| AssumeUTXO | MANAGEABLE | MANAGEABLE | add consensus-state commitments |
| encrypted P2P / transport security | EASY-MANAGEABLE | EASY-MANAGEABLE | transport stack can stay Bitcoin-derived |

Result: Tendermint-style has lower long-horizon integration risk in peer/sync/validator safety machinery.

---

## 20) Expected permanent Crown divergence vs upstream-tracking areas

### EXPECTED PERMANENT CROWN DIVERGENCE (preferred design)

| File / area | Reason | Conflict frequency | Risk | Can be isolated later? |
|---|---|---|---|---|
| `src/validation.cpp` | fork choice, finality gating, cert verification hooks | HIGH | HIGH | partly via interface extraction |
| `src/validation.h` | consensus hook interfaces and state wiring | HIGH | HIGH | partly |
| `src/net_processing.cpp` | consensus message handling and sync comparator changes | HIGH | HIGH | partially with consensus peer submodule |
| `src/chain.h` | chain scoring/index semantics beyond pure chainwork | MEDIUM-HIGH | HIGH | partial |
| `src/primitives/block.h` | consensus commitment fields/encoding strategy | MEDIUM | HIGH | limited |
| `src/pow.cpp` / pow integration | PoW replacement/deactivation | LOW-MEDIUM | MEDIUM | largely isolated |
| `src/rpc/mining.cpp` + proposer RPC | mining API replacement | MEDIUM | MEDIUM | mostly |
| headers sync path | anti-DoS and progression logic without chainwork primary | HIGH | HIGH | partial |

### EXPECTED UPSTREAM-TRACKING AREAS

- wallet core (`src/wallet/*`)
- script/interpreter (`src/script/*`)
- secp256k1
- PSBT/descriptors/miniscript-related code
- most mempool policy and transaction relay policy internals
- pruning/block file low-level mechanics (with consensus metadata hooks)
- broad build/test/fuzz infrastructure patterns

---

## 21) Proposed Crown consensus module boundary

[CROWN DESIGN PROPOSAL] keep Crown logic mostly beside Bitcoin core files:

```text
src/crown/consensus/
  validator_set.*
  validator_bond.*
  proposer_selection.*
  finality_cert.*
  fork_choice.*
  consensus_messages.*
  consensus_net.*
  consensus_db.*
  safety_state.*
  evidence.*
  snapshot_commitment.*
```

### Narrow hook surface into Bitcoin

- `ValidateConsensusHeader(...)`
- `ValidateConsensusCertificate(...)`
- `ValidateProposerEligibility(...)`
- `CompareConsensusBranches(...)`
- `ApplyValidatorTransition(...)`
- `UndoValidatorTransition(...)`
- `GetConsensusFinalizedCheckpoint(...)`
- `ValidateSnapshotConsensusCommitment(...)`

[ENGINEERING INFERENCE] This boundary is feasible if header/index/fork-choice hooks are explicit and limited.

---

## 22) Recommendation status update

### Decision status

**PROVISIONAL ARCHITECTURE RECOMMENDATION**

### Exact recommendation

> Adopt a **native Crown C++ implementation of Tendermint-style BFT/finality protocol concepts** inside a Bitcoin Core v31.1-derived node, **not standalone CometBFT software**, with HotStuff-style as a retained alternative if future validator-scale and performance data justify higher complexity.

### Why not call it “CometBFT”

Because this recommendation is for **protocol-style adoption** with Bitcoin-native integration, not replacing node architecture with CometBFT engine + ABCI app split.

---

## 23) Updated PoC specification (next task; still no implementation here)

PoC objective:

> Prove Crown can add finality consensus while keeping most Bitcoin Core maintainable/upstream-trackable.

### PoC scope

- Bitcoin Core v31.1-derived base
- 4 validators (equal initial power)
- 1 unpaid non-validator full node
- standard Bitcoin-style UTXO transactions
- consensus messages and finality proof verification
- validator-set transition case
- one-validator failure case
- validator crash/restart safety case
- initial sync path for new full node
- AssumeUTXO-style snapshot + consensus-state commitment validation

### Explicitly out of PoC scope

- service-node economics
- governance/tokenomics finalization
- legacy migration

---

## 24) Evidence classification and references

### Important claim classes used in this document

- **VERIFIED SOURCE FACT** — directly grounded in cited source.
- **ENGINEERING INFERENCE** — reasoned integration judgment from source facts.
- **CROWN DESIGN PROPOSAL** — architecture proposal for Crown successor.
- **OPEN QUESTION** — unresolved design point requiring PoC validation.

### Bitcoin Core v31.1 source anchors

- https://github.com/bitcoin/bitcoin/blob/v31.1/src/primitives/block.h
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/chain.h
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/pow.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/validation.h
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/validation.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/net_processing.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/node/blockstorage.h
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/node/blockstorage.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/node/utxo_snapshot.h
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/node/utxo_snapshot.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/kernel/chainparams.h
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/kernel/chainparams.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/rpc/blockchain.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/rpc/mining.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/versionbits.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/test/pow_tests.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/test/headers_sync_chainwork_tests.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/test/versionbits_tests.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/test/fuzz/pow.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/test/fuzz/p2p_headers_presync.cpp
- https://github.com/bitcoin/bitcoin/blob/v31.1/src/test/fuzz/versionbits.cpp

### Tendermint / CometBFT source anchors

- https://github.com/tendermint/tendermint/blob/master/spec/consensus/consensus.md
- https://github.com/cometbft/cometbft/blob/main/README.md
- https://github.com/cometbft/cometbft/blob/main/spec/abci/abci++_basic_concepts.md

### HotStuff-family authoritative implementation/spec anchors

- https://github.com/diem/diem/blob/main/specifications/consensus/README.md
- https://github.com/diem/diem/blob/main/consensus/consensus-types/src/quorum_cert.rs
- https://github.com/diem/diem/blob/main/consensus/safety-rules/src/consensus_state.rs
- https://github.com/aptos-labs/aptos-core/blob/main/consensus/README.md

---

## 25) Success-condition answers (third pass)

1. **Tendermint concepts or CometBFT software?**
   - Recommendation is Tendermint-style concepts, native Crown implementation; not standalone CometBFT.
2. **Which Bitcoin files/functions require permanent modification?**
   - Primarily `validation.*`, `net_processing.cpp`, `chain.h`, `primitives/block.h`, PoW/mining integration paths, and related tests.
3. **Approximate permanent patch surface size?**
   - Tendermint-style ~14–22 permanent upstream files; HotStuff-style ~16–26.
4. **Smaller long-term fork: Tendermint or HotStuff?**
   - Tendermint-style likely smaller operationally/maintainability-wise at Crown scale.
5. **What is Crown validator consensus state?**
   - Defined in section 6 with field-level classification.
6. **Can bonds/membership fit UTXO model?**
   - Yes, via constrained bond UTXO transitions with deterministic consensus rules.
7. **Where do votes/certs/state live?**
   - Compact commitments on chain; full cert/safety state in Crown consensus DB; ephemeral gossip in memory.
8. **What restart state must survive?**
   - last signed round/view, lock/highest cert state, signer anti-rollback data.
9. **How does a 2032 node verify history/state?**
   - Full verification from commitments/transitions, optionally accelerated by authenticated snapshot plus background validation.
10. **How extend AssumeUTXO?**
   - Include validator/finality consensus-state commitments in snapshot metadata.
11. **Can unpaid full nodes independently verify everything?**
   - Yes; mandatory design invariant.
12. **Which major Bitcoin subsystems remain upstream-like?**
   - tx/script/witness/wallet/PSBT/descriptors/secp256k1 and most mempool/storage primitives.
13. **5–10 year mergeability impact?**
   - manageable overall with difficult hotspots; Tendermint-style lower risk than HotStuff in sync/networking complexity.
14. **Can Tendermint move to provisional recommendation?**
   - Yes, now **provisional architecture recommendation**.
15. **Exact next PoC?**
   - Defined in section 23.

---

## 26) RESEARCH PHASE CONCLUSION

### PROVISIONAL ARCHITECTURE RECOMMENDATION

- **Bitcoin base:** Bitcoin Core v31.1
- **Repository:** https://github.com/bitcoin/bitcoin
- **Tag:** `v31.1`
- **Commit:** `9be056a8a72b624dae9623b2f7bded92c2a21c91`
- **Consensus direction:** Native Crown C++ implementation of Tendermint-style bonded BFT consensus/finality integrated directly into the Bitcoin Core-derived node.

Explicit boundary statements:

- Crown is **not** proposing to use standalone CometBFT.
- Crown is **not** proposing to retain legacy Crown consensus code.
- Crown is **not** attempting to convert the old Crown repository into the successor architecture.
- The old Crown repository remains historical/audit evidence only.

---

## 27) Bitcoin-upstream principle (wrap-up)

Central engineering principle:

> Crown should remain as close to modern Bitcoin Core as practical.

Crown-specific code should be:

- narrow
- modular
- isolated
- justified

Preferred implementation strategy:

- add new Crown modules beside Bitcoin Core
- avoid invasive rewrites of Bitcoin subsystems whenever technically possible

Bitcoin-derived areas intended to remain largely upstream-trackable:

- UTXO model
- transaction format
- Script / Witness / Taproot
- mempool and transaction relay
- wallet / descriptors / PSBT
- chainstate
- block storage / pruning
- P2P transport and peer management
- RPC infrastructure
- testing / fuzzing

Major replacement area: PoW-specific consensus path.

---

## 28) Consensus components to replace/adapt

Crown expects to replace or substantially adapt Bitcoin’s:

- SHA256d Proof-of-Work block production
- mining
- difficulty adjustment
- accumulated-chainwork fork choice
- PoW-specific block/header semantics where necessary
- mining-based activation/signalling assumptions

Clarification:

- SHA-256 itself is **not** being removed.
- SHA-256 remains useful for hashing, block/tx IDs, commitments, Merkle structures, and artifact integrity.
- Only SHA256d Proof-of-Work as the consensus mechanism is being removed.

---

## 29) Crown node-role model (agreed direction)

### Validators

Consensus-critical role:

- proposal
- voting
- finality
- validator-set participation
- bonded economic security

### Service nodes

Rewarded non-consensus infrastructure:

- authenticated state snapshots
- historical data
- indexes
- compact-filter data
- project artifacts
- other useful verifiable network data

Invariant:

> SERVICE NODES ARE DATA PROVIDERS, NOT AUTHORITIES.

### Archive nodes

- retain full historical data
- may be a distinct role or a service-node capability in later design

### Independent full / pruned nodes

First-class Crown participants:

- no validator bond required
- no service-node role required
- no mandatory protocol reward required
- independently verify Crown consensus and transactions

This remains a core architectural invariant.

---

## 30) Bootstrap reality

Realistic early launch may begin with ~1 independent operator running approximately:

- 4 validator instances
- several archive-capable nodes
- at least one service node

Potentially across separate infrastructure providers.

Important distinction:

- validator instance count != independent operator/control-domain count

Multiple validator processes under one owner provide operational redundancy, **not decentralisation**.

The same consensus family must allow additional independent validator operators to join later without consensus-family change.

---

## 31) Preferred finality structure

For block at height `N`:

1. block `N` is proposed and validated
2. validators perform Tendermint-style voting
3. `>2/3` voting power finalises block `N`
4. compact finality certificate is produced
5. block `N+1` commits to the finality certificate for block `N`

This avoids including signatures inside the hash of the block being signed.

Normal full nodes must independently verify finality certificates.

Exact certificate encoding remains a PoC-level design question.

---

## 32) One versioned CrownStateRoot per block

Agreed direction:

> Every Crown block should commit to one versioned `CrownStateRoot`.

Conceptual `CrownStateRoot v1` composition:

- UTXO-state commitment
- validator-state commitment
- consensus-state commitment

Future consensus-state extensions should use versioned root definitions, not ad hoc multiple unrelated block roots.

Exact authenticated-state structure remains open.

PoC must determine efficient incremental UTXO-commitment maintenance.

---

## 33) Block hash as checkpoint identifier

Simplification:

- Crown does not require service nodes to invent a separate checkpoint chain/hash.
- The ordinary Crown block hash is the checkpoint identifier.

Conceptual chain:

`CrownStateRoot -> consensus commitment in block -> tx/block commitment -> Crown block hash -> checkpoint identifier`

Commitment placement remains provisional.

---

## 34) CrownStateRoot commitment location (open)

Not yet locked:

- direct placement in `CBlockHeader`
- or commitment through a mandatory Bitcoin-style block-body/system-transaction commitment

Decision criterion:

- smallest permanent Bitcoin Core divergence
- lowest future upstream merge burden
- cleanest consensus implementation
- least destructive change to Bitcoin structures

Strong candidate:

- Bitcoin-style mandatory unspendable commitment in Crown reward/system transaction, allowing Merkle root + block hash to authenticate `CrownStateRoot` without permanently expanding `CBlockHeader`.

Status: **open; choose least invasive proven approach in PoC/code-level analysis.**

---

## 35) Snapshot model and cadence

Crown does not need full state snapshots every block.

Direction:

- every block commits `CrownStateRoot`
- periodic full state snapshots correspond to finalised Crown blocks

Do not freeze a hard snapshot interval yet.

Cadence should be chosen from:

- block time
- snapshot generation cost
- storage/bandwidth
- service-node burden
- desired new-client catch-up time

Snapshot cadence is primarily UX/performance, not core consensus security.

---

## 36) Snapshot content and format independence

Future snapshots may need enough information to reconstruct:

- UTXO state
- validator state
- bonded/unbonding state
- required slashing/evidence state
- epoch/consensus state
- other consensus-critical state

Key principle:

- consensus commits to state
- snapshot files are transport/serialization artifacts

Snapshot formats may evolve (`v1`, `v2`, new chunking/compression) without consensus fork, provided they reconstruct identical authenticated state.

---

## 37) Crown AssumeUTXO direction

Agreed UX direction (Bitcoin AssumeUTXO philosophy adapted):

A node should be able to:

1. authenticate a sufficiently recent Crown checkpoint
2. obtain matching state snapshot
3. verify snapshot against committed `CrownStateRoot`
4. start operating from that state
5. continue historical validation in background

Fast startup and eventual independent verification are both required.

Exact Crown AssumeUTXO adaptation remains implementation research.

---

## 38) Service-node distribution principle

Service nodes:

- distribute authenticated artifacts
- do not define consensus truth

Example:

- expected root from finalised block: `ABC123`
- snapshot reconstructs `ABC123` -> valid
- malicious snapshot reconstructs `DEF456` -> reject

No service-node majority vote is required for mathematical correctness.

Authoritative source remains the Crown chain and its verifiable commitments.

---

## 39) Proof-of-useful-service direction

Promising provisional reward model:

Service rewards only when service node can automatically prove it is:

- current
- storing required artifacts
- storing correct artifacts
- available
- able to serve data under required conditions

Candidate mechanisms:

- chunk challenges
- Merkle proofs
- response deadlines
- randomized possession checks
- observed serving performance
- uptime constraints

Target property:

`correct + current + proves possession + serves required data = service reward eligibility`

No recurring manual developer approval should be required.

Exact mechanism remains future design research.

---

## 40) Authenticated developer/release injection

Publication principle:

- Crown may operate authenticated publication for approved project artifacts
- signature means artifact was published/announced by Crown project
- signature does **not** mean artifact is automatically consensus-correct

Service nodes still run deterministic validation before accept/store/serve.

Candidate artifacts:

- release manifests
- snapshot manifests
- bootstrap metadata
- governance documents
- network artifacts

Security direction:

- prefer threshold/multi-key authority
- support rotation/revocation
- avoid one permanent developer signing key as single point of trust

---

## 41) New/stale node bootstrap rule

Mandatory requirement:

> If a node’s last known finalised checkpoint is older than Crown’s safe bootstrap period, it must obtain a recent authenticated checkpoint before selecting between competing histories.

Purpose:

- mitigate long-range selection risk for very stale/new nodes.

Safe-bootstrap period remains open; depends on:

- unbonding lifecycle
- slashing/economic-accountability horizon
- validator-key assumptions
- checkpoint authentication design

This must eventually be enforced automatically by client behavior.

---

## 42) Release checkpoints

Crown-native direction:

Releases should periodically include a recent known-finalised checkpoint:

```text
TrustedBootstrapCheckpoint {
  height
  Crown block hash
}
```

Optionally, clients may trust an authenticated checkpoint-publication key set to fetch newer checkpoint metadata without upgrading binary.

Checkpoint authority should only attest:

- “this block was already finalised Crown history when published.”

Checkpoint authority must not be able to:

- create coins
- rewrite balances
- choose future blocks
- select validators arbitrarily
- reverse valid transactions

Prefer threshold signatures / separated keys.

---

## 43) Long-range security position

Current conclusion:

- hashes and state commitments solve integrity/consistency/snapshot correctness
- hashes alone do not choose between competing internally valid long-range branches

Therefore:

- active/recent nodes follow locally known finalised state
- new/excessively stale nodes require recent authenticated finality checkpoint
- subsequent history is independently validated

No external Bitcoin anchoring is currently proposed.

---

## 44) NEXT PHASE: SUCCESSOR CONSENSUS PROOF OF CONCEPT

Implementation will occur in a **new PR** (not this research PR).

Suggested branch:

- `spike/successor-consensus-poc`

PoC 1 should be intentionally minimal:

- Bitcoin Core v31.1 baseline
- 4 static validators
- equal initial voting power
- 1 non-validator independently validating full node

PoC 1 should not initially include:

- dynamic validator bonding
- production tokenomics
- service-node rewards
- archive rewards
- governance
- legacy migration
- native assets
- polished wallet UX

---

## 45) First PoC success conditions

PoC 1 should demonstrate:

- normal Bitcoin-style UTXO transactions
- Bitcoin-derived transaction/script validation
- block proposals
- Tendermint-style prevote/precommit
- deterministic `>2/3` finality
- compact finality certificate
- block `N+1` commitment to certificate for `N`
- non-validator full-node verification
- validator restart/recovery
- full-node restart/resynchronization
- 4/4 validator operation
- 3/4 validator operation
- safe halt at insufficient quorum
- 3/1 partition behavior
- 2/2 partition behavior
- invalid proposal rejection
- conflicting/equivocating vote detection

---

## 46) Critical PoC architecture gate

Most important post-PoC review question:

> Did implementation keep Bitcoin Core divergence within an acceptable boundary?

After PoC 1, compare actual changes vs research estimate:

- permanently modified Bitcoin files
- new isolated Crown files
- validation changes
- net_processing changes
- chain/index logic changes
- wallet impact
- mempool impact
- script impact
- P2P impact

Decision rule:

- if Tendermint integration is significantly more invasive than predicted, stop and reconsider architecture before adding more features
- if wallet/script/mempool/UTXO remain largely upstream and consensus is reasonably isolated, architecture passes first practical gate

---

## 47) Later PoC phases (future, provisional)

### PoC 2

- `CrownStateRoot`
- authenticated incremental UTXO commitment
- validator-state commitment
- UTXO-backed validator bonds
- validator activation/exit/unbonding

### PoC 3

- periodic state snapshots
- Crown AssumeUTXO adaptation
- background historical validation
- new/stale-node checkpoint bootstrap

### PoC 4

- service-node snapshot distribution
- automated possession/availability challenges
- proof-of-useful-service
- service reward eligibility

Sequence is provisional and may change from PoC findings.

---

## 48) Final status table

| Item | Status |
|---|---|
| Bitcoin Core v31.1 base | PROVISIONAL AGREED DIRECTION |
| Native Tendermint-style BFT | PROVISIONAL ARCHITECTURE RECOMMENDATION |
| Standalone CometBFT | REJECTED |
| Legacy Crown code as successor base | REJECTED |
| Independent non-validator full nodes | ARCHITECTURAL REQUIREMENT |
| Service nodes as consensus authorities | REJECTED |
| Service nodes as verifiable data providers | PROVISIONAL AGREED DIRECTION |
| One versioned CrownStateRoot per block | PROVISIONAL AGREED DIRECTION |
| Crown block hash as checkpoint identifier | PROVISIONAL AGREED DIRECTION |
| Block N+1 commits finality certificate for N | PROVISIONAL AGREED DIRECTION |
| Full snapshot every block | REJECTED |
| Periodic authenticated state snapshots | PROVISIONAL AGREED DIRECTION |
| AssumeUTXO-style fast bootstrap + background validation | PROVISIONAL AGREED DIRECTION |
| Recent authenticated checkpoint required for stale/new nodes | ARCHITECTURAL REQUIREMENT |
| Proof-of-useful-service rewards | PROMISING / REQUIRES DESIGN & ADVERSARIAL TESTING |
| Exact CrownStateRoot commitment location | OPEN — CHOOSE LEAST INVASIVE BITCOIN INTEGRATION |
| Exact UTXO authenticated-state structure | OPEN — REQUIRES ENGINEERING RESEARCH/POC |
| Exact snapshot interval | OPEN — PERFORMANCE/UX PARAMETER |
| Exact safe-bootstrap/trusting period | OPEN — DEPENDS ON VALIDATOR LIFECYCLE |

---

## 49) PR wrap-up summary (for PR body hand-off)

### WHAT THIS PR ESTABLISHED

- Closed the architecture research stage with a documented provisional architecture recommendation.
- Pinned successor baseline to Bitcoin Core v31.1 (`9be056a8a72b624dae9623b2f7bded92c2a21c91`).
- Established native Tendermint-style integration direction inside Bitcoin-derived node architecture.
- Established non-validator independent full-node verification as mandatory.
- Established CrownStateRoot/checkpoint/snapshot/AssumeUTXO and service-node authority boundaries.
- Defined staged PoC path and practical architecture gate criteria.

### WHAT REMAINS PROVISIONAL

- exact finality certificate encoding
- exact CrownStateRoot commitment location
- exact authenticated-state internal structure
- exact snapshot cadence
- exact safe-bootstrap/trusting period
- final service reward challenge mechanics

### WHAT WAS EXPLICITLY REJECTED

- standalone CometBFT as successor runtime architecture
- legacy Crown codebase as successor implementation base
- service nodes as consensus authorities
- full-state snapshot every block

### WHY IMPLEMENTATION IS NOT INCLUDED

This PR is intentionally research/documentation-only and preserves a clean architecture decision hand-off. Implementation and falsification of assumptions belongs in a dedicated PoC PR.

### NEXT PR: SUCCESSOR CONSENSUS POC

The next PR should attempt to falsify this provisional architecture by implementing the smallest viable Crown consensus network and measuring real Bitcoin Core divergence against this research estimate.

Final wrap-up statement:

- This PR closes the architecture-research stage.
- It does **not** claim production consensus readiness.
- Recommendation remains provisional until PoC validation.

