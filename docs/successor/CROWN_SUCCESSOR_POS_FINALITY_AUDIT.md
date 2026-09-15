# Crown Successor — Bitcoin Core + PoS/Finality Architecture Audit

## Executive answer

**Recommended consensus family:** **Tendermint/CometBFT-style bonded BFT PoS with deterministic finality**, implemented as a **Crown consensus module** around a largely upstream Bitcoin Core transaction/UTXO engine.

**Acceptable alternative:** **HotStuff-family BFT PoS** (especially if Crown later needs lower vote-message complexity at larger validator sets).

**Rejected for v1 successor baseline:** BABE+GRANDPA, Gasper/Casper-FFG, Ouroboros family, Avalanche/Snowman family.

Why this answer:

1. Best fit for Crown’s explicit bootstrap reality (4 validators, possibly one operator initially) with clear, auditable safety/liveness thresholds.
2. Deterministic finality with straightforward full-node verification (no trust in validator RPC/service node).
3. Clean role separation: validators secure consensus; service/archive nodes distribute verifiable data only.
4. Lowest overall implementation and maintenance risk among mature designs that still preserve Bitcoin transaction/wallet/script stack.
5. Supports progressive decentralization without changing consensus family.

---

## 1) Modern Bitcoin consensus boundary (what must change vs what should stay)

Target architecture is **Bitcoin Core-derived execution + Crown consensus adapter**, not a legacy Crown extension.

### Keep upstream-like (high mergeability target)

- Transaction format/serialization, witness, script, Taproot/Tapscript, sighash
- UTXO model and state transition logic
- Mempool policy architecture and relay policy framework
- Wallet/PSBT/descriptors/miniscript compatibility surface
- P2P transport, peer manager hardening, compact block relay, compact filters (with incremental adapter hooks only)
- Chainstate DB, block storage, pruning machinery, AssumeUTXO base machinery
- Test/fuzz scaffolding philosophy and structure

### Replace/adapt (consensus boundary)

- PoW difficulty/target checks and PoW chainwork fork-choice assumptions
- Miner-driven block production interfaces
- Chain selection based on accumulated work
- Header validity model that assumes PoW-only objective scoring
- Activation/signaling paths tied to miner signaling semantics

### Proposed clean boundary

- **Bitcoin-derived validation module**: tx/script/UTXO/block-structure/mempool/wallet/storage
- **Crown consensus module**: validator set, proposer selection, votes/QC/finality certificate, fork choice, equivocation evidence, slashing hooks, reward eligibility hooks
- **Adapter interfaces**: block-header extension parsing, finality verification at connect-time, consensus state snapshots/checkpoints, P2P messages for consensus votes/certificates

---

## 2) Consensus candidate matrix (against Crown architecture)

| Family | Finality | 4-validator bootstrap behavior | Independent full-node verification | Service/archive separation fit | Complexity for Crown | Maturity signal |
|---|---|---|---|---|---|---|
| Tendermint/CometBFT | Deterministic (2/3 precommit) | Strongly defined; liveness requires >=3 online honest validators in 4-set | Straightforward: verify proposer + commit signatures/QC per block | Excellent | Moderate | High (long production track record) |
| HotStuff-family | Deterministic (QC chain) | Similar 2/3 assumptions; better message scaling | Straightforward: verify QC chain and validator set proofs | Excellent | Moderate-high (view sync complexity) | Medium-high (production but less homogeneous than Tendermint) |
| BABE + GRANDPA | GRANDPA deterministic; BABE probabilistic production | Works, but two-protocol operational complexity is high for small team/bootstrap | Good, but verification/state transitions are more complex | Good | High | High in Polkadot ecosystem |
| Gasper (LMD-GHOST + FFG) | Deterministic checkpoints + probabilistic head dynamics | Not ideal for tiny bootstrap; heavier attestation/epoch machinery | Possible but heavy | Good | Very high | High |
| Ouroboros family | Probabilistic chain growth (plus protocol variants) | Works, but weaker UX around fast deterministic finality | Good but protocol math/state more complex | Good | High | High |
| Avalanche/Snowman | Probabilistic metastable finality | Can function but sensitive to networking/sample assumptions | Harder mental model for independent node users | Good | High | Medium-high |

### Crown-fit conclusion

- **Top fit:** Tendermint-style BFT PoS (simplest mature deterministic model for Crown’s likely validator range).
- **Second fit:** HotStuff-style BFT PoS (better asymptotic scaling, more implementation subtlety).

---

## 3) Bitcoin Core patch-surface matrix (expected for successor using modern upstream baseline)

Classification: `UNCHANGED`, `VERY SMALL ADAPTER`, `CROWN CONSENSUS HOOK`, `PERMANENT MODIFICATION`, `LARGE DIVERGENCE`, `REPLACE`.

| Bitcoin subsystem | Tendermint-style | HotStuff-style | BABE+GRANDPA | Gasper | Avalanche/Snowman |
|---|---|---|---|---|---|
| tx/script/witness/Taproot | UNCHANGED | UNCHANGED | UNCHANGED | UNCHANGED | UNCHANGED |
| mempool tx policy | VERY SMALL ADAPTER | VERY SMALL ADAPTER | CROWN CONSENSUS HOOK | CROWN CONSENSUS HOOK | PERMANENT MODIFICATION |
| block header fields | PERMANENT MODIFICATION | PERMANENT MODIFICATION | LARGE DIVERGENCE | LARGE DIVERGENCE | LARGE DIVERGENCE |
| PoW checks (nBits/difficulty/chainwork) | REPLACE | REPLACE | REPLACE | REPLACE | REPLACE |
| CBlockIndex fork-choice semantics | PERMANENT MODIFICATION | PERMANENT MODIFICATION | LARGE DIVERGENCE | LARGE DIVERGENCE | LARGE DIVERGENCE |
| ActivateBestChain/connect logic | CROWN CONSENSUS HOOK | CROWN CONSENSUS HOOK | LARGE DIVERGENCE | LARGE DIVERGENCE | LARGE DIVERGENCE |
| headers-first sync | PERMANENT MODIFICATION | PERMANENT MODIFICATION | LARGE DIVERGENCE | LARGE DIVERGENCE | LARGE DIVERGENCE |
| net_processing consensus msgs | PERMANENT MODIFICATION | PERMANENT MODIFICATION | LARGE DIVERGENCE | LARGE DIVERGENCE | LARGE DIVERGENCE |
| assumevalid/assumeutxo commitment integration | CROWN CONSENSUS HOOK | CROWN CONSENSUS HOOK | CROWN CONSENSUS HOOK | CROWN CONSENSUS HOOK | CROWN CONSENSUS HOOK |
| mining RPCs/getblocktemplate/generate | REPLACE | REPLACE | REPLACE | REPLACE | REPLACE |
| wallet, PSBT, descriptors | VERY SMALL ADAPTER | VERY SMALL ADAPTER | CROWN CONSENSUS HOOK | CROWN CONSENSUS HOOK | CROWN CONSENSUS HOOK |
| pruning/block storage/chainstate DB | VERY SMALL ADAPTER | VERY SMALL ADAPTER | CROWN CONSENSUS HOOK | CROWN CONSENSUS HOOK | CROWN CONSENSUS HOOK |

### Patch-surface takeaway

- All candidates must replace PoW and miner paths.
- **Tendermint/HotStuff keep the smallest *understandable* Crown patch surface** while preserving Bitcoin execution layers.
- Gasper/BABE-GRANDPA/Avalanche impose broader permanent divergence in sync/fork-choice/networking semantics.

---

## 4) Failure-mode comparison (strongest candidates)

Assume bootstrap set size = 4 validators, BFT threshold = 3/4 voting power.

### Tendermint-style (preferred)

- **All 4 online:** normal deterministic finality each height.
- **1 offline (3 online):** safety and liveness both hold.
- **2 offline (2 online):** safety holds; liveness halts (expected BFT behavior).
- **1 equivocates:** safety preserved if <1/3 Byzantine; equivocation evidence is accountable/slashable.
- **3/1 partition:** side with 3 can continue/finalize; side with 1 cannot.
- **2/2 partition:** no side can finalize (safe halt), resumes on recovery.
- **Key loss for one validator:** set can continue if still 3 active; requires validator-set update for long-term health.
- **Bootstrap operator disappears entirely:** network halts unless enough independent operators remain with 2/3+ stake.

### HotStuff-style (alternative)

- Same core BFT threshold outcomes as above.
- Better communication scaling for larger validator sets.
- Operationally more sensitive to leader/view synchronization correctness.

### Safety/liveness summary

- With N=4 and threshold 3, Crown gets clear honest messaging: redundancy != decentralization.
- Early centralization by single operator is explicit operational risk, not protocol decentralization.
- Protocol still supports progressive decentralization by onboarding new independent bonded validators via epoch/set updates.

---

## 5) Existing UTXO/PoS lessons (engineering, not fork targets)

1. UTXO+PoS systems that deeply entangle staking into wallet internals accumulate long-term merge pain.
2. Consensus logic embedded across many validation/networking files creates chronic upstream conflict.
3. Designs with weakly explicit finality make snapshot trust and service-node verification harder.
4. Clear on-chain finality proofs and validator-set commitments make independent full-node verification and snapshot authentication tractable.
5. Keep consensus-critical data compact, authenticated, and decoupled from optional service/archive incentives.

---

## 6) Final recommendation

### Preferred consensus family: Tendermint/CometBFT-style BFT PoS

**Why it fits Crown best**

- Mature and understandable deterministic finality model for Crown’s expected validator scale.
- Strong fit for bootstrap reality (4 validators) with explicit quorum/safety behavior.
- Supports validator/service/archive/full-node role separation cleanly.
- Lets Crown preserve Bitcoin transaction/wallet/script/mempool/chainstate tooling with limited consensus-boundary changes.
- Easier to reason about, audit, and operate than more complex dual-protocol or beacon-style systems.

**Safety/liveness assumptions**

- Safety requires <1/3 Byzantine voting power.
- Liveness requires >=2/3 voting power online and sufficiently synchronous periods.
- At 4 validators (equal weight), 3 signatures are required for finality.

**Expected permanent Crown-specific modules**

- Validator set state machine and epoch transitions
- Proposer schedule/selection
- Vote handling + commit/QC verification
- Fork-choice and finality integration hooks
- Equivocation evidence/slashing hook pipeline
- Consensus-aware header/body synchronization extensions

**Upstream merge burden estimate:** **MEDIUM-LOW** relative to other serious PoS/finality families, if consensus changes are tightly isolated.

### Acceptable alternative: HotStuff-family BFT PoS

Adopt if Crown later prioritizes validator-set growth and linear message scaling over implementation simplicity.

### Rejected candidates (for this successor baseline)

- **BABE+GRANDPA:** robust but two-protocol complexity raises implementation and maintenance burden.
- **Gasper:** highly mature but architecturally heavy; too much divergence for Crown’s minimal-patch objective.
- **Ouroboros family:** strong research lineage but less aligned with deterministic-finality-first UX and simple integration.
- **Avalanche/Snowman:** different networking/finality model with higher conceptual and integration divergence.

---

## 7) Crown-specific requirement checks

- **Progressive validator growth without consensus-family change:** yes (epoch-based validator-set updates).
- **Unpaid independent full/pruned nodes remain first-class verifiers:** yes; verify tx/script/UTXO + finality certificates locally.
- **Service/archive rewarded but not consensus authorities:** yes; they distribute data and proofs, not truth.
- **Atomic swap / Bitcoin compatibility:** preserved by keeping Bitcoin script/CLTV/CSV/hashlock/sighash/PSBT semantics unchanged.

---

## 8) AssumeUTXO + service-node fit

Recommended chain-of-trust model:

1. Finalized Crown block/epoch anchors canonical state.
2. Deterministic snapshot builder derives UTXO snapshot at a finalized height.
3. Snapshot manifest includes: height, block hash, validator-set commitment root, snapshot hash.
4. Commitment published via Crown consensus path (direct in-block commitment or deterministic epoch commitment object).
5. Service nodes distribute snapshot chunks + manifest.
6. Full/pruned clients verify commitment and hashes independently before loading snapshot.

This preserves service-node utility while avoiding service-node authority.

---

## 9) Minimal proof-of-concept architecture (post-research next step)

Build only:

- modern Bitcoin Core-derived node
- Crown consensus adapter implementing Tendermint-style rounds/finality
- 4 validator instances
- 1 independent non-validator full node
- standard Bitcoin-style UTXO transactions

PoC must demonstrate:

- block production
- deterministic finality
- independent full-node validation
- one-validator failure tolerance
- restart/recovery correctness
- synchronization behavior
- validator-set update path

Exclude from first PoC:

- service-node economics
- governance system
- legacy migration mechanics
- final tokenomics

---

## 10) Major implementation risks and open uncertainties

### Risks

- Consensus code bleeding into non-consensus Bitcoin subsystems (merge burden inflation).
- Header/sync modifications growing beyond planned adapter boundary.
- Validator key-management operational failures during early centralization phase.

### Uncertainties to resolve in design phase

- Exact header extension format for vote/QC commitments.
- Epoch/validator-set commitment encoding and upgrade path.
- Slashing scope (double-sign only vs broader liveness faults).
- Snapshot commitment publication mechanism choice (on-chain vs software-shipped hybrid).

---

## 11) Success-criteria answers

1. **Best fit family:** Tendermint-style BFT PoS finality.
2. **Least modern Bitcoin divergence among strong candidates:** Tendermint-style (HotStuff close second).
3. **Can Crown preserve Bitcoin tx/wallet/script/mempool/chainstate/P2P/tooling?** Yes, if consensus boundary is strictly enforced.
4. **Permanently Crown-specific modules:** validator lifecycle, finality proofs, fork choice, consensus-sync hooks, slashing evidence.
5. **Can validators be added progressively?** Yes via epoch/set updates.
6. **Can unpaid full/pruned nodes stay first-class independent validators?** Yes.
7. **Can service/archive roles stay useful/rewarded without authority?** Yes, via cryptographically verifiable distribution.
8. **Minimal PoC:** 4 validators + 1 independent full node on Bitcoin-derived execution with Tendermint-style finality adapter.

