# Crown Revival — Phase 1D: Executed MNPoS Private-Network Validation

## Starting baseline

- Copilot branch: `copilot/phase-1d-mnpos-validation`
- Current HEAD at phase start and at audit close: `0f69245dc75e435102298e7377f5ccd317065ff6`
- `master` SHA fetched for baseline comparison: `0f69245dc75e435102298e7377f5ccd317065ff6`
- `git status` at start: clean (before this Phase 1D doc/tooling work)
- Required merged revival docs present:
  - `docs/revival/RECOVERY_BASELINE.md`
  - `docs/revival/CONSOLIDATION_REPORT.md`
  - `docs/revival/MULTINODE_NETWORK_AUDIT.md`
- Phase 1C findings carried forward, including the regtest `tCRW...` validation limitation.

## Execution environment

- Execution model: **NATIVE** (no Docker)
- Host OS: Ubuntu 24.04.4 LTS
- Kernel: Linux 6.17.0-1022-azure x86_64
- Compiler: gcc/g++ 13.3.0
- OpenSSL: 3.0.13
- Boost: 1.83.0.1ubuntu2
- Build path executed:
  - `./autogen.sh`
  - `./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui`
  - `make -C src -j4 crownd crown-cli crown-tx`
- Built binaries:
  - `crownd v0.14.0.7-0f69245`
  - `crown-cli v0.14.0.7-0f69245`

## Source architecture

### Masternodes

- Collateral amount: **10000 CRW**. **CONFIRMED FROM SOURCE** (`src/wallet.h:54`)
- Min confirmations: **15**. **CONFIRMED FROM SOURCE** (`src/masternode.h:17`, `src/masternode.cpp:702-721`)
- Expiry/removal windows: **65 min / 75 min**. **CONFIRMED FROM SOURCE** (`src/masternode.h:21-22`, `src/masternode.cpp:192-197`)
- Active state transitions (`ENABLED`, `EXPIRED`, `REMOVE`, `VIN_SPENT`). **CONFIRMED FROM SOURCE** (`src/masternode.cpp:188-220`)
- Registration/broadcast path through masternode broadcast creation and checks. **CONFIRMED FROM SOURCE** (`src/masternode.cpp:456-511`, `src/masternode.cpp:669-764`)
- Operator key/signover support (`fSignOver`). **CONFIRMED FROM SOURCE** (`src/masternode.cpp:486-499`)

### Systemnodes

- Collateral amount: **500 CRW**. **CONFIRMED FROM SOURCE** (`src/wallet.h:55`)
- Min confirmations: **15**. **CONFIRMED FROM SOURCE** (`src/systemnode.h:16`, `src/systemnode.cpp:624-643`)
- Expiry/removal windows: **65 min / 75 min**. **CONFIRMED FROM SOURCE** (`src/systemnode.h:20-21`, `src/systemnode.cpp:284-289`)
- Active state transitions (`ENABLED`, `EXPIRED`, `REMOVE`, `VIN_SPENT`). **CONFIRMED FROM SOURCE** (`src/systemnode.cpp:280-310`)
- Registration/broadcast path through systemnode broadcast creation and checks. **CONFIRMED FROM SOURCE** (`src/systemnode.cpp:783-834`, `src/systemnode.cpp:592-686`)
- Operator key/signover support (`fSignOver`). **CONFIRMED FROM SOURCE** (`src/systemnode.cpp:813-822`)

### MNPoS

- PoS activation gate: block height `>= PoSStartHeight`; PoW rejected after gate and PoS rejected before gate. **CONFIRMED FROM SOURCE** (`src/main.cpp:2374-2385`)
- Regtest PoS start behavior: regtest inherits testnet PoS start (`141000`) because `CRegTestParams` extends `CTestNetParams` and does not override `nBlockPoSStart`. **CONFIRMED FROM SOURCE** (`src/chainparams.cpp:346-367`, `src/chainparams.cpp:574-609`)
- Stake pointer validity rules include:
  - referenced block must be on active chain
  - depth limited by `ValidStakePointerDuration`
  - must be older than `MaxReorganizationDepth`
  - pointer reuse rejected
  - pointed output must be payment slot output
  **CONFIRMED FROM SOURCE** (`src/main.cpp:2250-2332`, `src/main.cpp:2344-2353`)
- Payment-slot dependency in pointer validity (`MN_PMT_SLOT=1`, `SN_PMT_SLOT=2`). **CONFIRMED FROM SOURCE** (`src/masternode-payments.h:28`, `src/systemnode-payments.h:27`, `src/main.cpp:2331`)
- Stake pointer construction from recent MN/SN payment outputs. **CONFIRMED FROM SOURCE** (`src/wallet.cpp:2091-2160`)
- Block signature creation/validation path (`SignBlock` + `CheckBlockSignature`) and collateral signover verification. **CONFIRMED FROM SOURCE** (`src/mn-pos/stakeminer.cpp:26-65`, `src/mn-pos/stakevalidation.cpp:11-23`, `src/main.cpp:2311-2314`, `src/main.cpp:2351-2353`)

### Sporks / payments / governance interactions

- Relevant sporks include `SPORK_4`, `SPORK_8`, `SPORK_13`, `SPORK_14`, `SPORK_15`, `SPORK_16`. **CONFIRMED FROM SOURCE** (`src/spork.h:31-41`)
- Defaults for enforcement sporks are mostly future timestamp `4070908800` (off), while `SPORK_4` has special start-time behavior. **CONFIRMED FROM SOURCE** (`src/spork.h:47-58`, `src/spork.cpp:78-90`)
- Payment validity checks are sync- and spork-dependent; unsynced nodes may accept longest chain behavior without strict payment enforcement. **CONFIRMED FROM SOURCE** (`src/masternode-payments.cpp:50-102`, `src/systemnode-payments.cpp:27-80`)
- Governance/budget code can inject superblock payment behavior when enabled. **CONFIRMED FROM SOURCE** (`src/masternode-budget.cpp:449-473`, `src/masternode-payments.cpp:133-142`, `src/systemnode-payments.cpp:183-192`)

## Bootstrap path

**Question:** How does a fresh chain obtain its first valid MNPoS producer?

- Fresh chain starts in PoW mode until `PoSStartHeight`; PoS blocks are invalid before that. **CONFIRMED FROM SOURCE** (`src/main.cpp:2374-2385`)
- On regtest, `PoSStartHeight` is effectively inherited from testnet (141000). **CONFIRMED FROM SOURCE** (`src/chainparams.cpp:346-367`, `src/chainparams.cpp:574-609`)
- Therefore bootstrap sequence is:
  `PoW blocks -> spendable coins -> MN/SN collateral + maturity -> payment outputs usable as stake pointers -> MNPoS eligibility -> PoS blocks`
  **INFERRED** from source rules above.
- No dedicated consensus bootstrap shortcut was identified in current recovered source. **CONFIRMED FROM SOURCE / UNKNOWN** (no explicit alternate bootstrap hook found).

## Topology

Runtime topology executed natively (localhost-only):

- `ctl` (observer/controller wallet): RPC 18401 / P2P 24001
- `mn1`: RPC 18402 / P2P 24002
- `sn1`: RPC 18403 / P2P 24003
- `obs`: RPC 18404 / P2P 24004

All datadirs were disposable under `/tmp/crown-phase1d`.

## Collateral setup

- Systemnode collateral UTXO created and matured:
  - type: Systemnode
  - amount: `500.00000000`
  - txid: `6f520bf933be0d4a044c01f77013eeb8e7aa3b1c39a66a5ed97f2bbd4dd1974a`
  - vout: `0`
  - confirmations observed: `1424`
  - required maturity: `15`
  - achieved maturity: `yes`
  **OBSERVED AT RUNTIME** (`gettxout` evidence)

- Masternode collateral setup was not completed:
  - required amount is `10000 CRW` from source
  - wallet balance after extended regtest PoW mining remained `3097.93750000`
  - regtest halving interval is 150 blocks, causing rapid subsidy decay
  **OBSERVED AT RUNTIME + CONFIRMED FROM SOURCE** (`getwalletinfo`; `src/chainparams.cpp:583`; `src/main.cpp:1716-1732`)

## Masternode setup

- `masternode start` path was attempted earlier during phase execution but collateral requirement was not met. **OBSERVED AT RUNTIME**
- In this phase run, no active masternode was reached due collateral economics on fresh regtest. **OBSERVED AT RUNTIME**
- Eligibility for MNPoS as masternode: **NOT ACHIEVED** in runtime.

## Systemnode setup

- Systemnode alias configuration and `systemnode start-alias sn1` succeeded in multiple runs. **OBSERVED AT RUNTIME**
- Local node reported `ENABLED` for `sn1` collateral vin. **OBSERVED AT RUNTIME**
- Direct `systemnode start` path is sensitive to inbound-connect check (`ConnectNode`) and routable address constraints. **CONFIRMED FROM SOURCE + OBSERVED AT RUNTIME** (`src/activesystemnode.cpp:92-97`, `src/systemnode.cpp:212-218`)

## Node-list agreement

- Node-list agreement was inconsistent across repeated restarts:
  - some runs: all peers reported SN count/status consistently
  - later runs: `sn1` retained local `ENABLED`, while other peers reported empty systemnode lists
- This indicates propagation/sync-state sensitivity in this isolated setup. **OBSERVED AT RUNTIME**

## MNPoS block production

- Actual MNPoS (PoS) blocks were **not produced**.
- Reason: PoS activation height not reached (`141000`), and practical progression to full MN/SN producer set on fresh regtest was constrained by collateral economics and list/payment behavior in this run. **CONFIRMED FROM SOURCE + OBSERVED AT RUNTIME**

## Stake pointers

- Runtime stake pointer objects from actual PoS blocks: **NOT OBSERVED** (no PoS blocks produced).
- Source-verified lifecycle/rules documented above (valid chain membership, depth constraints, anti-reuse, reward-slot dependency, signover support). **CONFIRMED FROM SOURCE**

## Producer selection

- Source shows score-based ranking/selection for MN and SN managers. **CONFIRMED FROM SOURCE** (`src/masternodeman.cpp:401-423`, `src/systemnodeman.cpp:511-533`)
- Runtime producer rotation/selection across PoS blocks: **NOT TESTED** (no PoS blocks).

## Block signatures

- Signature validation path for PoS blocks is source-confirmed (`CheckBlockSignature`, collateral/signover handling).
- Runtime verification against produced MNPoS blocks: **NOT TESTED** (no PoS blocks).

## Reward outputs

- Source confirms payment slot rules and payout construction paths (`MN_PMT_SLOT`, `SN_PMT_SLOT`).
- Runtime PoS reward-output validation: **NOT TESTED** (no PoS blocks).
- Runtime PoW template behavior with/without detected node payees was observed.
- Earlier in this phase, one runtime path produced `CTransaction::GetValueOut() : value out of range` while creating new blocks after node-payment selection changes. Source inspection shows `systemnode` coinbase fill resizes to 3 outputs and only assigns slot 2 when it has a payee (`src/systemnode-payments.cpp:231-237`), while masternode slot 1 assignment is conditional (`src/masternode-payments.cpp:179-186`). This interaction is a candidate cause when slot initialization does not align with payment detection paths. **OBSERVED AT RUNTIME + INFERRED FROM SOURCE**.

## Failure/recovery

- Systemnode startup and broadcast behavior proved restart-sensitive in isolated regtest runs. **OBSERVED AT RUNTIME**
- Producer failure/rejoin for active MNPoS producers: **NOT TESTED** (no MNPoS production).

## Partition/reorganisation

- **NOT TESTED — CONSENSUS REQUIREMENT**
- Rationale: no established independent MNPoS production on both sides was available in this phase run.

## Spork dependency audit

Relevant sporks and impact:

- `SPORK_4_ENABLE_MASTERNODE_PAYMENTS` (`10003`) — toggles node payment behavior and has special fallback to chainparam start time.
- `SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT` (`10007`) — strict masternode payment enforcement toggle.
- `SPORK_13_ENABLE_SUPERBLOCKS` (`10012`) — superblock behavior.
- `SPORK_14_SYSTEMNODE_PAYMENT_ENFORCEMENT` (`10013`) — strict systemnode payment enforcement toggle.
- `SPORK_15_SYSTEMNODE_PAY_UPDATED_NODES` (`10014`) / `SPORK_16_DISCONNECT_OLD_NODES` (`10015`) — protocol-gating behavior.

Source locations: `src/spork.h:31-41`, `src/spork.h:47-58`, `src/spork.cpp:78-90`, `src/spork.cpp:110-123`.

Runtime `spork show` / `spork active` demonstrated payment feature active while strict enforcement sporks stayed inactive in this private run. **OBSERVED AT RUNTIME**

**Can a revived network operate without historical spork infrastructure?**

- **PARTIALLY**
- Rationale: defaults/fallbacks permit baseline behavior, but long-term governance of spork state still depends on valid spork authority operations.

## Governance / payment-state dependencies

- Consensus-critical stake-pointer/block-signature checks are local chain-data based and source-defined in validation paths. **CONFIRMED FROM SOURCE**
- Payment winner/governance flows are partially policy/spork/sync mediated and may degrade to permissive behavior while unsynced. **CONFIRMED FROM SOURCE + OBSERVED AT RUNTIME**
- Dependence on historical persisted winner/state files for strict behavior in fresh private runs appears **limited but operationally relevant**. **INFERRED**

## Regtest address issue impact

Carried forward and reproduced:

- `getnewaddress` generated `tCRW...` addresses
- `validateaddress` returned `isvalid:false`
- `sendtoaddress` rejected those addresses

**OBSERVED AT RUNTIME** and previously documented in Phase 1C.

Impact in this phase:

- Collateral creation via normal address flow: impacted
- MN/SN setup itself: workaround possible via raw transaction path and alias config
- MNPoS producer execution: not directly proven blocked by this issue in this run

Classification: **MAJOR**, currently **REGTEST-BOUND IN EVIDENCE**.

## Risks

See detailed risk register below.

## Runtime evidence table

| TEST | ACTION / COMMAND | NODE(S) | OBSERVED RESULT | EVIDENCE | STATUS |
|---|---|---|---|---|---|
| Baseline build | `./autogen.sh`, `./configure ...`, `make -C src -j4 crownd crown-cli crown-tx` | repo | Build completed; binaries produced | command logs + versions | GREEN |
| Private topology | start 4 `crownd`, `addnode ... onetry`, `getblockcount` | ctl/mn1/sn1/obs | all nodes connected and synchronized | equal heights/bestblockhash | GREEN |
| Systemnode collateral creation | wallet-signed raw tx path + confirmations | sn1/ctl | 500 CRW UTXO created and matured well past 15 confirms | txid `6f520b...974a`, `gettxout` confirms 1424 | GREEN |
| Regtest address limitation | `getnewaddress`, `validateaddress`, `sendtoaddress` | ctl | generated `tCRW...` invalid for validate/send | RPC error code -5 | GREEN |
| Systemnode activation | `systemnode start-alias sn1` | sn1 | alias start successful; local status `ENABLED` | RPC success + `systemnode list status` | GREEN |
| Node-list agreement | `systemnode count`, `systemnode list status` across peers | ctl/mn1/sn1/obs | inconsistent cross-peer visibility across restarts | sn1 shows 1; others sometimes 0 | AMBER |
| Masternode collateral feasibility | `getwalletinfo` + source collateral requirement | ctl + source | fresh-run wallet balance below 10000; no MN collateral formed | 3097.9375 balance vs 10000 requirement | RED |
| Fresh-chain bootstrap to MNPoS | source + runtime progression checks | all | PoW bootstrap exists; full MNPoS producer realization incomplete in run | PoS gate at 141000, no PoS blocks | AMBER |
| Actual MNPoS block production | observe PoS blocks and acceptance | all | not reached | no PoS block evidence | NOT TESTED |
| Stake pointer runtime validation | inspect produced PoS block pointers | all | no PoS blocks produced | n/a | NOT TESTED |
| Producer rotation | produce sufficient MNPoS blocks with >1 eligible producer | all | not reached | n/a | NOT TESTED |
| Producer failure/recovery | stop active producer and observe continuity/rejoin | all | not reached | n/a | NOT TESTED |
| Partition/reorg | controlled split and reconverge under MNPoS | subset/all | not validly executable without independent MNPoS production | n/a | NOT TESTED |

## Final status matrix

- Fresh-chain bootstrap: **AMBER**
- Collateral creation: **AMBER**
- Collateral maturity: **GREEN**
- Masternode registration: **RED**
- Systemnode registration: **GREEN**
- Node-list agreement: **AMBER**
- Masternode eligibility: **RED**
- Systemnode eligibility: **AMBER**
- MNPoS block production: **NOT TESTED**
- Block propagation: **GREEN**
- Stake-pointer validation: **NOT TESTED**
- Producer selection: **NOT TESTED**
- Producer rotation: **NOT TESTED**
- Block signatures: **NOT TESTED**
- Reward outputs: **NOT TESTED**
- Producer disappearance: **NOT TESTED**
- Chain continues after producer loss: **NOT TESTED**
- Producer rejoin: **NOT TESTED**
- Partition: **NOT TESTED**
- Competing MNPoS history: **NOT TESTED**
- Reorganisation: **NOT TESTED**
- Final convergence: **NOT TESTED**
- Spork independence: **AMBER**
- Governance independence: **AMBER**
- Address-issue impact understood: **GREEN**
- Reusable MNPoS tooling executed: **GREEN**

## Risk register

| ID | SYSTEM | RISK | SEVERITY | EVIDENCE | IMPACT | NEXT INVESTIGATION | CLASS |
|---|---|---|---|---|---|---|---|
| R1 | Bootstrap economics | Fresh regtest run cannot practically form 10k MN collateral before heavy subsidy decay | HIGH | `nSubsidyHalvingInterval=150` + runtime balance 3097.9375 at h=1724 | blocks MN producer setup and MN/SN mix testing | evaluate devnet/private param profile for MNPoS lab runs | ARCHITECTURAL RISK |
| R2 | Node-list propagation | Systemnode list visibility diverges across peers after restarts/broadcast sequences | MEDIUM | runtime `systemnode count/status` mismatch | inconsistent payment/eligibility observations | isolate sync/broadcast timing and fulfilled-request constraints | IMPLEMENTATION DEFECT |
| R3 | Spork operations | Historical spork authority absence can constrain operational control despite defaults | MEDIUM | spork code paths and defaults | weakens operational governance for revived network | define revival-era spork governance plan | OPERATIONAL RISK |
| R4 | Stake-pointer dependence | MNPoS requires prior reward-output pointers with depth/age/reuse constraints | MEDIUM | `CheckBlockProofPointer` and wallet pointer construction | can stall producer continuity if pointer flow is disrupted | run long-lived controlled PoS sequence once producer set is viable | LEGACY DESIGN LIMITATION |
| R5 | Regtest wallet address flow | `tCRW...` addresses fail validate/send normal flow | MEDIUM | runtime RPC failures; prior Phase 1C evidence | complicates collateral/payment setup tooling and operator UX | dedicated scoped fix task for regtest address prefix handling | IMPLEMENTATION DEFECT |
| R6 | Payment-state sensitivity | payment behavior depends on sync/spork state and can run permissively while unsynced | MEDIUM | payment validation guards in source | harder to reason about strict policy in fresh private nets | targeted tests across sync states with controlled winner data | ARCHITECTURAL RISK |
| R7 | Block template/payment assembly | runtime `GetValueOut` range error seen in block creation path under node-payment transitions | HIGH | runtime RPC error + payout-slot assembly paths in `masternode-payments.cpp`/`systemnode-payments.cpp` | can stall fresh-chain block generation in some node-state combinations | isolate minimal deterministic reproducer and validate coinbase output initialization paths | IMPLEMENTATION DEFECT |

## Safe reusable MNPoS test tooling

Added and executed:

- `contrib/devtools/revival/start-mnpos-regtest.sh`
- `contrib/devtools/revival/status-mnpos-regtest.sh`
- `contrib/devtools/revival/stop-mnpos-regtest.sh`

Properties:

- disposable datadir use (`/tmp/crown-phase1d` default)
- localhost RPC/P2P only
- no real keys or real CRW embedded
- repeatable start/status/stop flow

Execution evidence: scripts were run during this phase and produced expected node lifecycle/status output.

## Conclusions

### Final verdict

**MNPOS PRIVATE NETWORK BASELINE INCOMPLETE**

### Required explicit answers

- Fresh isolated MNPoS bootstrap possible: **PARTIALLY**
- Masternodes operational: **NO**
- Systemnodes operational: **PARTIALLY**
- Actual MNPoS blocks produced: **NO**
- Stake-pointer mechanism operational: **NOT TESTED**
- Producer rotation observed: **NOT TESTED**
- Producer-failure recovery works: **NOT TESTED**
- Historical spork infrastructure required: **PARTIALLY**
- Historical governance state required: **PARTIALLY**
- Regtest `tCRW` issue blocks MNPoS: **PARTIALLY**
- Safe to proceed to Phase 2 historical-chain/economic audit: **NO**

### Production source stop rule outcome

- Production Crown consensus source modified in this phase: **NO**
- Consensus behavior changed: **NO**
- Monetary behavior changed: **NO**
- Wallet format changed: **NO**
- Cryptographic behavior changed: **NO**
