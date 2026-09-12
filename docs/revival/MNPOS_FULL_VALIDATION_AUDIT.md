# Crown Revival — Phase 1H: Full MNPoS Private-Network Validation Audit

## 1. Starting baseline

| Item | Value |
| --- | --- |
| Task branch | `copilot/phase-1h-validation-audit` |
| HEAD SHA | `d8fa3990ccb387bb5d66e895ed69dc6a2e3e218c` |
| Starting `master` SHA | `d8fa3990ccb387bb5d66e895ed69dc6a2e3e218c` (`git ls-remote --heads origin master`) |
| Git status at start | `## copilot/phase-1h-validation-audit...origin/copilot/phase-1h-validation-audit` |
| OS | `Ubuntu 24.04.5 LTS`, Linux `6.17.0-1022-azure` x86_64 |
| Compiler | `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` |
| Boost | `1.83.0.1ubuntu2` |
| OpenSSL | `OpenSSL 3.0.13 30 Jan 2024` |
| `crownd --version` | `Crown Core Daemon version v0.14.0.7-d8fa399` |
| `crown-cli --version` | `Crown Core RPC client version v0.14.0.7-d8fa399` |

Required prior audits were reviewed before execution:

- `docs/revival/MULTINODE_NETWORK_AUDIT.md`
- `docs/revival/MNPOS_NETWORK_AUDIT.md`
- `docs/revival/MNPOS_BLOCKER_AUDIT.md` (Phase 1E blocker/root-cause audit)
- `docs/revival/MNPOS_PAYMENT_FIX_AUDIT.md`
- `docs/revival/HISTORICAL_PR1_AUDIT.md`
- `docs/revival/HISTORICAL_PR1_REMEDIATION.md`
- `docs/revival/MNPOS_REGISTRATION_FIX_AUDIT.md`

Current `master` contains the required predecessors:

- Phase 1F payment fix present (`src/systemnode-payments.cpp:230-237`, `src/test/mnpos_payment_tests.cpp:63-134`)
- PR #10 identity-aware duplicate-IP behavior present (`src/masternodeman.cpp:252-260`, `src/systemnodeman.cpp:479-487`, `src/systemnode.cpp:593-598`)
- Phase 1G origin/peer local-validation path fix present (`src/rpcsystemnode.cpp:230-346`, `src/qt/systemnodelist.cpp:125-164`)

## 2. Pre-network guard regressions

Executed and passing:

- `./src/test/test_crown --run_test=pr1_remediation_tests --log_level=test_suite`
- `./src/test/test_crown --run_test=mnpos_payment_tests --log_level=test_suite`
- `./qa/rpc-tests/systemnode_registration_divergence.sh --srcdir /home/runner/work/crown-core/crown-core/src`

Also executed and passing for nearby risk coverage:

- `staking_tests`, `transaction_tests`, `serialize_tests`, `rpc_tests`
- `CalculateScore`, `TestBudgetDraft`, `BudgetProposals`, `BudgetVoting`, `SuperblockPayment`

Build verification executed:

- `crownd`, `crown-cli`, `crown_test`, `crown-tx`

## 3. Fresh private-network topology and chain context

Execution model: native localhost-only disposable regtest network under `/tmp/crown-phase1h-runtime`.

Repeatable tooling added: `contrib/devtools/revival/phase1h-full-validation.sh` (requires `SYSTEMNODE_SERVICE_ADDR` to be set explicitly for the generated `systemnode.conf` service-address field).

| Node | Role | RPC | P2P | Bind scope |
| --- | --- | ---: | ---: | --- |
| `ctl` | controller/funding/miner | 18401 | 24001 | `127.0.0.1` |
| `mn1` | masternode participant peer | 18402 | 24002 | `127.0.0.1` |
| `sn1` | systemnode participant | 18403 | 24003 | `127.0.0.1` |
| `obs` | independent observer | 18404 | 24004 | `127.0.0.1` |

Registration metadata note: `systemnode.conf` used a routable service address string for broadcast validation compatibility, while all actual peer transport remained loopback-only.

Initial chain/network identity on all four nodes:

- chain: `regtest`
- genesis/best hash at height 0: `231de73ec08234a4adff3c71e57271a13fa73f5ae1ca6b0ded89275e557a6207`
- protocol version: `70062`
- subversion: `/Crown Core:0.14.0.7/`

Relevant chainparams confirmed from source:

- masternode collateral: `10000` (`src/wallet.h:54`)
- systemnode collateral: `500` (`src/wallet.h:55`)
- minimum confirmations for MN/SN collateral: `15` (`src/masternode.h:17`, `src/systemnode.h:16`)
- regtest halving interval: `150` (`src/chainparams.cpp:583`)
- regtest inherits testnet PoS start (does not override): testnet `nBlockPoSStart=141000` (`src/chainparams.cpp:367`, `src/chainparams.cpp:574-609`)

## 4. Normal chain operation before service-node activation

Validated on the fresh network:

- all nodes started and accepted RPC
- peer connections formed and remained active
- block propagation converged across nodes
- ordinary transaction propagation worked (raw transaction path due to regtest address limitation)
- restart/resync behavior worked for service and observer roles

Transaction propagation evidence (second probe):

- txid: `ee050d0b15f317523ed3761900d1ed5c2445b1fd3b0e29fca495420f225feb69`
- observed in mempool on `ctl`, `mn1`, `sn1`, `obs` before confirmation
- removed from mempools after confirmation block at shared height `746`

## 5. Collateral creation and maturity

### Systemnode collateral

| Field | Value |
| --- | --- |
| Collateral amount | `500.00000000 CRW` |
| txid | `6c7f74666c81ba9aa4add767c3a4bb0c0c15050bd35a43f93685f6df79f99f29` |
| vout | `0` |
| Collateral block height | `701` |
| Required confirmations | `15` |
| Eligibility height | `715` |
| Collateral block time | `1789206136` |
| 15-conf block time | `1789206138` |

### Masternode collateral

Attempted under unchanged Crown regtest rules.

Observed mature spendable total at runtime: `2395.72 CRW` (far below `10000 CRW` required).

Deterministic source-based cap on this regtest emission profile:

- halving interval `150`, subsidy right-shifted each interval (`src/main.cpp:1716-1732`, `src/chainparams.cpp:583`)
- last positive subsidy height is `4649`; first zero-subsidy height is `4650` (integer right-shift behavior in `GetSubsidy`)
- maximum theoretical cumulative subsidy upper bound before zeroing: `3599.99998500 CRW`

Result: **masternode collateral cannot be reached on this regtest configuration without changing production economics/params**.

## 6. Systemnode registration and Phase 1G regression

Invalid/too-early cases:

- at 14 confirmations: rejected with `Input must have at least 15 confirmations`
- immediate post-maturity (wall clock < 15-conf block time): rejected with `Systemnode broadcast rejected by local validation`
- both invalid cases left all nodes at `systemnode count = 0` (no origin/peer divergence)

Valid case:

- after maturity-time gating, bounded retries of `systemnode start-alias sn1` reached a successful registration
- all four nodes converged to `systemnode count = 1`
- all four nodes agreed on status map: `{6c7f...9f29-0: ENABLED}`

This preserves the Phase 1G fix behavior.

## 7. PR #10 duplicate-IP semantics regression

Runtime checks on this private network:

- same addr + same vin (`sn1` reannounce): accepted (`result: successful`)
- same addr + different vin (`sn2`, distinct collateral): rejected with `IP address is already in use by another systemnode.`

This matches identity-aware duplicate-IP semantics.

## 8. MNPoS activation requirements and boundary

Source-traced requirements:

- PoW is rejected at/after PoS start and PoS is rejected before it (`src/main.cpp:2374-2385`)
- stake blocks require valid stake pointer + signature validation (`src/main.cpp:2250-2358`, `src/mn-pos/stakevalidation.cpp:11-23`)
- payment checks are enforced via masternode and systemnode payee validators (`src/main.cpp:3442-3450`)
- payment/spork dependencies include `SPORK_4`, `SPORK_8`, `SPORK_13`, `SPORK_14` (`src/spork.h:31-41`, `src/spork.cpp:78-97`)

Runtime spork state on the test network:

- `SPORK_4_ENABLE_MASTERNODE_PAYMENTS`: active
- `SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT`: inactive
- `SPORK_13_ENABLE_SUPERBLOCKS`: inactive
- `SPORK_14_SYSTEMNODE_PAYMENT_ENFORCEMENT`: inactive

Activation boundary status in this run:

- final pre-MNPoS height reached: `746`
- configured activation height on this chain: `141000`
- first MNPoS-relevant height: `141000`
- boundary interpretation: `140999` is the last permissible PoW height; `141000` is the first PoS-required height
- activation crossed: **NO**

## 9. Repeated block/payment observations (pre-activation)

Because activation was not reached, no post-activation MNPoS (PoS) blocks were produced.  
However, repeated node-payment construction remained stable over 20 consecutive pre-activation blocks with one enabled systemnode and no masternode.

| HEIGHT | HASH | PRODUCER | MN PAYEE | SN PAYEE | GOV PAYEE | TOTAL VALUE | ACCEPTED BY ALL |
| ---: | --- | --- | --- | --- | --- | ---: | --- |
| 727 | `37aa4d1e767d2cbee83154e52cdef184cc9f25877f37666968d52b76fb89cb06` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 728 | `3187a21b6b2f02de134ed00d37fe36fec59683c074e7988f06f0b22882b04680` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 729 | `3988b9b9235dd20b227664ee42a3c01938a6c51390be8d21322ca43803af27cc` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 730 | `4aff6a7d2086e5d6353402d50815fe2b069cfc22ffdca9e94f027c0b8f02acf5` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 731 | `49c53fa5de6b6a60f754d5c45a644b10d31addab09cdd5c5ebeb8e287efe501d` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 732 | `19e319dc7e25d71e7bdaf371acecc2b5dd43408bea0d12d3d22f0bd09487b425` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 733 | `59444582b9befcb1c480c9eff40b90b9fc05b7c20604dc56da9353d4ec87a399` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 734 | `5e064bcbdfa1aa4666bde8bfa15256d67aa6676d65c456d4211750a4beb41c5b` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 735 | `60f988be9916e9dc7950e42f1cdd9ef1a504bfd050865388ec94ef6bc071e7d2` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 736 | `1cf86e3d8463a715c83e17ef854bc77e79e090c130b8978cea25a3cb6ac81c2f` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 737 | `1c168aa4912e4e6b3d08c428e5410fa3baab37d4b2250287c563e96e429dd18e` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 738 | `08a8dd3f39b69efb2b601a3c955a067f8d2080d6026f7b23a175a6aa916d3aea` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 739 | `053091a54297a9d0300da0638db16247b186eb8e16eadc63a8215ca5b2e0159f` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 740 | `3ee1095056e820913ba58d3e4672d98224e25ac556db7a5b79c34e0d4e66e21e` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 741 | `0a70a7743894de2c8a789ee6e8d7b0839b067ea76c1c752914c399b6ad3bc90f` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 742 | `3842ac41a560c949f255d9e0a0ce31d6d2b56577b2af101df35fe5a89ff275b5` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 743 | `67b4457ed5636936dc637b05c67af474a2d9da7769dd45a3382e5c8701d87f62` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 744 | `0abc00f37c26d53ce38d34ef4714bca483fa4c4d76df7907d28896b8d723002a` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 745 | `3a101c52a9466efa0bc2692c88f3483b080186effaf7b6d8656447ed2e473b01` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.75000000 | YES |
| 746 | `0813c60058554cc3eae899c0ad9a55202cc8631b499df35f8186bc4930b50ea2` | `ctl` (PoW) | — | `tCRWGicxoVtU5vRPxREsK9GkR9baSXbqyEabL` | — | 0.76000000 | YES |

## 10. Payment-combination and Phase 1F regression status

In this runtime topology (0 MN, 1 SN), only **Systemnode-only** case was reachable.

- systemnode-only outputs observed repeatedly as `[producer, 0.0 placeholder, SN payee]`
- no negative outputs observed in sampled range
- no `nValue = -1` observed
- totals remained internally consistent per block (including fee-bearing block 746)

Combination coverage in this runtime:

- A. MN + SN payee: **NOT REACHED** (no MN collateral possible on this regtest profile)
- B. MN payee only: **NOT REACHED**
- C. SN payee only: **PASS**
- D. neither payee where legitimate: **NOT EXERCISED IN THIS RUN**

Phase 1F production fix remains preserved by:

- passing `mnpos_payment_tests`
- runtime non-negative slot-1 placeholder behavior

## 11. Block creation vs validation checks

Creation-path references:

- payee construction in `CreateNewBlock` (`src/miner.cpp:371-418`)
- PoS block signing in creation path (`src/miner.cpp:441-447`)

Validation-path references:

- PoW/PoS boundary enforcement (`src/main.cpp:2374-2385`)
- stake-pointer and signature validation (`src/main.cpp:2250-2358`)
- masternode/systemnode payee validation during `CheckBlock` (`src/main.cpp:3442-3450`)

Runtime acceptance was independently checked by requiring matching tip/hash across all four peers after each mined transition segment.

## 12. Service-node convergence, restart, loss/rejoin, partition/reconnect

- **Convergence after valid registration:** all nodes agreed on one enabled `sn1` entry
- **Restart persistence (sn1 + obs):** chain and systemnode state reloaded; network converged at same tip
- **Service-node loss/rejoin:** with `sn1` stopped, remaining nodes advanced chain; after restart, `sn1` converged back to shared tip/state
- **Observer partition/reconnect:** observer temporarily lagged (`743` vs `745`) then reconciled to shared tip `746`

Final consensus check:

- `ctl`: height `746`, hash `0813c60058554cc3eae899c0ad9a55202cc8631b499df35f8186bc4930b50ea2`
- `mn1`: height `746`, hash `0813c60058554cc3eae899c0ad9a55202cc8631b499df35f8186bc4930b50ea2`
- `sn1`: height `746`, hash `0813c60058554cc3eae899c0ad9a55202cc8631b499df35f8186bc4930b50ea2`
- `obs`: height `746`, hash `0813c60058554cc3eae899c0ad9a55202cc8631b499df35f8186bc4930b50ea2`

## 13. Wallet interaction scope and known regtest address issue

Observed again:

- `getnewaddress` produced `tCRW...`
- `validateaddress` returned `{"isvalid":false}`

Wallet usage in this phase was limited to collateral/signing/payment operations needed for MNPoS validation, using the existing raw-transaction workaround when required.

## 14. New independent blocker identified in Phase 1H

Classification: **deterministic environment-level blocker for full regtest MN+SN MNPoS validation**

Deterministic facts:

1. Masternode collateral required by source is `10000 CRW`.
2. Regtest subsidy-halving profile (`interval=150`) hard-caps total mintable subsidy at `~3600 CRW` (upper bound) before right-shift zeroing.
3. Therefore, fresh regtest cannot fund a masternode collateral under unchanged production rules.
4. Without a masternode, full MN+SN payout-combination coverage and full intended end-to-end MNPoS validation target cannot be completed in this environment.

This was documented; no production monetary/collateral rule changes were made.

## 15. Reward accounting summary (sampled range 727–746)

- total generated reward: `15.01000000 CRW`
- producer rewards: `13.50900000 CRW`
- masternode rewards: `0.00000000 CRW`
- systemnode rewards: `1.50100000 CRW`
- governance/treasury rewards: `0.00000000 CRW` (not active in sampled range)
- fees observed: `0.01000000 CRW` (reflected in block 746)

Accounting verdict:

- TOTAL REWARD CONSERVED: **YES**
- UNEXPECTED INFLATION: **NO**
- UNEXPECTED REWARD LOSS: **NO**
- NEGATIVE OUTPUT: **NO**
- INVALID NULL OUTPUT: **NO**

## 16. Component verdict table

| Component | Verdict | Evidence |
| --- | --- | --- |
| P2P | PASS | startup/connectivity, block/tx propagation, tip convergence |
| MASTERNODE REGISTRATION | NOT TESTED | deterministic inability to fund 10000 CRW collateral on this regtest profile |
| SYSTEMNODE REGISTRATION | PASS | invalid-too-early rejection consistency + eventual converged success |
| MNPOS ACTIVATION | NOT TESTED | activation height `141000` not reached (run ended at `746`, blocked by phase scope/runtime limits) |
| BLOCK PRODUCTION | PARTIAL | stable repeated pre-activation blocks; post-activation PoS not exercised |
| BLOCK VALIDATION | PARTIAL | peer acceptance verified pre-activation; post-activation PoS validation not exercised |
| MN PAYMENTS | NOT TESTED | no funded masternode |
| SN PAYMENTS | PASS | repeated SN-only payouts, non-negative outputs |
| REWARD ACCOUNTING | PASS | sampled totals conserved; no invalid/negative outputs |
| NODE RESTART | PASS | state and tip convergence after restart |
| NODE REJOIN | PASS | stopped service node rejoined and converged |
| CHAIN CONVERGENCE | PASS | final shared tip/hash on all healthy connected nodes |

## 17. Five-platform CI policy

No workflow matrix weakening was introduced in this phase.  
No platform was removed or skipped in repository configuration.

## 18. Remaining defects and mainnet relevance

Outstanding from this and prior phases:

- regtest `tCRW` address-validation/send limitation remains
- full MN+SN MNPoS validation remains blocked on regtest by the collateral economics mismatch above

Mainnet relevance:

- the collateral-economics blocker identified here is specific to this regtest profile and does not by itself imply mainnet collateral infeasibility
- however, it blocks complete private-network MNPoS validation on the canonical revival regtest setup

## 19. Final verdict

FRESH PRIVATE NETWORK CREATED: **YES**

MASTERNODE REGISTRATION CONSISTENT: **PARTIAL** (blocked: masternode collateral unreachable on this regtest profile)

SYSTEMNODE REGISTRATION CONSISTENT: **YES**

PR #10 DUPLICATE-IP SEMANTICS PRESERVED: **YES**

PHASE 1G REGISTRATION FIX PRESERVED: **YES**

PHASE 1F PAYMENT FIX PRESERVED: **YES**

MNPOS ACTIVATION REACHED: **NO**

MULTIPLE MNPOS BLOCKS PRODUCED: **NO**

NUMBER OF POST-ACTIVATION BLOCKS TESTED: **0**
