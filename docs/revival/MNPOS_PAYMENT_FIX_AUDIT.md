# Crown Revival — Phase 1F: MNPoS Payment-Transition Fix Audit

## 1. Starting baseline

| Item | Value |
| --- | --- |
| Copilot task branch | `copilot/fix-payment-transition-failure` |
| Starting HEAD SHA | `027997dd2a5e820fbc298f247053d0bf04503c39` |
| Starting `master` SHA | `027997dd2a5e820fbc298f247053d0bf04503c39` |
| `git status` at start | `## copilot/fix-payment-transition-failure...origin/copilot/fix-payment-transition-failure` |
| Operating system | `Ubuntu 24.04.5 LTS` |
| Compiler | `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` |
| OpenSSL | `OpenSSL 3.0.13 30 Jan 2024` |
| Boost | `1.83.0.1ubuntu2` |
| `crownd --version` baseline build | `Crown Core Daemon version v0.14.0.7-027997d` |
| `crown-cli --version` baseline build | `Crown Core RPC client version v0.14.0.7-027997d` |

Confirmed pre-existing revival docs:

- `docs/revival/MNPOS_NETWORK_AUDIT.md`
- `docs/revival/MNPOS_BLOCKER_AUDIT.md`
- `docs/revival/CI_BUILD_PERFORMANCE.md`

Phase 1E deterministic payment reproduction was taken from `docs/revival/MNPOS_BLOCKER_AUDIT.md:178-244`.

## 2. Pre-fix deterministic reproduction

Baseline reproduction used the committed Phase 1E flow from `contrib/devtools/revival/repro-payment-transition.sh:9-72`:

1. start the disposable four-node regtest network
2. mine 700 blocks
3. create a 500 CRW systemnode collateral output
4. mine 20 more blocks to height `720`
5. wait until wall clock passes the collateral 15-confirmation block time
6. restart `sn1`
7. run `systemnode start-alias sn1`
8. confirm all four peers report one enabled systemnode
9. call `getblocktemplate '{}'`

Observed pre-fix runtime result:

- accepted/enabled Systemnode: **YES**, converged on `ctl`, `mn1`, `sn1`, `obs`
- height at failure: **721** template target height
- `sn1 getblocktemplate`: `error: {"code":-1,"message":"CTransaction::GetValueOut() : value out of range"}`
- `ctl getblocktemplate`: `error: {"code":-1,"message":"CTransaction::GetValueOut() : value out of range"}`

Direct pre-fix coinbase evidence from the failing `GetValueOut()` call:

| Output index | Value (duffs) | Value (CRW) | Associated payee |
| --- | ---: | ---: | --- |
| `0` | `67500000` | `0.67500000` | producer/miner remainder |
| `1` | `-1` | invalid | unintended default/null `CTxOut` |
| `2` | `7500000` | `0.07500000` | systemnode payee |

Additional pre-fix facts:

- `vout.size() == 3`
- no masternode payee was selected
- one systemnode payee was selected
- `GetValueOut()` threw at `src/primitives/transaction.cpp:120-129`

## 3. Root cause

Construction path:

1. `CreateNewBlock` initializes coinbase with one output at `src/miner.cpp:111-116`
2. `FillBlockPayee` dispatches to masternode or budget logic at `src/masternode-payments.cpp:133-143`
3. `CMasternodePayments::FillBlockPayee` leaves `txNew.vout` at size `1` when no masternode payee exists at `src/masternode-payments.cpp:159-180`
4. `SNFillBlockPayee` dispatches to systemnode logic at `src/systemnode-payments.cpp:183-192`
5. `CSystemnodePayments::FillBlockPayee` resizes to `3` and fills only slot `2` at `src/systemnode-payments.cpp:230-237`
6. `rpcmining` reports `coinbasevalue` by calling `pblock->vtx[0].GetValueOut()` at `src/rpcmining.cpp:635`
7. `CTransaction::GetValueOut()` rejects the negative sentinel from the default `CTxOut` at `src/primitives/transaction.cpp:120-129`

Why slot `1` stayed invalid:

- `CTxOut()` calls `SetNull()`, which sets `nValue = -1` at `src/primitives/transaction.h:135-155`
- when the masternode payee is absent, slot `1` is never populated
- when the systemnode payee is present, slot `2` is still required by existing output-position semantics (`src/systemnode-payments.h:27`, `src/systemnode-payments.cpp:233-235`, `src/systemnode-payments.cpp:310-315`)
- later code treats every serialized `vout` entry as a real transaction output and sums them in `GetValueOut()`

## 4. Intended payment/output semantics

Source-defined slot assignments:

- output `0`: producer reward, initialized in `CreateNewBlock` (`src/miner.cpp:111-116`)
- output `1`: masternode payee when present (`src/masternode-payments.h:28`, `src/masternode-payments.cpp:179-185`)
- output `2`: systemnode payee when present (`src/systemnode-payments.h:27`, `src/systemnode-payments.cpp:230-237`)
- governance/superblock outputs: appended by budget logic after output `0` only (`src/masternode-budget.cpp:449-476`)

Relevant cases:

| Case | Expected `vout` count | Expected order | Evidence |
| --- | ---: | --- | --- |
| A. MN payee present, SN payee present | `3` | producer, masternode, systemnode | `src/masternode-payments.cpp:179-185`, `src/systemnode-payments.cpp:230-237`, `src/systemnode-payments.cpp:310-315` |
| B. MN payee present, SN payee absent | `2` | producer, masternode | `src/masternode-payments.cpp:179-185`, `src/systemnode-payments.cpp:213-220` |
| C. MN payee absent, SN payee present | `3` | producer, empty masternode slot, systemnode | fixed-position systemnode validation at `src/systemnode-payments.cpp:310-315`, RPC field access at `src/rpcmining.cpp:662-668` |
| D. MN payee absent, SN payee absent | `1` | producer only | `src/masternode-payments.cpp:163-170`, `src/systemnode-payments.cpp:213-220` |

Governance / budget path:

- on superblocks, `budget.FillBlockPayee` uses output `0` plus appended proposal outputs (`src/masternode-budget.cpp:449-476`)
- `SNFillBlockPayee` intentionally skips systemnode payouts on those blocks (`src/systemnode-payments.cpp:188-191`)
- no additional placeholder output is needed on budget blocks because the systemnode payment path is not entered

Conclusion:

- omitted outputs are intentional when no later fixed-position payout depends on them
- a placeholder is intentional only for the systemnode-only case because slot `2` is consensus-checked and exported through RPC as the systemnode slot
- the placeholder must be non-negative to remain a valid transaction output

## 5. Candidate fixes considered

| Candidate | Classification | Assessment |
| --- | --- | --- |
| Initialize slot `1` to `CTxOut(0, CScript())` only when systemnode logic needs slot `2` and slot `1` is still null | **CONSENSUS-NEUTRAL** | Preserves existing slot numbering, payee amounts, and validation rules while fixing invalid transaction construction at the source |
| Compact outputs to `[producer, systemnode]` when no masternode payee exists | **CONSENSUS-CHANGING** | Conflicts with fixed systemnode position checks in `src/systemnode-payments.cpp:310-315` and RPC assumptions in `src/rpcmining.cpp:662-668` |
| Change `GetValueOut()` / `MoneyRange()` to tolerate negative placeholder outputs | **CONSENSUS-CHANGING** | Weakens transaction-value validation and was explicitly rejected |
| Pre-size every coinbase to all node-payment slots from `CreateNewBlock` | **CONSENSUS-SENSITIVE** | Broader serialized-coinbase change than required and alters all node-payment states, not just the failing transition |

## 6. Consensus / monetary impact assessment

- serialized coinbase structure changes only for the previously broken systemnode-only creation path
- output ordering is preserved
- output count is preserved relative to the intended fixed-slot layout
- block hash changes only for newly created blocks that previously could not be constructed successfully
- block validation rules are unchanged
- payment-validation rules are unchanged
- total reward is preserved
- masternode, systemnode, and budget formulas are unchanged

Historical compatibility:

- Historical blocks reinterpreted: **NO**
- Historical transaction validation changed: **NO**
- Historical wallet format changed: **NO**
- P2P serialization changed: **NO**

This is a block-creation-path fix, not a validation-path rule change.

## 7. Implemented fix

Production change:

- file: `src/systemnode-payments.cpp`
- function: `CSystemnodePayments::FillBlockPayee`
- change: after `txNew.vout.resize(3)`, if `txNew.vout[MN_PMT_SLOT]` is still null, replace it with `CTxOut(0, CScript())`

Why required:

- preserves the existing fixed output layout
- prevents the default `CTxOut(nValue = -1)` sentinel from entering the coinbase
- leaves an absent masternode payee visibly empty (`scriptPubKey == CScript()`) while remaining transaction-valid

## 8. Regression tests

Added `src/test/mnpos_payment_tests.cpp` and wired it through `src/Makefile.test.include`.

Covered cases:

1. masternode payee + systemnode payee
2. masternode payee only
3. systemnode payee only
4. neither payee

Assertions per case:

- no negative output values
- `GetValueOut()` succeeds
- total output value matches `GetBlockValue(...)`
- `vout` count matches expected layout
- output ordering remains `[producer, masternode, systemnode]` where applicable
- payee script/value matches the selected payee

The exact Phase 1E failure became the `coinbase_outputs_with_systemnode_payee_only` regression and would fail against pre-fix code because slot `1` would remain `nValue = -1`.

## 9. Reward accounting comparison

For `blockValue = GetBlockValue(height, fees)`, `mn = GetMasternodePayment(height+1, blockValue)`, `sn = GetSystemnodePayment(height+1, blockValue)`:

| Case | Producer | Masternode | Systemnode | Governance | Actual total | Expected total | Difference |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A. MN + SN | `blockValue - mn - sn` | `mn` | `sn` | `0` | `blockValue` | `blockValue` | `0` |
| B. MN only | `blockValue - mn` | `mn` | `0` | `0` | `blockValue` | `blockValue` | `0` |
| C. SN only | `blockValue - sn` | `0` placeholder | `sn` | `0` | `blockValue` | `blockValue` | `0` |
| D. Neither | `blockValue` | `0` | `0` | `0` | `blockValue` | `blockValue` | `0` |

Post-fix runtime confirmation for the reproduced systemnode-only case at height `721`:

- producer payment: `0.67500000`
- masternode payment: `0.00000000`
- systemnode payment: `0.07500000`
- total: `0.75000000`
- difference: `0`

## 10. Post-fix deterministic reproduction

Reused the same Phase 1E sequence through height `720`, waited past the collateral 15-confirmation wall-clock time, then ran `systemnode start-alias sn1` and `getblocktemplate '{}'`.

Observed post-fix results:

- accepted/enabled Systemnode: **YES**, converged on `ctl`, `mn1`, `sn1`, `obs`
- `sn1 getblocktemplate`: **success**
- `ctl getblocktemplate`: **success**
- `payee`: empty
- `payeeSN`: `tCRWFE3BTAbCyHNT1F5FJGPqS6uHSWc47vfaj`
- `payeeSN_amount`: `7500000`

Produced post-fix block coinbase:

| Output index | Value | Associated payee |
| --- | --- | --- |
| `0` | `0.67500000` | producer |
| `1` | `0.00000000` | empty masternode placeholder |
| `2` | `0.07500000` | systemnode |

`GetValueOut()` succeeded implicitly because both `getblocktemplate` and subsequent block creation completed.

## 11. MNPoS runtime result

After the successful `getblocktemplate`, one more block was mined from the same state:

- block height: `721`
- block hash: `2b6b334c7aebaa15a2fbad0c169db744d0a2ab42e2d85e85e322f30b62ce85d0`
- producer: `ctl`
- masternode payee: none
- systemnode payee: `tCRWFE3BTAbCyHNT1F5FJGPqS6uHSWc47vfaj`
- peer acceptance: all four nodes advanced to the same tip hash
- chain-tip agreement: **YES**

This establishes that block production now proceeds past the previous payment-transition blocker.

## 12. Relevant verification

Local build / test:

- `./autogen.sh`
- `./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui`
- `make -C src -j$(nproc) crownd crown-cli crown_test crown-tx`
- `./src/test/test_crown --run_test=mnpos_payment_tests/* --log_level=test_suite`
- `./src/test/test_crown --run_test=TestBudgetDraft/* --log_level=test_suite`
- `./src/test/test_crown --run_test=staking_tests/* --log_level=test_suite`
- `./src/test/test_crown --run_test=transaction_tests/* --log_level=test_suite`
- `./src/test/test_crown --run_test=serialize_tests/* --log_level=test_suite`

All executed suites completed without errors.

CI matrix:

- existing five-platform workflow retained unchanged in `.github/workflows/main.yml`
- workflow `Crown Platform Binaries` was dispatched on branch `copilot/fix-payment-transition-failure`

## 13. Remaining blockers

- registration divergence in `CSystemnodeBroadcast::CheckInputsAndAdd` remains **out of scope** and **unfixed** in this task
- regtest `tCRW...` address issue remains **out of scope**
- if future MNPoS work hits another independent bootstrap issue, it should be handled in a separate task after this payment fix

## 14. Recommended next task

Next task: targeted fix for the known registration divergence documented in `docs/revival/MNPOS_BLOCKER_AUDIT.md`, without mixing it with this resolved payment-transition defect.

## 15. Production change review

| File | Function | Change | Why required | Consensus impact | Monetary impact | Wire impact | Wallet impact | Crypto impact |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `src/systemnode-payments.cpp` | `CSystemnodePayments::FillBlockPayee` | replace null slot `1` with `CTxOut(0, CScript())` before filling slot `2` | prevent invalid negative default output while preserving fixed slot layout | creation-path only; validation rules unchanged | none; total reward preserved | none | none | none |

## Final verdict

| Question | Verdict |
| --- | --- |
| PAYMENT-TRANSITION DEFECT FIXED | **YES** |
| EXACT PHASE 1E REPRO NOW PASSES | **YES** |
| NEGATIVE COINBASE OUTPUT REMOVED | **YES** |
| `GetValueOut()` SUCCEEDS | **YES** |
| TOTAL REWARD PRESERVED | **YES** |
| MASTERNODE PAYMENT BEHAVIOUR PRESERVED | **YES** |
| SYSTEMNODE PAYMENT BEHAVIOUR PRESERVED | **YES** |
| GOVERNANCE PAYMENT BEHAVIOUR PRESERVED | **YES** |
| HISTORICAL BLOCK VALIDATION CHANGED | **NO** |
| CONSENSUS BEHAVIOUR CHANGED | **NO** |
| MONETARY BEHAVIOUR CHANGED | **NO** |
| MNPoS BLOCK PRODUCTION NOW PROCEEDS PAST THIS BLOCKER | **YES** |
| NEXT KNOWN BLOCKER | registration divergence in `CSystemnodeBroadcast::CheckInputsAndAdd` |
