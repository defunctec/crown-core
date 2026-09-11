# Crown Revival — Phase 1E: Deterministic MNPoS Blocker Audit

## 1. Starting baseline

| Item | Value |
| --- | --- |
| Copilot task branch | `copilot/crown-revival-phase-1e-investigation` |
| Current HEAD before Phase 1E work | `1fabf53b62917ceb5dfa55080c5c2285d711db0e` |
| Starting `master` SHA | `1fabf53b62917ceb5dfa55080c5c2285d711db0e` |
| `git status` before Phase 1E edits | `## copilot/crown-revival-phase-1e-investigation...origin/copilot/crown-revival-phase-1e-investigation` |
| Operating system | `Ubuntu 24.04.5 LTS (Noble Numbat)` |
| Compiler | `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` |
| OpenSSL | `OpenSSL 3.0.13 30 Jan 2024` |
| Boost | `1.83.0.1ubuntu2` |
| `crownd --version` | `Crown Core Daemon version v0.14.0.7-1fabf53` |
| `crown-cli --version` | `Crown Core RPC client version v0.14.0.7-1fabf53` |
| Build commands executed | `./autogen.sh`; `./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui`; `make -C src -j$(nproc) crownd crown-cli crown-tx` |

Confirmed merged audit docs present before investigation:

- `docs/revival/MULTINODE_NETWORK_AUDIT.md`
- `docs/revival/MNPOS_NETWORK_AUDIT.md`
- `docs/revival/CI_BUILD_PERFORMANCE.md`

## 2. Phase 1D evidence carried forward

Phase 1D explicitly identified two blockers:

- registration/visibility instability: local `ENABLED` state on `sn1` while other peers reported empty systemnode lists in some runs (`docs/revival/MNPOS_NETWORK_AUDIT.md:127-130`, `docs/revival/MNPOS_NETWORK_AUDIT.md:281`)
- node-payment transition error: `CTransaction::GetValueOut() : value out of range` during block/template creation after node-payment state changes (`docs/revival/MNPOS_NETWORK_AUDIT.md:152-157`, `docs/revival/MNPOS_NETWORK_AUDIT.md:282`)

Relevant Phase 1D runtime topology and state:

- nodes: `ctl`, `mn1`, `sn1`, `obs` on loopback-only disposable datadirs (`docs/revival/MNPOS_NETWORK_AUDIT.md:84-93`)
- systemnode collateral matured far beyond the required 15 confirmations (`docs/revival/MNPOS_NETWORK_AUDIT.md:95-105`)
- local `systemnode start-alias sn1` succeeded, but cross-peer visibility was inconsistent (`docs/revival/MNPOS_NETWORK_AUDIT.md:119-130`)
- the recommended next task was deterministic reproduction of both blockers before further MNPoS bootstrap work (`docs/revival/MNPOS_NETWORK_AUDIT.md:354-367`)

## 3. Test environment

Execution model: **NATIVE**

Private topology reused from Phase 1D tooling:

| Node | Datadir | RPC | P2P |
| --- | --- | --- | --- |
| `ctl` | `/tmp/.../ctl` | `18401` | `24001` |
| `mn1` | `/tmp/.../mn1` | `18402` | `24002` |
| `sn1` | `/tmp/.../sn1` | `18403` | `24003` |
| `obs` | `/tmp/.../obs` | `18404` | `24004` |

Reused tooling:

- `contrib/devtools/revival/start-mnpos-regtest.sh`
- `contrib/devtools/revival/status-mnpos-regtest.sh`
- `contrib/devtools/revival/stop-mnpos-regtest.sh`

Controlled diagnostic variation:

- actual RPC/P2P sockets remained loopback-only
- the committed repro scripts use a syntactically routable advertised systemnode service address `8.8.8.8:24003` only because `systemnode.conf` parsing rejects loopback/private addresses (`src/nodeconfig.cpp:59-80`) and systemnode broadcast validation rejects non-routable IPv4 addresses (`src/systemnode.cpp:212-219`, `src/systemnodeman.cpp:229-234`)
- no external peers were contacted; the routable address is metadata for broadcast validation, not a connected peer in the test topology

Collateral setup used a wallet-signed raw-transaction path because regtest wallet-generated `tCRW...` addresses still fail local `validateaddress` and `sendtoaddress` (`src/base58.cpp:171-201`, `src/base58.cpp:263-273`, `src/chainparams.cpp:417-425`, `src/rpcwallet.cpp:140-148`, `src/rpcmisc.cpp:311-333`)

## 4. Registration divergence reproduction

### Deterministic immediate-start reproduction

Executed flow:

1. start the four-node private network
2. mine 700 blocks on `ctl`
3. create a 500 CRW systemnode collateral output to an `sn1` wallet key hash using a wallet-signed raw transaction
4. mine 20 more blocks, reaching height `720`
5. write `sn1/regtest/systemnode.conf`
6. restart `sn1`
7. run `systemnode start-alias sn1` immediately

Observed post-registration state:

| Node | Expected state | Observed state | First divergent event | Rejection / state reason | Evidence |
| --- | --- | --- | --- | --- | --- |
| `sn1` | sees its own systemnode | `count=1`, local status `ENABLED` | local `start-alias` inserts directly into local list | no local full `CheckInputsAndAdd` replay | `src/rpcsystemnode.cpp:225-230`; `/tmp/crown-phase1e-run5/sn1/regtest/debug.log:11725-11727` |
| `ctl` | should agree on `count=1` | `count=0`, empty list | remote `CheckInputsAndAdd` | `sigTime` older than 15-confirmation block time | `/tmp/crown-phase1e-run5/ctl/regtest/debug.log:18919-18924`; `src/systemnode.cpp:632-644` |
| `mn1` | should agree on `count=1` | `count=0`, empty list | remote validation path never adds node | same rejection condition as `ctl` path | runtime `systemnode count/list status` from run5 |
| `obs` | should agree on `count=1` | `count=0`, empty list | remote validation path never adds node | same rejection condition as `ctl` path | runtime `systemnode count/list status` from run5 |

Run 5 runtime summary:

```text
=== ctl ===
0
{}
=== mn1 ===
0
{}
=== sn1 ===
1
{"f2ab...42dc-0":"ENABLED"}
=== obs ===
0
{}
```

Earliest divergent event captured on `ctl`:

```text
2026-09-11 18:50:42 ... Systemnode broadcast ... new
2026-09-11 18:50:42 snb - Accepted systemnode entry
2026-09-11 18:50:42 snb - Bad sigTime 1789152641 ... (15 conf block is at 1789152754)
2026-09-11 18:50:42 CSystemnodeMan::CheckSnbAndUpdateSystemnodeList - Rejected Systemnode entry 8.8.8.8:24003
```

### Classification

**REGISTRATION DIVERGENCE REPRO: DETERMINISTIC**

Within the controlled immediate-start scenario, the result reproduced consistently: `sn1` kept a local `ENABLED` entry while peers remained at zero.

## 5. Registration divergence source trace

Actual source path:

1. RPC entry: `systemnode start-alias` (`src/rpcsystemnode.cpp:192-243`)
2. broadcast creation: `CSystemnodeBroadcast::Create(...)` (`src/systemnode.cpp:727-823`)
3. local insertion on origin node: `snodeman.UpdateSystemnodeList(snb); snb.Relay();` (`src/rpcsystemnode.cpp:227-230`)
4. peer message handling: `CSystemnodeMan::ProcessMessage("snb")` (`src/systemnodeman.cpp:96-118`)
5. peer validation: `CheckSnbAndUpdateSystemnodeList` (`src/systemnodeman.cpp:217-264`)
6. signature/update checks: `CSystemnodeBroadcast::CheckAndUpdate` (`src/systemnode.cpp:421-570`)
7. collateral and maturity checks: `CSystemnodeBroadcast::CheckInputsAndAdd` (`src/systemnode.cpp:572-672`)
8. list insertion on accepting peers: `snodeman.Add(sn)` / `UpdateSystemnodeList` (`src/systemnode.cpp:648-650`, `src/systemnodeman.cpp:400-415`)

Important local state consulted during validation:

- local active chain height and collateral maturity via `GetInputAge(vin)` (`src/systemnode.cpp:624-629`)
- local transaction-to-block lookup via `GetTransaction(vin.prevout.hash, tx2, hashBlock, true)` (`src/systemnode.cpp:634-636`)
- local active-chain 15-confirmation block timestamp via `chainActive[pMNIndex->nHeight + SYSTEMNODE_MIN_CONFIRMATIONS - 1]` (`src/systemnode.cpp:639-644`)
- local seen-broadcast cache via `mapSeenSystemnodeBroadcast` (`src/systemnodeman.cpp:222-228`)

Two peers can evaluate different inputs to the same rule because the origin node inserts locally from the RPC path without re-running `CheckInputsAndAdd`, while peers must run the full remote path (`src/rpcsystemnode.cpp:225-230` vs `src/systemnodeman.cpp:241-259`).

## 6. First divergent condition

Exact function: `CSystemnodeBroadcast::CheckInputsAndAdd`

Exact condition:

```cpp
if (pConfIndex->GetBlockTime() > sigTime) { ... return false; }
```

Source: `src/systemnode.cpp:640-644`

Actual observed values from run 5:

- `sigTime = 1789152641`
- 15-confirmation block time = `1789152754`
- result = reject on peers, remain locally inserted on `sn1`

Why peers differ:

- `systemnode start-alias` inserts the broadcast directly into the local list on `sn1` (`src/rpcsystemnode.cpp:227-230`)
- peer nodes then run `CheckInputsAndAdd`, which compares broadcast wall-clock `sigTime` from `GetAdjustedTime()` against the collateral confirmation block time (`src/systemnode.cpp:632-644`)
- rapid on-demand regtest mining advanced block timestamps ahead of wall clock, so the collateral looked mature by depth but not by the later `sigTime` check

Root-cause classification for registration divergence:

- **REGTEST-SPECIFIC DEFECT**
- **STATE-INITIALIZATION DEFECT**
- **TIMING/ORDER DEPENDENCY**
- **TEST-ENVIRONMENT LIMITATION**

Evidence:

- the failure depends on fast regtest block timestamps overtaking wall clock
- waiting until wall clock passes the 15-confirmation block time removes the divergence without any source change

## 7. Payment-transition reproduction

### Deterministic converged-state reproduction

Executed flow:

1. repeat the same collateral setup
2. compute the collateral transaction's 15-confirmation block time
3. wait until wall clock passes that block time
4. restart `sn1`
5. run `systemnode start-alias sn1`
6. confirm all four peers now report `count=1`
7. call `getblocktemplate '{}'` on `sn1` and `ctl`

Observed registration convergence after the wait:

```text
=== ctl ===
1
{"754b...ac2f-0":"ENABLED"}
=== mn1 ===
1
{"754b...ac2f-0":"ENABLED"}
=== sn1 ===
1
{"754b...ac2f-0":"ENABLED"}
=== obs ===
1
{"754b...ac2f-0":"ENABLED"}
```

Observed payment-transition failure:

```text
sn1 getblocktemplate rc=1
error: {"code":-1,"message":"CTransaction::GetValueOut() : value out of range"}

ctl getblocktemplate rc=1
error: {"code":-1,"message":"CTransaction::GetValueOut() : value out of range"}
```

### Minimal repeatable condition

- zero masternodes
- one enabled systemnode
- node payments active
- block/template creation invoked

No historical payment winner data was required.

## 8. `GetValueOut()` source trace

Call path:

1. RPC caller: `getblocktemplate` (`src/rpcmining.cpp:545-569`)
2. block assembly: `CreateNewBlock(scriptDummy)` (`src/rpcmining.cpp:566-569`, `src/miner.cpp:103-458`)
3. masternode payment fill: `FillBlockPayee(txCoinbase, nFees)` (`src/miner.cpp:371-375`, `src/masternode-payments.cpp:154-192`)
4. systemnode payment fill: `SNFillBlockPayee(txCoinbase, nFees)` (`src/miner.cpp:371-375`, `src/systemnode-payments.cpp:183-244`)
5. returned template coinbase summary: `pblock->vtx[0].GetValueOut()` (`src/rpcmining.cpp:635`)
6. exception site: `CTransaction::GetValueOut()` (`src/primitives/transaction.cpp:120-129`)

Invalid assumption:

- `CMasternodePayments::FillBlockPayee` leaves `txCoinbase.vout` at size 1 when no masternode payee exists (`src/masternode-payments.cpp:163-180`)
- `CSystemnodePayments::FillBlockPayee` then resizes `txCoinbase.vout` to 3 and fills only slot 2 (`src/systemnode-payments.cpp:230-237`)
- slot 1 remains a default-constructed `CTxOut`, whose `SetNull()` value is `nValue = -1` (`src/primitives/transaction.h:135-155`)
- `GetValueOut()` rejects that negative output (`src/primitives/transaction.cpp:123-127`)

## 9. Transition-boundary analysis

The trigger is state-based, not activation-height-based.

| Height / state | Payment mode | Expected output structure | Actual output structure | `GetValueOut` result | Status |
| --- | --- | --- | --- | --- | --- |
| 720, no enabled systemnode | no node payee | `[miner]` | `[miner]` | succeeds | GREEN |
| 720, immediate local-only `sn1` entry | systemnode payee only on `sn1` | `[miner, mn, sn]` or `[miner, sn]` handled safely | `[miner, null(-1), sn]` on `sn1` | throws | RED |
| 720, waited converged registration | systemnode payee only on all peers | `[miner, mn, sn]` or `[miner, sn]` handled safely | `[miner, null(-1), sn]` on all peers | throws | RED |

At height 721 on regtest in these runs:

- block value from the template path: `75000000`
- expected systemnode payment: `7500000` (`src/main.cpp:1770-1778`)
- miner remainder after systemnode payment: `67500000`
- actual hidden middle slot: `-1`

## 10. Relationship between failures

**RELATIONSHIP: INDIRECTLY RELATED**

Evidence:

- registration divergence is not required for the payment failure; after waiting away the sigTime rejection, all peers still hit `GetValueOut()` (`run6`)
- payment failure does not explain the original divergence; the first disagreement already happens in registration validation before block creation (`run5`)
- both blockers are exposed by the same one-systemnode/zero-masternode private-network setup, so the registration outcome can mask or localize the payment failure

## 11. `tCRW` impact

| Area | Classification | Evidence |
| --- | --- | --- |
| registration divergence | UNRELATED | rejection is the `sigTime` check in `CheckInputsAndAdd`, not address parsing |
| collateral recognition | CONTRIBUTING | normal `validateaddress` / `sendtoaddress` regtest flow is broken, so collateral setup required a raw-transaction workaround |
| payment construction | UNRELATED | payout assembly uses existing pubkey hashes and list state, not wallet address validation |
| `GetValueOut()` failure | UNRELATED | failure is caused by an uninitialized slot 1 output, not by address parsing |

## 12. Historical-state / spork / governance impact

| Dependency | Registration divergence | Payment-transition failure | Classification |
| --- | --- | --- | --- |
| historical spork state | not required | not required; current default payment activation is enough | NOT REQUIRED |
| payment-winner state | not required | not required; fallback `GetCurrentSystemNode(1)` is enough (`src/systemnode-payments.cpp:213-218`) | NOT REQUIRED |
| governance / budget state | not required | not required in reproduced path | NOT REQUIRED |
| cached masternode state | not required | not required beyond there being no masternode payee | NOT REQUIRED |
| cached systemnode state | no historical cache required; live local list entry is enough | live local enabled systemnode entry is required | PAYMENT/POLICY REQUIREMENT |
| historical database contents | not required | not required | NOT REQUIRED |
| historical registration broadcasts | not required | not required | NOT REQUIRED |

Conclusion: neither blocker required historical mainnet-era operational data to reproduce.

## 13. Reproduction tooling

Committed tooling:

- `contrib/devtools/revival/mnpos-repro-common.sh`
- `contrib/devtools/revival/repro-registration-divergence.sh`
- `contrib/devtools/revival/repro-payment-transition.sh`

Properties:

- disposable datadirs under `/tmp`
- loopback-only node sockets
- deterministic startup order and command sequence
- no real wallets, keys, or CRW
- explicit failure checks and non-zero exit codes
- safe cleanup with optional `KEEP_WORKDIR=1`

## 14. Root-cause classification

### Registration divergence

- **IMPLEMENTATION DEFECT** — local `start-alias` insertion bypasses the same full acceptance path used by peers
- **REGTEST-SPECIFIC DEFECT** — fast regtest mining makes the `sigTime`/confirmation-block-time comparison fail deterministically
- **STATE-INITIALIZATION DEFECT** — collateral depth and collateral-time validity are checked in different places with different effective inputs
- **TEST-ENVIRONMENT LIMITATION** — loopback/private-only labs also need a fake routable advertised address because config/broadcast validation rejects private addresses

### Payment-transition failure

- **IMPLEMENTATION DEFECT** — slot 1 is left as a null `CTxOut` when only a systemnode payee exists
- **PAYMENT-TRANSITION DEFECT** — the failure happens during node-payment assembly when state transitions from no systemnode payee to one enabled systemnode payee
- **LEGACY DESIGN LIMITATION** — the payout builder assumes a fixed masternode/systemnode slot layout even when only one node class is active

## 15. Production-fix assessment

### Registration divergence

| Question | Assessment |
| --- | --- |
| Production source change required | **LIKELY** |
| Affected source | `src/rpcsystemnode.cpp`, `src/systemnode.cpp`, `src/systemnodeman.cpp` |
| Consensus impact if corrected | **LOW** |
| Monetary impact | **NONE** |
| P2P / wire impact | **LOW** |
| Wallet-format impact | **NONE** |
| Cryptographic impact | **NONE** |
| Historical mainnet compatibility impact | **LOW** |

Likely change shape: unify local and remote acceptance criteria or gate regtest/private-lab start timing against the same maturity-time rule.

### Payment-transition failure

| Question | Assessment |
| --- | --- |
| Production source change required | **YES** |
| Affected source | `src/miner.cpp`, `src/masternode-payments.cpp`, `src/systemnode-payments.cpp`, `src/primitives/transaction.h` |
| Consensus impact if corrected | **POSSIBLE** |
| Monetary impact | **POSSIBLE** |
| P2P / wire impact | **NONE** |
| Wallet-format impact | **NONE** |
| Cryptographic impact | **NONE** |
| Historical mainnet compatibility impact | **UNKNOWN** |

Likely change shape: ensure coinbase output construction never leaves a negative sentinel output in the fixed payment-slot layout.

## 16. Recommended next task

**Selected next task: B. production fix for payment-transition failure**

Reason: it is the smaller code-local defect, is now deterministically reproduced on any peer once registration converges, and blocks further node-payment and MNPoS private-network validation even after the registration timing issue is controlled.

Remaining dependency order:

1. **B** — production fix for `GetValueOut()` payment-transition failure
2. **E** — targeted production fix/investigation for registration divergence timing and local/remote acceptance asymmetry
3. **D** — further targeted MNPoS bootstrap investigation after node payments can operate in a converged private network
4. **F** — targeted `tCRW` regtest address investigation
5. **G** — historical-state/spork dependency investigation only if new evidence appears
6. **H** — Phase 2 historical chain/economic audit

## Final verdict

| Question | Verdict |
| --- | --- |
| REGISTRATION DIVERGENCE REPRO | **DETERMINISTIC** |
| REGISTRATION DIVERGENCE ROOT CAUSE | **ESTABLISHED** |
| PAYMENT-TRANSITION REPRO | **DETERMINISTIC** |
| PAYMENT-TRANSITION ROOT CAUSE | **ESTABLISHED** |
| RELATIONSHIP | **INDIRECT** |
| PRODUCTION FIX REQUIRED | **YES** |
| SAFE TO CONTINUE MNPoS VALIDATION | **PARTIALLY** |
| SAFE TO PROCEED TO PHASE 2 | **NO** |

Committed diff scope check:

- no permanent C++ production-behaviour changes
- committed files are audit/tooling only
