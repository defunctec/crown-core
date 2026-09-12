# Crown Revival — Phase 1G: Fix Deterministic Systemnode Registration Divergence

## 1. Starting baseline

| Item | Value |
| --- | --- |
| Copilot branch | `copilot/phase-1g-fix-deterministic-registration-divergence` |
| Current HEAD before Phase 1G edits | `2c865c2bb1d635549a1acba8c680e06e0dde9791` |
| Starting `master` SHA | `2c865c2bb1d635549a1acba8c680e06e0dde9791` (`git ls-remote --heads origin master`, because `master` was not fetched locally) |
| `git status` before edits | `## copilot/phase-1g-fix-deterministic-registration-divergence...origin/copilot/phase-1g-fix-deterministic-registration-divergence` |
| OS | `Linux 6.17.0-1022-azure x86_64` |
| Compiler | `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` |
| OpenSSL | `OpenSSL 3.0.13 30 Jan 2024` |
| Boost | `1.83.0.1ubuntu2` |
| `crownd` | `Crown Core Daemon version v0.14.0.7-2c865c2` |
| `crown-cli` | `Crown Core RPC client version v0.14.0.7-2c865c2` |

Required documents were present and read before source changes:

- `docs/revival/MNPOS_NETWORK_AUDIT.md`
- `docs/revival/MNPOS_PAYMENT_FIX_AUDIT.md`
- `docs/revival/HISTORICAL_PR1_AUDIT.md`
- `docs/revival/HISTORICAL_PR1_REMEDIATION.md`
- Phase 1E blocker document identified as `docs/revival/MNPOS_BLOCKER_AUDIT.md`

Current master already contained both required predecessors:

- Phase 1F payment fix, verified by the merged audit and by `mnpos_payment_tests` passing (`docs/revival/MNPOS_PAYMENT_FIX_AUDIT.md:140-175`)
- PR #10 identity-aware duplicate-IP remediation, verified by merge history and by `pr1_remediation_tests` passing (`docs/revival/HISTORICAL_PR1_REMEDIATION.md:67-85`, `src/test/pr1_remediation_tests.cpp:39-61`)

Pre-change guard tests:

- `./src/test/test_crown --run_test=mnpos_payment_tests/* --log_level=test_suite` → **PASS**
- `./src/test/test_crown --run_test=pr1_remediation_tests/* --log_level=test_suite` → **PASS**

## 2. Phase 1E pre-fix deterministic repro

Exact reproduction reused the committed Phase 1E tooling in `contrib/devtools/revival/mnpos-repro-common.sh` and `contrib/devtools/revival/repro-registration-divergence.sh`.

Runtime topology:

| Node | RPC | P2P | Role |
| --- | --- | --- | --- |
| `ctl` | `18401` | `24001` | controller / miner |
| `mn1` | `18402` | `24002` | peer |
| `sn1` | `18403` | `24003` | systemnode origin |
| `obs` | `18404` | `24004` | observer |

Recorded pre-fix values:

| Item | Value |
| --- | --- |
| node count | `4` |
| node identities | `ctl`, `mn1`, `sn1`, `obs` |
| collateral txid | `c0ae03222c56beb255d7c325b9476246a845ebae8c70541542046d0fd02d85be` |
| collateral vout | `0` |
| collateral block height | `701` |
| collateral block timestamp | `1789200580` |
| required confirmation depth | `15` |
| 15-confirmation block height | `715` |
| 15-confirmation block timestamp | `1789200582` |
| current chain height | `720` |
| current tip timestamp | `1789200583` |
| local wall-clock time at start | `1789200466` |
| adjusted/network time relevance | `ctl` `timeoffset=0`; broadcast `sigTime` still came from local `GetAdjustedTime()` |
| median-time-past | not exposed by this older RPC path in the repro run |
| broadcast `sigTime` | peer observed `1789200470`; a same-state created/decode probe reported `1789200473` |
| origin-node result | `systemnode start-alias sn1` returned `successful`; local `systemnode count=1` |
| peer result | `ctl`, `mn1`, `obs` each remained `systemnode count=0` |

Observed divergence:

```text
=== ctl ===
0
{}
=== mn1 ===
0
{}
=== sn1 ===
1
{"c0ae...85be-0":"ENABLED"}
=== obs ===
0
{}
```

Origin evidence:

- local mutation happened immediately through `CSystemnodeMan::UpdateSystemnodeList()` on `sn1`
- log evidence: `/tmp/crown-phase1g-prefix/sn1/regtest/debug.log:3709`

Peer rejection evidence:

```text
/tmp/crown-phase1g-prefix/ctl/regtest/debug.log:7171
snb - Bad sigTime 1789200470 ... (15 conf block is at 1789200582)

/tmp/crown-phase1g-prefix/ctl/regtest/debug.log:7172
CSystemnodeMan::CheckSnbAndUpdateSystemnodeList - Rejected Systemnode entry 8.8.8.8:24003
```

### Exact divergence point

The first state divergence occurred before relay recipients completed full acceptance:

- origin path inserted locally via `snodeman.UpdateSystemnodeList(snb)` in `src/rpcsystemnode.cpp:227-239` (pre-fix behavior documented in `docs/revival/MNPOS_BLOCKER_AUDIT.md:125-141`)
- peers ran `CSystemnodeMan::CheckSnbAndUpdateSystemnodeList(...)` in `src/systemnodeman.cpp:217-264`
- peer rejection fired in `CSystemnodeBroadcast::CheckInputsAndAdd(...)` at `src/systemnode.cpp:632-645`

ORIGIN: **accepted / inserted**

PEER: **rejected**

## 3. Complete registration path

Actual runtime path for `systemnode start-alias`:

1. RPC entry in `src/rpcsystemnode.cpp:192-249`
2. broadcast construction in `CSystemnodeBroadcast::Create(...)` at `src/systemnode.cpp:727-823`
3. `sigTime` assignment during signing in `CSystemnodeBroadcast::Sign(...)` at `src/systemnode.cpp:825-842`
4. local validation/insertion path through `CSystemnodeMan::CheckSnbAndUpdateSystemnodeList(...)` at `src/systemnodeman.cpp:217-264` (**post-fix**) instead of direct insertion
5. peer P2P handling in `CSystemnodeMan::ProcessMessage("snb")` at `src/systemnodeman.cpp:96-118`
6. peer signature/update validation in `CSystemnodeBroadcast::CheckAndUpdate(...)` at `src/systemnode.cpp:421-570`
7. collateral, duplicate-IP, maturity, and collateral-time validation in `CSystemnodeBroadcast::CheckInputsAndAdd(...)` at `src/systemnode.cpp:572-672`
8. list insertion only after successful full validation via `snodeman.Add(sn)` at `src/systemnode.cpp:648-650`

Relevant conditions and state mutations:

- `sigTime` is set from `GetAdjustedTime()` when the broadcast is signed (`src/systemnode.cpp:832`)
- peers reject future signatures beyond one hour (`src/systemnode.cpp:425-430`)
- peers reject broadcasts whose collateral has fewer than 15 confirmations (`src/systemnode.cpp:624-630`)
- peers reject broadcasts whose `sigTime` predates the block where the collateral reached 15 confirmations (`src/systemnode.cpp:632-645`)
- PR #10 duplicate-IP checks remain identity-aware and only reject same-address conflicts when `vin` differs (`src/systemnode.cpp:519-537`, `src/systemnode.cpp:593-598`, `src/systemnodeman.cpp:479-487`)

The broadcast is not mutated between successful signing and relay; the divergence was caused by **origin-only local insertion before equivalent validation**, not by relay-time mutation.

## 4. PR #10 duplicate-IP relationship

Classification for the Phase 1E divergence: **UNRELATED**.

Evidence:

- the first rejection is the collateral-time `sigTime` failure in `src/systemnode.cpp:641-644`
- PR #10 logic is limited to identity-aware duplicate-IP filtering (`src/systemnode.cpp:519-537`, `src/systemnode.cpp:593-598`, `src/systemnodeman.cpp:479-487`)
- the dedicated PR #10 regression remained green before and after the fix (`src/test/pr1_remediation_tests.cpp:39-61`)

No PR #10 duplicate-IP semantics were changed in Phase 1G.

## 5. Historical collateral timestamp rule

Intended historical rule:

> A systemnode broadcast must not claim a signing time earlier than the block time at which its collateral first reached the required 15 confirmations.

Source evidence:

- code comment and enforcement in `src/systemnode.cpp:632-645`
- parallel masternode rule in `src/masternode.cpp:710-723`

Purpose preserved by this task:

- prevent pre-dated registration before mature collateral
- preserve ordering between collateral maturity and advertised node activation
- keep origin and peer admission decisions aligned under the same temporal rule

The fix does **not** weaken or remove this rule.

## 6. Root cause vs trigger

ROOT CAUSE:

- local systemnode registration paths mutated local state before running the same full acceptance path that peers run; specifically, `UpdateSystemnodeList()` was used directly by start paths instead of `CheckSnbAndUpdateSystemnodeList()`

TRIGGER:

- rapid regtest mining advanced block timestamps ahead of the origin node's adjusted wall clock, so `sigTime` from `GetAdjustedTime()` lagged the collateral 15-confirmation block time

SECONDARY CONTRIBUTING FACTORS:

- the rule compares two different time domains: local adjusted time vs block header time (`src/systemnode.cpp:641-644`)
- block headers may be up to two hours in the future relative to adjusted time (`src/main.cpp:3329-3332`), while systemnode broadcast signatures are capped at one hour in the future (`src/systemnode.cpp:425-430`)

## 7. Mainnet relevance

Classification: **REGTEST-EASILY-TRIGGERED BUT PRODUCTION-POSSIBLE**

Why:

- regtest makes the defect deterministic because 15 blocks can be mined almost instantly
- the logical mismatch is not regtest-only: block headers may be accepted up to `GetAdjustedTime() + 2 * 60 * 60` (`src/main.cpp:3330-3332`), while broadcast `sigTime` is only sourced from local adjusted time and cannot be more than one hour ahead (`src/systemnode.cpp:425-430`, `src/systemnode.cpp:832`)
- therefore a sufficiently future-skewed but still-valid block sequence can make a just-mature collateral appear deep enough while its maturity block time is still ahead of the broadcaster's adjusted time

This makes the bug easier to trigger on regtest, but not logically confined to regtest.

## 8. Masternode comparison

The equivalent masternode code follows the same structural pattern:

- `masternode start-alias` locally inserted via `UpdateMasternodeList(...)` in `src/rpcmasternode.cpp:291-296`
- peer validation runs through `CMasternodeMan::CheckMnbAndUpdateMasternodeList(...)` in `src/masternodeman.cpp:720-762`
- the same collateral-time rule exists in `CMasternodeBroadcast::CheckInputsAndAdd(...)` at `src/masternode.cpp:710-723`

Conclusion:

- the same logical divergence is theoretically possible for masternodes
- Phase 1G did **not** change masternode code, because the established deterministic blocker under this task was Systemnode registration

## 9. Candidate fixes considered

| Candidate | Root cause addressed | Historical rule preserved? | Origin/peer equivalence restored? | Mainnet behavior changed? | PR #10 impact | Drawbacks |
| --- | --- | --- | --- | --- | --- | --- |
| Remove or relax the `sigTime >= conf15 block time` rule | No | **No** | Maybe | Yes | None | Explicitly weakens the historical maturity-ordering protection |
| Force `sigTime` to `max(GetAdjustedTime(), conf15 block time)` during creation | Partly | Yes | Yes | Yes | None | Changes broadcast creation semantics and can shift externally visible registration timing |
| Delay local insertion until the existing full validation path accepts the broadcast | **Yes** | **Yes** | **Yes** | Minimal | None | Local start now fails early instead of creating a divergent local-only entry |

Chosen fix: **delay local insertion until the existing full validation path accepts the broadcast**.

## 10. Safety gate before implementation

| Area | Impact |
| --- | --- |
| Consensus validation | **NO** |
| Block creation | **NO** |
| Block validation | **NO** |
| P2P serialization | **NO** |
| Broadcast serialization | **NO** |
| Node-list semantics | **YES** (restores origin/peer admission equivalence) |
| Collateral maturity | **NO** |
| Historical registrations | **NO** |
| Wallet format | **NO** |
| Monetary behavior | **NO** |
| Cryptography | **NO** |
| PR #10 duplicate-IP semantics | **NO** |

No serialized fields, collateral rules, wallet formats, or payment values were changed.

## 11. Implemented minimal fix

Production changes:

- `src/rpcsystemnode.cpp:227-239,339-358`
  - `start-alias` and `start-many/start-all/start-missing/start-disabled` now call `snodeman.CheckSnbAndUpdateSystemnodeList(...)`
  - local RPC returns `failed` if the broadcast is rejected by the same full validation path peers use
- `src/activesystemnode.cpp:127-145`
  - hot/cold activation now requires local acceptance through `CheckSnbAndUpdateSystemnodeList(...)`
- `src/qt/systemnodelist.cpp:121-132,160-173`
  - Qt start flows now use the same local validation path before reporting success

What did **not** change:

- collateral amount
- confirmation count
- payment rules
- reward calculations
- MNPoS producer selection
- block timing rules
- chainparams
- transaction format
- broadcast serialization
- wallet format
- PR #10 duplicate-IP semantics

## 12. Regression tests

New targeted regression:

- `qa/rpc-tests/systemnode_registration_divergence.sh:1-134`
- wired into `qa/pull-tester/rpc-tests.sh:18-29`

What the new regression proves:

1. 14 confirmations still fails with `Input must have at least 15 confirmations`
2. immediate post-maturity start no longer produces `origin accepts / peers reject`; all nodes stay at `count=0`
3. local rejection is driven by the same `Bad sigTime ... (15 conf block is at ...)` validation path
4. once wall clock naturally passes the maturity block time, registration succeeds and all nodes agree on the same enabled Systemnode

Existing guard regressions re-run:

- `pr1_remediation_tests` → same `addr` + same `vin` still valid; same `addr` + different `vin` still rejected
- `mnpos_payment_tests` → Phase 1F payout fix preserved
- `serialize_tests`, `transaction_tests`, `staking_tests` → no regressions in nearby subsystems

## 13. Post-fix deterministic repro

Exact same immediate-start sequence after the fix:

| Item | Value |
| --- | --- |
| collateral txid | `6b802c85fa8d5b13d08c1797c4684454889f04c9eea17e439b1e737bad69df8d` |
| collateral block timestamp | `1789200865` |
| 15-confirmation block timestamp | `1789200867` |
| chain-tip timestamp at start | `1789200868` |
| broadcast `sigTime` | `1789200755` |
| origin result | `failed` |
| peer A result (`ctl`) | `count=0` |
| peer B result (`mn1`) | `count=0` |
| peer C result (`obs`) | `count=0` |

Immediate-start post-fix result:

```text
{
  "alias": "sn1",
  "result": "failed",
  "errorMessage": "Systemnode broadcast rejected by local validation. See debug.log for details."
}
```

All-node state after the immediate retry:

```text
=== ctl === 0
=== mn1 === 0
=== sn1 === 0
=== obs === 0
```

Local rejection evidence:

```text
/tmp/crown-phase1g-postfix/sn1/regtest/debug.log:3709
snb - Bad sigTime 1789200755 ... (15 conf block is at 1789200867)

/tmp/crown-phase1g-postfix/sn1/regtest/debug.log:3710
CSystemnodeMan::CheckSnbAndUpdateSystemnodeList - Rejected Systemnode entry 8.8.8.8:24003
```

EXACT PHASE 1E REPRO NO LONGER DIVERGES: **YES**

## 14. Eventual valid registration

No rule changes were needed. The only condition advanced was the existing wall clock / adjusted-time condition required by the historical collateral timestamp rule.

After waiting until wall clock exceeded the 15-confirmation block timestamp:

| Item | Value |
| --- | --- |
| wall clock after wait | `1789200874` |
| start result | `successful` |
| agreed `vin` | `6b802c85fa8d5b13d08c1797c4684454889f04c9eea17e439b1e737bad69df8d-0` |
| agreed status | `ENABLED` on `ctl`, `mn1`, `sn1`, `obs` |
| agreed address | `8.8.8.8:24003` |
| agreed protocol version | `70062` |

Converged result:

```text
=== ctl ===
1
{"6b80...df8d-0":"ENABLED"}
=== mn1 ===
1
{"6b80...df8d-0":"ENABLED"}
=== sn1 ===
1
{"6b80...df8d-0":"ENABLED"}
=== obs ===
1
{"6b80...df8d-0":"ENABLED"}
```

## 15. PR #10 duplicate-IP regression result

`./src/test/test_crown --run_test=pr1_remediation_tests/* --log_level=test_suite` → **PASS**

- same `addr` + same `vin` remains allowed
- same `addr` + different `vin` remains rejected

PR #10 semantics preserved: **YES**

## 16. Phase 1F payment regression result

`./src/test/test_crown --run_test=mnpos_payment_tests/* --log_level=test_suite` → **PASS**

Runtime follow-through after converged registration:

- `sn1 getblocktemplate '{}'` → **success**
- `ctl getblocktemplate '{}'` → **success**
- `payee` remained empty
- `payeeSN` agreed as `tCRWDjfojs7o4E7xAAbphh8uyVRita5Jfnu9h`
- `payeeSN_amount` agreed as `7500000`

This preserved the Phase 1F guarantee that the Systemnode-only payment transition no longer produces an invalid `nValue = -1` coinbase output.

## 17. MNPoS follow-through

Small private-network follow-through after converged registration:

- Systemnode registration converged across all peers
- MNPoS payment/template generation passed the previous Phase 1F blocker on both `sn1` and `ctl`
- one additional block was mined successfully: `2102afbc398e13443770222b2efb92809b58965fed0a5a910d39bcb1bb53be75`
- all nodes agreed on the final chain tip:
  - `ctl`: `2102afbc398e13443770222b2efb92809b58965fed0a5a910d39bcb1bb53be75`
  - `mn1`: `2102afbc398e13443770222b2efb92809b58965fed0a5a910d39bcb1bb53be75`
  - `sn1`: `2102afbc398e13443770222b2efb92809b58965fed0a5a910d39bcb1bb53be75`
  - `obs`: `2102afbc398e13443770222b2efb92809b58965fed0a5a910d39bcb1bb53be75`

No new independent blocker appeared during this limited follow-through.

## 18. Historical compatibility report

| Check | Result |
| --- | --- |
| Broadcast wire format changed | **NO** |
| Broadcast serialized fields changed | **NO** |
| Historical valid broadcasts reinterpreted | **NO** |
| Collateral amount changed | **NO** |
| Required confirmations changed | **NO** |
| Collateral timestamp rule changed | **NO** |
| Node-list persistence format changed | **NO** |
| PR #10 duplicate-IP semantics changed | **NO** |
| Wallet format changed | **NO** |
| Cryptography changed | **NO** |
| Monetary behavior changed | **NO** |
| Historical block validation changed | **NO** |

## 19. Production diff summary

Files changed for the fix:

- `src/rpcsystemnode.cpp`
- `src/activesystemnode.cpp`
- `src/qt/systemnodelist.cpp`
- `qa/rpc-tests/systemnode_registration_divergence.sh`
- `qa/pull-tester/rpc-tests.sh`

Net effect:

- origin-side Systemnode start flows now succeed **only** when the same validation path peers use also succeeds
- invalid early broadcasts no longer create local-only Systemnode entries
- once the historical maturity-time rule is satisfied, registration converges normally

## 20. Tests run

Builds:

- `./autogen.sh`
- `./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui`
- `make -C src -j4 crownd crown-cli crown_test crown-tx`
- `make -C src -j4 crownd crown-cli crown_test crown-tx` (post-fix incremental rebuild)

Targeted tests:

- `./src/test/test_crown --run_test=mnpos_payment_tests/* --log_level=test_suite`
- `./src/test/test_crown --run_test=pr1_remediation_tests/* --log_level=test_suite`
- `./src/test/test_crown --run_test=serialize_tests/* --log_level=test_suite`
- `./src/test/test_crown --run_test=transaction_tests/* --log_level=test_suite`
- `./src/test/test_crown --run_test=staking_tests/* --log_level=test_suite`
- `./qa/rpc-tests/systemnode_registration_divergence.sh --srcdir ./src`

All listed commands passed.

## 21. Concise issue table

| ISSUE | PRE-FIX RESULT | ROOT CAUSE | FIX | POST-FIX RESULT | COMPATIBILITY IMPACT |
| --- | --- | --- | --- | --- | --- |
| Immediate regtest Systemnode start after depth maturity | Origin inserted `ENABLED`, peers rejected | Origin bypassed full admission path and skipped collateral-time validation | Route local Systemnode start paths through `CheckSnbAndUpdateSystemnodeList(...)` before reporting success | All nodes consistently reject until valid, then converge on success | No wire, consensus, wallet, or monetary change |
| Phase 1F Systemnode-only payment transition | Already fixed before Phase 1G | N/A for this task | Unchanged; re-verified | `getblocktemplate` succeeds and block mining proceeds | None |
| PR #10 duplicate-IP identity awareness | Already fixed before Phase 1G | N/A for this task | Unchanged; re-verified | same `vin` allowed, different `vin` rejected | None |

## 22. Final verdict

REGISTRATION DIVERGENCE FIXED: **YES**

EXACT PHASE 1E REPRO NO LONGER DIVERGES: **YES**

ROOT CAUSE:

- local Systemnode registration paths inserted broadcasts into the origin node's list before running the same `CheckSnbAndUpdateSystemnodeList(...)` / `CheckInputsAndAdd(...)` validation path that peers use, so an early `sigTime` could create an origin-only entry while peers correctly rejected it against the existing collateral-confirmation-time rule.
