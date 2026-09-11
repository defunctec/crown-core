# Crown Revival — Historical PR #1 Selective Remediation

## Baselines and runtime context

- Clean Crown baseline (`v0.14.0.4`): `3050c1f970e6dc4713c41a88f80638c597af33e9`
- Historical PR #1 merge: `487053abf22c7bacdfad80fad1081f856db9b940`
- Starting master SHA for this task branch: `8d19bba1ba518c65e1fb21c7dbd2195e270c6486`
- Task branch: `copilot/selective-remediation-historical-pr1`
- Current HEAD (post-remediation): `8eb2d7701fea8a9edc9537230d79ff78c56145ed`
- Git status at analysis start: clean

## PR #1 change decomposition (clean vs PR #1)

| CHANGE ID | FILE | FUNCTION/PATH | ORIGINAL v0.14.0.4 BEHAVIOUR | PR #1 BEHAVIOUR | ORIGINAL INTENT | AUDIT CLASSIFICATION | CURRENT REVIVAL DEPENDENCY |
|---|---|---|---|---|---|---|---|
| PR1-01 | `src/amount.h` | `MAX_MONEY` / `MoneyRange` | `MAX_MONEY=21,000,000*COIN` | `MAX_MONEY=42,000,000*COIN` | Align ceiling with presumed supply target | QUESTIONABLE (monetary/consensus-adjacent) | Survives in current master/task branch |
| PR1-02 | `src/masternode.cpp` | `CMasternodeBroadcast::CheckAndUpdate` | No explicit duplicate-IP rejection branch | Added duplicate-IP rejection branch keyed by address, with DoS score path | Enforce unique MN IPv4 identity | QUESTIONABLE (original implementation quality) | Survives, with later revival hardening |
| PR1-03 | `src/masternode.cpp` | `CMasternodeBroadcast::CheckInputsAndAdd` | No duplicate-IP pre-reject branch | Added duplicate-IP pre-reject branch | Enforce unique MN IPv4 identity | QUESTIONABLE (address-only false positives) | Remediated in task branch to identity-aware (`addr + different vin`) |
| PR1-04 | `src/masternodeman.h/.cpp` | `IsAddressInUse(const CService&)` | Helper absent | Added helper for address-in-use checks | Shared duplicate-IP policy helper | SUPPORTING/LOW RISK | Survives; extended with identity-aware overload |
| PR1-05 | `src/systemnode.cpp` | `CSystemnodeBroadcast::CheckAndUpdate` | No explicit duplicate-IP rejection branch | Added duplicate-IP rejection branch keyed by address, with DoS score path | Enforce unique SN IPv4 identity | QUESTIONABLE (original implementation quality) | Survives, with later revival hardening |
| PR1-06 | `src/systemnode.cpp` | `CSystemnodeBroadcast::CheckInputsAndAdd` | No duplicate-IP pre-reject branch | Added duplicate-IP pre-reject branch | Enforce unique SN IPv4 identity | QUESTIONABLE (address-only false positives) | Remediated in task branch to identity-aware (`addr + different vin`) |
| PR1-07 | `src/systemnodeman.h/.cpp` | `Find(const CScript&)`, `IsAddressInUse(const CService&)`, score var refactor | Helper/refactor absent | Added helper/refactor code | Support duplicate-IP and manager querying | HARMLESS/REDUNDANT (for `Find`/refactor) | Survives; address helper extended with identity-aware overload |
| PR1-08 | `src/rpcmasternode.cpp` | `masternode(...)`, `masternodebroadcast(...)` | No duplicate-IP prechecks in start/create flows | Added duplicate-IP prechecks plus connect UX improvements | Fail early for duplicate operators; improve diagnostics | QUESTIONABLE (state-local over-rejection risk) | Remediated in task branch to identity-aware checks |
| PR1-09 | `src/rpcsystemnode.cpp` | `systemnode(...)`, `systemnodebroadcast(...)` | No duplicate-IP prechecks in start/create flows | Added duplicate-IP prechecks plus connect UX improvements | Fail early for duplicate operators; improve diagnostics | QUESTIONABLE (state-local over-rejection risk) | Remediated in task branch to identity-aware checks |
| PR1-10 | `src/qt/createnodedialog.cpp` | `CreateNodeDialog::CheckIP()` | Syntax/routability validation only | Added local-list duplicate-IP blocking and error handling | Fail early in UI | QUESTIONABLE (UI local-state hard gate) | Reverted in task branch to validation-only behavior |

## Baseline verification and surviving PR #1 scope

Historical references were verified by commit SHA and compared against current master/task branch.

PR #1 historical files in scope:
- `src/amount.h`
- `src/masternode.cpp`
- `src/masternodeman.cpp`
- `src/masternodeman.h`
- `src/qt/createnodedialog.cpp`
- `src/rpcmasternode.cpp`
- `src/rpcsystemnode.cpp`
- `src/systemnode.cpp`
- `src/systemnodeman.cpp`
- `src/systemnodeman.h`

Observed in current master before this remediation branch:
- All ten PR #1 paths still existed in modified form relative to clean baseline.
- Post-PR #1 master-era edits touched `src/masternode.cpp` and `src/systemnode.cpp` (stakepointer plus duplicate-IP branch cleanup), while most other PR #1-introduced patterns persisted.

## Monetary analysis (`src/amount.h`) — high-risk guardrail

### What changed historically
- PR #1 changed `MAX_MONEY` from 21M to 42M.

### Impact surface
- `MoneyRange(...)` validation boundaries
- transaction/value checks in consensus/wallet paths that depend on `MoneyRange`
- potential historical block/transaction validity boundary behavior

### Remediation decision
- **No monetary constant change in this remediation.**
- Reason: high consensus/historical-compatibility uncertainty remains without explicit chain-evidence proving safe restoration to 21M.
- Classification: **UNKNOWN/HIGH** for historical consensus impact if altered now.

## Masternode remediation analysis

### Historical issue focus
- PR #1 duplicate-IP checks were partly address-only and could over-reject when same identity (`vin`) re-broadcasted.

### Implemented low-risk/proven remediation
- Added/used `CMasternodeMan::IsAddressInUse(const CService&, const CTxIn&)` in broadcast/RPC prechecks.
- Updated `CMasternodeBroadcast::CheckInputsAndAdd` to reject duplicate address only when `vin` differs.
- Updated RPC start/create paths to pass candidate `vin` to duplicate-IP checks.

### Classification
- Decision: **KEEP INTENT, REIMPLEMENT SAFELY**
- Consensus impact: low (admission policy hardening without serialization or reward rule change)
- Wire impact: low (no message format changes)

## Systemnode remediation analysis

### Historical issue focus
- Same address-only duplicate-IP prechecks and over-rejection risk as masternodes.

### Implemented low-risk/proven remediation
- Added/used `CSystemnodeMan::IsAddressInUse(const CService&, const CTxIn&)` in broadcast/RPC prechecks.
- Updated `CSystemnodeBroadcast::CheckInputsAndAdd` to reject duplicate address only when `vin` differs.
- Updated RPC start/create/broadcast paths to pass candidate `vin`.

### Registration-divergence relationship
- Classification against deterministic Phase 1E divergence: **CONTRIBUTING/UNRELATED boundary remains unresolved for primary trigger**.
- The deterministic repro’s first divergence remains `sigTime` confirmation timing (per audit with/without evidence), not duplicate-IP logic.

## GUI remediation analysis (`src/qt/createnodedialog.cpp`)

- PR #1 GUI local-list duplicate-IP hard gates were removed.
- Current behavior restored to UI validation-only (`empty`, `port-present`, `IPv4+routable`), avoiding local state as protocol gate.
- Decision: **REVERT TO v0.14.0.4-style behavior** (validation scope only).

## Keep/rewrite/revert disposition

| Logical unit | Disposition | Rationale |
|---|---|---|
| `MAX_MONEY` 21M→42M | UNKNOWN — REQUIRES MORE TESTING / DEFER | High consensus/monetary uncertainty without explicit chain evidence |
| MN duplicate-IP intent | KEEP INTENT, REIMPLEMENT SAFELY | Enforce uniqueness but avoid self/identity false positives |
| SN duplicate-IP intent | KEEP INTENT, REIMPLEMENT SAFELY | Same as MN |
| RPC duplicate-IP prechecks | KEEP INTENT, REIMPLEMENT SAFELY | Converted to identity-aware checks |
| GUI duplicate-IP precheck | REVERT TO v0.14.0.4-style validation-only | UI local-state hard gate not protocol-safe |
| Manager helper additions (`Find(const CScript&)`, score temp var) | KEEP UNCHANGED | Harmless/supporting |

## Proposed-to-implemented production change set (low-risk only)

| FILE | FUNCTION | CURRENT BEHAVIOUR (pre-remediation branch) | PROPOSED/IMPLEMENTED BEHAVIOUR | WHY | CONSENSUS | MONETARY | WIRE | WALLET | MNPoS | HISTORICAL COMPATIBILITY |
|---|---|---|---|---|---|---|---|---|---|---|
| `src/masternodeman.h/.cpp` | `IsAddressInUse` | Address-only helper primarily used | Added overload with `vin` exclusion (`addr` conflict only if `vin` differs) | Remove false positives | Low | None | None | None | Low | Low risk |
| `src/systemnodeman.h/.cpp` | `IsAddressInUse` | Address-only helper primarily used | Added overload with `vin` exclusion | Remove false positives | Low | None | None | None | Low | Low risk |
| `src/masternode.cpp` | `CheckInputsAndAdd` | Duplicate-IP reject on address-only | Identity-aware duplicate-IP reject | Preserve intent safely | Low | None | None | None | Low | Low risk |
| `src/systemnode.cpp` | `CheckInputsAndAdd` | Duplicate-IP reject on address-only | Identity-aware duplicate-IP reject | Preserve intent safely | Low | None | None | None | Low | Low risk |
| `src/rpcmasternode.cpp` | start/create/broadcast checks | Address-only duplicate-IP prechecks | Identity-aware checks with candidate `vin` | Avoid rejecting same node identity | Low | None | None | None | Low | Low risk |
| `src/rpcsystemnode.cpp` | start/create/broadcast checks | Address-only duplicate-IP prechecks | Identity-aware checks with candidate `vin` | Avoid rejecting same node identity | Low | None | None | None | Low | Low risk |
| `src/qt/createnodedialog.cpp` | `CheckIP` | UI hard-block by local duplicate-IP list | Validation-only check (no list gate) | Keep UI in UX scope, not protocol policy | None | None | None | None | None | Low risk |

## Regression test coverage

Added:
- `src/test/pr1_remediation_tests.cpp`
  - `masternode_duplicate_ip_checks_ignore_same_vin`
  - `systemnode_duplicate_ip_checks_ignore_same_vin`

Wired through:
- `src/Makefile.test.include`

Test intent:
- prove same-vin rebroadcast path is not rejected as duplicate
- prove different-vin same-address remains rejected

## With/without semantics checkpoint (A/B/C)

- **A: clean v0.14.0.4** — no PR #1 duplicate-IP policy.
- **B: historical PR #1** — duplicate-IP intent present, but with address-only over-rejection patterns.
- **C: remediated current branch** — follows **B intent** (unique IP enforcement) with safer identity-aware implementation and GUI de-scoping.

## Historical compatibility assessment

- Historical block validation changed: **NO / UNKNOWN for deferred monetary item**
- Historical transaction validation changed: **NO / UNKNOWN for deferred monetary item**
- Historical node broadcasts changed: **YES** (duplicate-IP admission policy behavior is safer/identity-aware)
- P2P serialization changed: **NO**
- Wallet format changed: **NO**
- Cryptography changed: **NO**
- Monetary totals changed: **NO** (no change made here)
- MNPoS eligibility changed: **POSSIBLE (operational admission-path effects only)**

Critical unknowns highlighted:
- `MAX_MONEY` restoration decision remains deferred pending explicit historical chain evidence.

## Runtime validation status

Planned/required validation set for this remediation:
- `pr1_remediation_tests`
- `mnpos_payment_tests` (Phase 1F guard)
- relevant RPC/serialization/staking/transaction suites where practical in CI matrix

Phase 1F preservation criteria to keep validated:
- no `nValue = -1` coinbase output path
- `GetValueOut` succeeds
- reward total remains correct

## Final PR #1 remediation table

| PR1 CHANGE | ORIGINAL INTENT | DECISION | CURRENT IMPLEMENTATION | TEST COVERAGE | RISK |
|---|---|---|---|---|---|
| `MAX_MONEY` 42M | Raise monetary ceiling | DEFER (unknown/high risk) | unchanged from current master | none added in this patch | HIGH |
| MN duplicate-IP checks | Unique IPv4 policy | KEEP INTENT, REWRITE SAFELY | identity-aware (`addr` + different `vin`) | `pr1_remediation_tests` | LOW-MEDIUM |
| SN duplicate-IP checks | Unique IPv4 policy | KEEP INTENT, REWRITE SAFELY | identity-aware (`addr` + different `vin`) | `pr1_remediation_tests` | LOW-MEDIUM |
| RPC duplicate-IP prechecks | Early conflict detection | KEEP INTENT, REWRITE SAFELY | candidate `vin` now included in checks | covered indirectly by helper tests | LOW-MEDIUM |
| Qt duplicate-IP precheck | Early UI conflict detection | REVERT | validation-only UI check | manual/behavioral; no new Qt test | LOW |
| Manager helper/refactor additions | Support duplicate-IP logic | KEEP | retained; overload added | `pr1_remediation_tests` | LOW |

## Final verdict

- PR #1 retained unchanged: **NO**
- PR #1 partially retained: **YES**
- PR #1 logic rewritten: **YES**
- PR #1 logic reverted to v0.14.0.4: **YES** (GUI duplicate-IP gate)
- Monetary behavior changed from current master: **NO**
- Consensus behavior changed from current master: **POSSIBLE** (admission policy paths only)
- Wire/P2P behavior changed: **POSSIBLE** (reject-path behavior only)
- Wallet format changed: **NO**
- Cryptographic behavior changed: **NO**
- Historical block validation changed: **UNKNOWN** (because monetary decision intentionally deferred)
- Phase 1F payment fix preserved: **YES (targeted regression expected; validate in test run)**
- Registration-divergence relationship now understood: **PARTIALLY**
- Safe to proceed to Phase 1G: **YES, with MAX_MONEY decision tracked separately as a gated/high-risk item**

## Remaining work

1. Resolve `MAX_MONEY` with explicit chain evidence and dedicated consensus-risk validation.
2. Run full 5-platform CI matrix and capture green evidence for this remediation set.
3. Extend coverage with integration-level RPC duplicate-IP tests if CI/runtime budget permits.
