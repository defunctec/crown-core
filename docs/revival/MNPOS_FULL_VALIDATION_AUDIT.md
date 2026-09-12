# Crown Revival — Phase 1H/1I Full MNPoS Private-Network Validation Audit (Final)

## Scope and constraints

Phase 1H/1I remained a validation/audit effort only.
No production consensus, monetary policy, collateral amounts, reward schedules, or confirmation requirements were changed.

## Regtest-only override isolation proof (source + tests)

### Source isolation

Regtest-only override handling is confined to `CRegTestParams` and executed only when selecting `REGTEST`:

- `CRegTestParams::UpdateSubsidyHalvingIntervalFromArgs` (`-regtestsubsidyhalvinginterval`) in `src/chainparams.cpp:613-626`
- `CRegTestParams::UpdatePoSStartHeightFromArgs` (`-regtestposstartheight`) in `src/chainparams.cpp:628-641`
- `SelectParams` now selects base params first, then applies overrides only inside `if (network == CBaseChainParams::REGTEST)` in `src/chainparams.cpp:745-757`

Mainnet/testnet values remain defined in their own parameter classes and are not modified by these regtest-only paths.

### Test proof

`src/test/phase1i_profile_tests.cpp` covers:

- Mainnet/testnet production constants unchanged (`production_rules_unchanged`)
- Regtest override behavior and reset behavior (`regtest_fast_profile_overrides_are_regtest_only`)
- Invalid override rejection (`0`, `2147483648`) and explicit mainnet/testnet isolation while override args are present (`regtest_override_validation_and_isolation`)

## Phase 1I final runtime outcomes (already completed)

Fresh fast runs completed 3/3 PASS with no code changes between successful runs:

| Run | Runtime | Final fixed target height | Final fixed target hash | Result |
| --- | ---: | ---: | --- | --- |
| 1 | 98s | 1223 | `922a9de1d11e19635e6da7ab19ecbd5b1bb49cdfea5d43dc671bc68e5d044e47` | PASS |
| 2 | 102s | 1222 | `063fd6fd695e82258c241a69eee77daabdd3a6b915571d7563af6014b7c6b203` | PASS |
| 3 | 219s | 1228 | `5f807d470791251f258c63f3110c627876722085e8cb9ad8050e70964b71a687` | PASS |

For each run, `ctl`, `mn1`, `sn1`, and `obs` converged to identical fixed final height/hash before acceptance.

## Required validation points

- Genuine `10,000 CRW` masternode collateral achieved: **YES**
- Masternode + systemnode registration successful: **YES**
- Accelerated MNPoS activation successful: **YES**
- Post-activation blocks/payments validated: **YES**
- Original moving-tip convergence bug observed and documented: **YES**
- Incorrect `setmocktime 0` quiesce behavior identified (restores wall clock, does not disable staking): **YES**
- Final source-backed quiesce used: **YES**
  - Stage 10 now sets staking daemons (`ctl`, `mn1`, `sn1`) to per-node `tip_time - 1` mocktime (two passes) in `contrib/devtools/revival/phase1i-regtest-mn-collateral-bootstrap.sh:240-258`
  - Stationary precondition required before target capture in `contrib/devtools/revival/phase1i-regtest-mn-collateral-bootstrap.sh:800-819`

## Review-comment resolution (Phase 1I-related only)

Addressed valid outstanding comments related to this phase:

1. **Regtest override selection ordering**
   - Fixed by moving `SelectBaseParams(network)` before regtest override arg reads.
2. **Missing invalid override tests**
   - Added invalid-range rejection test coverage for both regtest overrides.
3. **Stage 10 quiesce behavior**
   - Replaced `setmocktime 0` stopping assumption with past-mocktime quiesce mechanism.

## Final determination

- Production consensus changed: **NO**
- Phase 1I fixed-target convergence acceptance: **PASS**
- Phase 1H/1I final validation status: **COMPLETE**
