# Phase 2A local tooling

These scripts prepare **local** analysis of historical Crown data when the archive is not in the cloud environment.

## Safety model

- Never run on `crown-old-chain.7z` directly.
- Extract once to a preserved source location.
- Create **two separate disposable copies** containing `blocks/` and `chainstate/`:
  - one for offline baseline
  - one for controlled sync check

## Scripts

- `phase2-offline-baseline.sh`
  - Starts `crownd` with networking disabled.
  - Exports:
    - `phase2-chain-baseline.json`
    - `phase2-utxo-summary.json`
    - `phase2-checkpoint-verification.json`
- `phase2-controlled-sync-check.sh`
  - Starts `crownd` with normal networking.
  - Exports:
    - `phase2-sync-result.json`
    - `phase2-peer-summary.json`

Both scripts require a datadir argument that points to a disposable working copy.
