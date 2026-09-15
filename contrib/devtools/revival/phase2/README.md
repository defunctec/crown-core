# Phase 2A local tooling (historical archive on user machine)

This tooling is for local execution when `crown-old-chain.7z` is not available in the cloud agent.

## Safety

- Never run `crownd` against `crown-old-chain.7z` directly.
- Keep one preserved extracted source copy.
- Use **two separate disposable copies**:
  - OFFLINE copy (no networking)
  - SYNC copy (controlled networking)
- No blockchain data is committed to Git.

## Scripts

- `phase2-prepare-working-copies.sh`
  - Verifies archive SHA256 (optional, recommended) and creates OFFLINE/SYNC disposable copies from an extracted source directory.
  - Recreates destination copy directories each run to avoid stale node state.
  - Refuses to delete non-empty destinations unless they were previously created by this tooling.
  - Verifies copied data does not share hard-linked inodes with the preserved source.
- `phase2-offline-baseline.sh`
  - Starts `crownd` with networking disabled, IPv4-only loopback RPC binding, and exports baseline JSON artifacts.
  - Also emits terminal-fork transaction/stakepointer forensics and a 90-day pre-failure stability-window analysis rooted only in the preserved archive plus local repository history.
- `phase2-controlled-sync-check.sh`
  - Starts `crownd` with `-testnet=0 -regtest=0`, IPv4-only loopback RPC binding, and inbound-disabled peer settings (`-listen=0`, `-discover=0`, `-upnp=0`). Outbound networking is intentionally enabled for continuation checks (`-dnsseed=1`, `-dns=1`) and the script may connect to normal mainnet peers.
- `phase2b-reconstruct-utxo-snapshot.sh`
  - Reconstructs chainstate exactly at the fixed provisional legacy-holder snapshot (height `5420279`, hash `8894040303b50f6f6989b65b0402bc09507a63736c3963657239cbaf6c1316ed`) using a disposable copy only, then exports deterministic full-UTXO and derived distribution artifacts.
  - Uses offline startup (`-listen=0 -dnsseed=0 -dns=0 -discover=0 -upnp=0 -maxconnections=0 -staking=0`) and fails closed if mainnet identity/snapshot identity/reconciliation checks fail.
  - Uses the `exportutxosnapshot` RPC to iterate the authoritative chainstate database through Crown's native serialization/deserialization logic (no custom consensus reimplementation).
- `phase2b-analyze-utxo-snapshot.sh`
  - Post-processing only: reads existing `phase2b-utxos.jsonl` and compact evidence files, with no daemon/RPC requirement and no chainstate mutation.
  - Streams JSONL line-by-line, validates parseability, recomputes totals in integer satoshis, and fails closed on reconciliation mismatch.
  - Produces standalone aggregation/distribution artifacts so Phase 2B analysis can be rerun independently of rewind/export.
  - Accepts optional `--raw-export-commit <git_commit>` so historical datasets can explicitly record the raw-export audit binary commit without regenerating the UTXO export.
- `phase2c-classify-economic-balances.sh`
  - Post-processing only: consumes existing `phase2b-*` artifacts and produces Phase 2C classification outputs without daemon start, rewind, or re-export.
  - Verifies fixed Phase 2B provenance/constants (archive SHA256, raw-export commit, UTXO JSONL SHA256, snapshot totals/entity counts, and raw 500/10,000 collateral counts) before classification.
  - Emits confidence-tagged per-entity classifications and dedicated reports for collateral concentration, top balances, node-collateral interpretation, exchange/custody findings, wrapped-reserve analysis, control entities, and final summary.
  - Supports optional evidence overrides (`--attribution-json`) for evidence-backed exchange/custody, wrapped, and control-entity attribution; defaults to `unknown` when evidence is absent.
- `phase2c-attribution-overrides.example.json`
  - Example schema for optional `--attribution-json` evidence input used by Phase 2C classification.

Both runtime scripts reject datadirs whose `crown.conf` contains explicit chain-selection settings (`testnet=...`, `regtest=...`, `devnet=...`, `chain=...`, or network section headers).
`-devnet=0` is intentionally **not** used: in this Crown codebase, `-devnet` is a named-network selector, so `-devnet=0` selects/creates devnet `0` instead of disabling devnet.
Both runtime scripts also require the `phase2-working-copy.json` marker written by `phase2-prepare-working-copies.sh`.
Both runtime scripts auto-provision disposable local RPC credentials (`phase2-rpc-user` / `phase2-rpc-password`) in the working copy when missing, so startup does not depend on pre-existing `rpcpassword` in `crown.conf`.
When `--outdir` is omitted, each runtime script writes to a sibling directory outside the datadir.

## Windows support

- **Native Windows:** not supported by these scripts as-is (they are Bash scripts).
- **WSL:** required/recommended for running these scripts.
- `crownd` and `crown-cli` binaries are required and must be runnable from WSL (`BIN_DIR`, or `CROWND_BIN`/`CROWNCLI_BIN`).

## Local run commands (WSL)

Assume:
- preserved archive: `C:\crown\crown-old-chain.7z`
- preserved extracted source directory: `C:\crown\preserved-extract` containing `blocks/` and `chainstate/`
- disposable work root: `C:\crown\phase2-work`

In WSL these paths are typically:
- `/mnt/c/crown/crown-old-chain.7z`
- `/mnt/c/crown/preserved-extract`
- `/mnt/c/crown/phase2-work`

```bash
cd /home/runner/work/crown-core/crown-core

# 1) Prepare two disposable working copies (recommended SHA check included)
contrib/devtools/revival/phase2/phase2-prepare-working-copies.sh \
  --archive-file /mnt/c/crown/crown-old-chain.7z \
  --source-dir /mnt/c/crown/preserved-extract \
  --offline-dir /mnt/c/crown/phase2-work/offline-copy \
  --sync-dir /mnt/c/crown/phase2-work/sync-copy

# 2) OFFLINE baseline (network disabled)
contrib/devtools/revival/phase2/phase2-offline-baseline.sh \
  --datadir /mnt/c/crown/phase2-work/offline-copy \
  --outdir /mnt/c/crown/phase2-work/offline-output

# 3) Controlled sync check (separate disposable copy)
contrib/devtools/revival/phase2/phase2-controlled-sync-check.sh \
  --datadir /mnt/c/crown/phase2-work/sync-copy \
  --outdir /mnt/c/crown/phase2-work/sync-output

# 4) Phase 2B snapshot UTXO reconstruction/export (disposable OFFLINE copy only)
contrib/devtools/revival/phase2/phase2b-reconstruct-utxo-snapshot.sh \
  --datadir /mnt/c/crown/phase2-work/offline-copy \
  --outdir /mnt/c/crown/phase2-work/phase2b-output

# 5) Phase 2B post-processing rerun (no daemon, no rewind, no re-export)
contrib/devtools/revival/phase2/phase2b-analyze-utxo-snapshot.sh \
  --input /mnt/c/crown/phase2-work/phase2b-output/phase2b-utxos.jsonl \
  --evidence-dir /mnt/c/crown/phase2-work/phase2b-output \
  --outdir /mnt/c/crown/phase2-work/phase2b-output \
  --raw-export-commit 516e2eb694cb73c9b14fcbff2eaf02d8a47329a3

# 6) Phase 2C economic-balance classification (post-processing only)
contrib/devtools/revival/phase2/phase2c-classify-economic-balances.sh \
  --balances-jsonl /mnt/c/crown/phase2-work/phase2b-output/phase2b-address-script-balances.jsonl \
  --distribution-json /mnt/c/crown/phase2-work/phase2b-output/phase2b-distribution-summary.json \
  --metadata-json /mnt/c/crown/phase2-work/phase2b-output/phase2b-snapshot-metadata.json \
  --audit-json /mnt/c/crown/phase2-work/phase2b-output/phase2b-reconstruction-audit.json \
  --attribution-json /home/runner/work/crown-core/crown-core/contrib/devtools/revival/phase2/phase2c-attribution-overrides.example.json \
  --outdir /mnt/c/crown/phase2-work/phase2c-output
```

## Expected output files

OFFLINE output directory:
- `phase2-chain-baseline.json`
- `phase2-utxo-summary.json`
- `phase2-checkpoint-verification.json`
- `phase2-fork-analysis.json`
- `phase2-fork-history-evidence.json`
- `phase2-terminal-fork-forensics.json`
- `phase2-stability-window-analysis.json`
- `phase2-fork-blocks/` (divergent-branch block JSON exports when available)
- supporting captures (`blockchaininfo.json`, `tip-block.json`, etc.)

`phase2-terminal-fork-forensics.json` records, for the selected active/valid-fork terminal pair:
- raw/decoded transactions for the terminal divergent blocks
- staking source outpoints and referenced stake-source transactions/vouts
- raw block-signature and serialized stakepointer fields not exposed by `getblock`
- reward/payment structure comparisons between the competing branches
- source-backed closeout findings for ordinary stakepointer validity, systemnode payment enforcement behavior, and equal-chainwork branch selection

`phase2-stability-window-analysis.json` summarizes the 90 days before `2025-08-19` and reports:
- active-chain block cadence and long-gap/stall candidates
- competing branch activity, fork depths, and reconstructable reorg indicators
- snapshot candidates around `2025-08-01`, `2025-07-01`, and the latest pre-instability point suggested by the preserved archive evidence
- for each candidate, both the requested cutoff UTC and the resolved last-active-chain block at or before that cutoff, so stalled periods do not produce misleading same-day labels

## Provisional revival snapshot decision

The provisional legacy-holder revival snapshot is fixed at:

- date rule: **last active-chain block at or before `2025-07-01T23:59:59Z`**
- resolved block height: **`5420279`**
- resolved block hash: **`8894040303b50f6f6989b65b0402bc09507a63736c3963657239cbaf6c1316ed`**
- resolved block timestamp: **`2025-07-01T23:59:24Z`**

Reason:

- lies on uncontested active ancestry
- no detected competing forks in the surrounding audit window
- no nearby long-block-gap anomaly
- active-chain production around this period was normal
- materially predates the late-July/August degradation, prolonged stalls, terminal equal-chainwork fork, and later emergency stakepointer recovery work

Important distinction:

- this snapshot defines the **provisional economic/holder entitlement reference point only**
- it does **not** truncate historical chain recovery at that height
- it does **not** declare later historical blocks invalid
- it does **not** choose either terminal August fork as canonical
- it does **not** by itself determine eligible addresses or UTXOs

Follow-on scope:

- **Phase 2B** reconstructs the UTXO/holder distribution at exactly height `5420279`
- **Phase 2C** classifies masternode/systemnode collateral, treasury/project-controlled funds, known exchange/custody holdings, wrapped-CRW reserve/custody UTXOs, and other special categories needed to prevent double entitlement

## Phase 2A final findings

- **Canonical official historical source baseline:** `3050c1f970e6dc4713c41a88f80638c597af33e9` / Crown Core `v0.14.0.4` remains the historical code baseline for analysis.
- **Preserved archive provenance:** the archive is a local preserved node state used as evidence, not an authority above production source rules.
- **Healthy chain through the provisional July 1 snapshot:** the selected holder-reference block at height `5420279` lies on uncontested active ancestry before the later instability window.
- **Late-July/August operational degradation:** the preserved archive shows later stalls, instability, and a terminal two-block fork near the August endpoint.
- **Unresolved terminal equal-chainwork fork:** the terminal branch pair has equal accumulated chainwork, so the archive's current `active` label proves only what this preserved node last persisted as best, not an objective fork winner.
- **Ordinary stakepointer validity:** mainnet source sets `ValidStakePointerDuration()` to `4320` and `MaxReorganizationDepth()` to `100`, so ordinary stakepointer ages are valid on an inclusive `100..4320` block window. The recorded terminal ages (`1576`, `1671`, `101`, `101`) all satisfy that window.
- **Systemnode payment difference:** PoS-era source expects normal non-superblock templates to place masternode payment in `coinbase.vout[1]` and systemnode payment in `coinbase.vout[2]` when a payee is known, but consensus rejection of a missing systemnode payment depends on sync completion, winner-vote availability, stall status, and `SPORK_14_SYSTEMNODE_PAYMENT_ENFORCEMENT`. The payment mismatch therefore does not by itself choose a fork winner or prove the competing branch invalid.
- **Later emergency stakepointer code history:** later `v0.14.0.7` branch history added emergency stakepointer options, but those later recovery changes do not change the settled Phase 2A snapshot decision.
- **Provisional holder snapshot remains fixed:** height `5420279`, hash `8894040303b50f6f6989b65b0402bc09507a63736c3963657239cbaf6c1316ed`, timestamp `2025-07-01T23:59:24Z`.
- **Terminal-fork findings do not affect entitlement height:** Phase 2A keeps the provisional holder reference point at `5420279`; resolving the later equal-work terminal fork is not required to begin holder reconstruction at that earlier height.

SYNC output directory:
- `phase2-sync-result.json`
- `phase2-peer-summary.json`
- supporting captures (`sync-polls.json`, `final-peerinfo.json`, etc.)

Phase 2B output directory:
- `phase2b-snapshot-metadata.json`
- `phase2b-reconstruction-audit.json`
- `phase2b-utxos.jsonl` (authoritative raw UTXO export; one JSON object per txid:vout)
- `phase2b-utxos.csv`
- `phase2b-address-script-balances.csv`
- `phase2b-address-script-balances.jsonl`
- `phase2b-distribution-summary.json`
- supporting captures (`blockchaininfo-after-reconstruction.json`, `txoutsetinfo-after-reconstruction.json`, `snapshot-block.json`, `chaintips-after-reconstruction.json`, `exportutxosnapshot-result.json`)

Phase 2C output directory:
- `phase2c-classification-registry.json`
- `phase2c-collateral-concentration.json`
- `phase2c-top-balances-report.json`
- `phase2c-node-collateral-analysis.json`
- `phase2c-exchange-custody-analysis.json`
- `phase2c-wrapped-crown-analysis.json`
- `phase2c-control-entities.json`
- `phase2c-summary.json`

Phase 2B provenance fields include:
- snapshot height/hash/timestamp/chainwork
- archive SHA256
- `raw_export.audit_binary_git_commit`
- `raw_export.utxo_jsonl_sha256`
- `post_processing.tooling_git_commit`
- reconstruction method detail
- generation timestamp
- reconciliation result and artifact SHA256 hashes

## Archive integrity reference

Expected archive SHA256 for `crown-old-chain.7z`:

`56EFDB665EF04F6AC21D218388A92471DBCB827332DCD6501872D319998FC3D0`

## Version and source provenance

- Canonical historical baseline commit: `3050c1f970e6dc4713c41a88f80638c597af33e9`
- Canonical historical release identity: **Crown Core v0.14.0.4**
- At `3050c1f...`, `configure.ac` defines:
  - `_CLIENT_VERSION_MAJOR=0`
  - `_CLIENT_VERSION_MINOR=14`
  - `_CLIENT_VERSION_REVISION=0`
  - `_CLIENT_VERSION_BUILD=4`
- At the same commit, `src/clientversion.h` fallback metadata still has `CLIENT_VERSION_BUILD 3`.
- `src/clientversion.h` uses `config/crown-config.h` when `HAVE_CONFIG_H` is set, so normal Autotools-configured builds derive build `4` from `configure.ac`; the fallback `3` is stale metadata and is **not** evidence of a canonical `v0.14.0.3` release.

Current Phase 2A/revival branch provenance:

- Record current audit/build provenance from the local repository at runtime (`git rev-parse HEAD`) and local binary version output (`crownd --version` / `crown-cli --version`) instead of relying on static README hashes.
- Current local binaries on this branch identify as `v0.14.0.7` plus the current Git revision.
- `v0.14.0.7` on this branch is later development ancestry, introduced by:
  - `361f5c574aff8de59e52f403d715986b53e6e355` (30 Aug 2025, "Added compiler switch EMERGENCY_STAKEPOINTERS...")
  - This commit changed build metadata in both `configure.ac` and `src/clientversion.h` (`6 -> 7`) and also included production-code changes in staking/wallet/masternode/systemnode/version-related areas.

Interpretation for Phase 2A:

- `v0.14.0.4` at `3050c1f...` remains the canonical historical baseline.
- `v0.14.0.7` is **not** being treated as the canonical historical release.
- This Phase 2A branch currently inherits `v0.14.0.7` metadata from later development.
- No version rollback/rewrite is performed here; a deliberate revival versioning scheme will be chosen before release/public binaries.

Local build-validation provenance:

- Modern WSL local validation completed full pinned `depends` build successfully after the Phase 2A compatibility fixes.
- Working local `crownd` and `crown-cli` binaries were produced from that pinned-depends toolchain.
