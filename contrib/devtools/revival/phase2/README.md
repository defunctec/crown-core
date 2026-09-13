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

`phase2-stability-window-analysis.json` summarizes the 90 days before `2025-08-19` and reports:
- active-chain block cadence and long-gap/stall candidates
- competing branch activity, fork depths, and reconstructable reorg indicators
- snapshot candidates around `2025-08-01`, `2025-07-01`, and the latest pre-instability point suggested by the preserved archive evidence

SYNC output directory:
- `phase2-sync-result.json`
- `phase2-peer-summary.json`
- supporting captures (`sync-polls.json`, `final-peerinfo.json`, etc.)

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
