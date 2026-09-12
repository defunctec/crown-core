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
  - Preserves hard links while copying block/chainstate data.
- `phase2-offline-baseline.sh`
  - Starts `crownd` with networking disabled, loopback-only RPC binding, and exports baseline JSON artifacts.
- `phase2-controlled-sync-check.sh`
  - Starts `crownd` in explicit mainnet mode with loopback-only RPC binding and inbound-disabled peer settings (`listen=0`, `upnp=0`), with outbound peer discovery explicitly enabled (`discover=1`, `dnsseed=1`).

Both runtime scripts reject datadirs whose `crown.conf` explicitly enables non-mainnet mode (`testnet=1`, `regtest=1`, or non-zero `devnet`).
Both runtime scripts also require the `phase2-working-copy.json` marker written by `phase2-prepare-working-copies.sh`.
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
- supporting captures (`blockchaininfo.json`, `tip-block.json`, etc.)

SYNC output directory:
- `phase2-sync-result.json`
- `phase2-peer-summary.json`
- supporting captures (`sync-polls.json`, `final-peerinfo.json`, etc.)

## Archive integrity reference

Expected archive SHA256 for `crown-old-chain.7z`:

`56EFDB665EF04F6AC21D218388A92471DBCB827332DCD6501872D319998FC3D0`
