# Crown CI Build Performance

This document records the CI/build-only optimisation work for Crown's GitHub Actions matrix without changing Crown production behaviour, dependency versions, or platform coverage.

## Matrix retained

The required matrix remains:

| Workflow target | Host triplet | Runner/container |
| --- | --- | --- |
| Linux x86_64 | `x86_64-unknown-linux` | `ubuntu-latest` + `ubuntu:focal` |
| Linux i686 | `i686-pc-linux-gnu` | `ubuntu-latest` + `ubuntu:focal` |
| Windows x86_64 | `x86_64-w64-mingw32` | `ubuntu-latest` + `ubuntu:focal` |
| Windows i686 | `i686-w64-mingw32` | `ubuntu-latest` + `ubuntu:focal` |
| ARM / Raspberry Pi | `arm-linux-gnueabihf` | `ubuntu-latest` + `ubuntu:focal` |

## Original bottlenecks

Baseline timings were taken from GitHub Actions workflow run `34607908566` (attempt 2) before this optimisation change.

| Target | Status | Total | Runner/package setup | Depends step | Crown configure/build/install | Tests | Artifact upload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Linux x86_64 | success | ~40m 26s | ~15m 51s | ~16m 14s | ~7m 56s | no separate test execution | ~5s |
| Linux i686 | success | ~30m 36s | ~12m 13s | ~12m 06s | ~5m 56s | no separate test execution | ~5s |
| Windows x86_64 | success | ~43m 23s | ~17m 41s | ~16m 06s | ~9m 13s | no separate test execution | ~5s |
| Windows i686 | success | ~42m 54s | ~18m 49s | ~14m 30s | ~9m 18s | no separate test execution | ~5s |
| ARM / Raspberry Pi | success | ~12m 09s | ~1m 53s | ~4m 25s | ~5m 32s | no separate test execution | ~2s |

Largest bottleneck:

- overall: runner/package setup for the heavier x86/x64 lanes
- build-specific: repeated depends work
- cache-specific root cause: the old depends cache key included `src/**`, so unrelated Crown source edits invalidated depends cache reuse

## Changes made

### 1. Depends source archive cache

Added a dedicated cache for downloaded dependency archives:

- `depends/sources`
- `depends/sdk-sources`

Key:

```text
crown-depends-sources-${DEPENDS_CACHE_VERSION}-${host}-${depends_recipe_hash}
```

Where `depends_recipe_hash` is based only on depends definition inputs:

- `depends/Makefile`
- `depends/funcs.mk`
- `depends/config.site.in`
- `depends/builders/**`
- `depends/hosts/**`
- `depends/packages/**`
- `depends/patches/**`

This keeps unrelated `.cpp` changes from invalidating Boost/OpenSSL/Berkeley DB source downloads.

### 2. Built depends/prefix cache

Added a separate cache for compiled depends outputs:

- `depends/built/${host}`
- `depends/${host}`

Key:

```text
crown-depends-prefix-${DEPENDS_CACHE_VERSION}-${runner_os}-${container_id}-${host}-${packages_id}-${dep_opts_id}-${build_toolchain_id}-${host_toolchain_id}-${depends_recipe_hash}
```

Safety properties:

- isolated per target host
- isolated by container identity
- isolated by package-install set
- isolated by depends option set
- isolated by build-toolchain identity
- isolated by host-toolchain identity
- invalidated whenever relevant files under `depends/` change

The toolchain identities are generated with `depends/gen_id`, so stale incompatible compiled caches do not silently cross architectures or compiler changes.

### 3. ccache

Added `ccache` installation and per-target cache persistence:

- cache path: `.ccache/${host}`
- key:

```text
crown-ccache-${CCACHE_CACHE_VERSION}-${runner_os}-${container_id}-${host}-${host_toolchain_id}-${crown_build_hash}
```

`crown_build_hash` is based on:

- `configure.ac`
- `Makefile.am`
- `src/**`
- `qt/**`
- `share/**`
- `depends/config.site.in`

Configuration used:

- `CCACHE_DIR=$GITHUB_WORKSPACE/.ccache/${host}`
- `CCACHE_BASEDIR=$GITHUB_WORKSPACE`
- `CCACHE_COMPILERCHECK=content`
- `CCACHE_MAXSIZE=750M`
- `/usr/lib/ccache:/usr/lib64/ccache` prepended to `PATH`

The wrapper `PATH` update is applied immediately before the Crown build so the ccache statistics reflect Crown compilation rather than the depends package build.

Each build now:

- restores the ccache directory
- zeroes stats before compilation
- prints `ccache --show-stats --verbose` at the end
- writes cache status and ccache stats into the GitHub Actions job summary

This preserves normal compiler failures; `ccache` only wraps compiler invocation.

### 4. Parallelism

Replaced the fixed `-j4` with:

```bash
MAKEJOBS=-j$(nproc)
```

The selected job count is recorded in logs and the job summary as:

- `MAKEJOBS`
- `BUILD_JOBS=$(nproc)`

This improves Crown compilation parallelism while still using the runner's visible CPU count rather than hardcoding a larger unsafe value.

## Cache effectiveness reporting

Each matrix job now reports:

- depends source cache hit/miss
- built depends cache hit/miss
- ccache restore hit/miss
- chosen `MAKEJOBS`
- end-of-build ccache statistics

## Cold and warm expectations

### Cold run

Observed effective-cold baseline before this change:

- depends sources: miss
- built depends cache: effectively invalidated by Crown source tree changes
- ccache: not present
- total duration: see baseline table above

### Warm run

Expected behaviour for a repeat run with matching host/toolchain/depends definitions:

- depends source cache: hit
- built depends cache: hit
- ccache: hit

Expected impact:

- source archive download should drop to near-zero
- depends should avoid needless rebuild/repack work when the cached `${host}` prefix and built tarballs match
- repeated Crown C/C++ compilations should show ccache hits and materially lower compile time

Warm timings were not directly re-measured inside this task run, so the first post-change warmed workflow run should be used as the acceptance measurement.

## Incremental agent/developer build guidance

For a clean validation:

```bash
./autogen.sh
./configure ...
make ...
```

For subsequent small changes in the same environment:

- do **not** automatically run `make clean`
- prefer incremental targets when only a subset changed

Examples:

```bash
make -C src -j$(nproc) crownd crown-cli crown-tx
```

```bash
make -C src -j$(nproc) crown_test
```

Only perform a clean/full rebuild when needed for final acceptance or when build-system inputs changed enough to justify it.

## Matrix results

Current measured pre-change matrix baseline from run `34607908566`:

| Target | Result |
| --- | --- |
| Linux x86_64 | success |
| Linux i686 | success |
| Windows x86_64 | success |
| Windows i686 | success |
| ARM / Raspberry Pi | success |

## Known limitations

- `apt-get update` / `apt-get install` still dominate several lanes and are not solved by depends/ccache alone.
- The workflow still does not have a separate explicit test-execution step; the baseline and optimisation preserve that existing behaviour.
- First runs after cache-version or depends-definition changes remain cold by design.
- GitHub Actions cache eviction policy can remove warm caches between runs.
