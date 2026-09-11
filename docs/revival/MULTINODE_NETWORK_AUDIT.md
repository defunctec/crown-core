# Crown Revival — Phase 1C Multinode Network Audit

This document records **executed** three-node private-network validation on the recovered Crown `master` baseline. All runtime claims below were produced by actually building Crown, starting three independent `crownd` processes, and exercising them on isolated loopback-only `regtest` data directories under `/tmp`.

Repository working tree for all commands: `/home/runner/work/crown-core/crown-core`

## 1. Starting baseline

| Item | Value |
| --- | --- |
| Copilot task branch | `copilot/crown-revival-phase-1c` |
| Exact task HEAD SHA | `b8b2bf65fd184c418cebd22422b0a233a660773d` |
| Starting `master` SHA | `b8b2bf65fd184c418cebd22422b0a233a660773d` |
| Historical baseline explicitly **not** used | `6a60c10a0e8f53ede56c3598bbe3370c61dc11ec` |
| Git status before starting | `## copilot/crown-revival-phase-1c...origin/copilot/crown-revival-phase-1c` |
| Operating system | `Ubuntu 24.04.4 LTS` |
| Kernel | `Linux 6.17.0-1022-azure x86_64 GNU/Linux` |
| Compiler | `gcc 13.3.0`, `g++ 13.3.0` |
| OpenSSL | `OpenSSL 3.0.13 30 Jan 2024` |
| Boost at initial capture | `libboost-all-dev` not installed |
| Boost used for the recovered build | `libboost-all-dev 1.83.0.1ubuntu2` |
| Berkeley DB C++ dev package used for the recovered build | `libdb++-dev 1:5.3.21ubuntu2` |
| cURL dev package used for the recovered build | `libcurl4-openssl-dev 8.5.0-2ubuntu10.13` |
| `crownd --version` | `Crown Core Daemon version v0.14.0.7-b8b2bf6` |
| `crown-cli --version` | `Crown Core RPC client version v0.14.0.7-b8b2bf6` |
| Configure flags | `./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui` |
| Build flags | `make -C src -j4 crownd crown-cli crown-tx` |

Recovered documentation confirmed present before runtime work:

- `docs/revival/RECOVERY_BASELINE.md`
- `docs/revival/TEST_RECOVERY_AUDIT.md`
- `docs/revival/CONSOLIDATION_REPORT.md`
- `docs/revival/CODEBASE_AUDIT_RECONSTRUCTED.md`

This task therefore started from the already recovered and merged `master` baseline, not from the historical pre-recovery tree.

## 2. Build execution

### 2.1 Commands executed

```bash
cd /home/runner/work/crown-core/crown-core
./autogen.sh
./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui
make -C src -j4 crownd crown-cli crown-tx
```

### 2.2 First configure attempt on the fresh runner

The first direct Phase 1C `./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui` attempt failed before any package installation with missing Berkeley DB C++ headers:

```text
configure: error: libdb_cxx headers missing
```

Exit status: `1`

This was documented before any further build action, per task instructions.

### 2.3 Host package preparation actually executed

```bash
sudo apt-get update
sudo apt-get install -y libdb++-dev libboost-all-dev libcurl4-openssl-dev
```

### 2.4 Recovered build results

| Command | Exit status | Result |
| --- | --- | --- |
| `./autogen.sh` | `0` | Succeeded |
| `./configure --with-incompatible-bdb --with-unsupported-ssl --without-gui` | `0` | Succeeded after installing required host packages |
| `make -C src -j4 crownd crown-cli crown-tx` | `0` | Succeeded |

Resulting binaries:

- `/home/runner/work/crown-core/crown-core/src/crownd`
- `/home/runner/work/crown-core/crown-core/src/crown-cli`
- `/home/runner/work/crown-core/crown-core/src/crown-tx`

## 3. Execution model

**Execution model used:** `NATIVE`

**Reason:** Three localhost `crownd` processes matched the preferred model and provided sufficient isolation without introducing Docker-specific variables. Docker was available on the runner (`Docker version 28.0.4`) but was not needed.

Private runtime layout actually used:

| Node | Datadir | P2P port | RPC port | Bind scope |
| --- | --- | --- | --- | --- |
| A | `/tmp/crown-phase1c/network3/nodeA` | `23918` | `26918` | `127.0.0.1` only |
| B | `/tmp/crown-phase1c/network3/nodeB` | `23919` | `26919` | `127.0.0.1` only |
| C | `/tmp/crown-phase1c/network3/nodeC` | `23920` | `26920` | `127.0.0.1` only |

All three nodes ran with disposable `regtest` data, disposable RPC credentials, no public seed usage, no public peer connections, and no existing user datadirs.

## 4. Node bring-up and peer topology

Nodes were started independently and connected over loopback. The stable topology used for the runtime checks was a three-node private network with node C acting as a relay hub:

- node A outbound peer: `127.0.0.1:23920`
- node B outbound peer: `127.0.0.1:23920`
- node C inbound peers from both node A and node B

Representative `getpeerinfo` evidence after bring-up:

```json
// node A
[
  {
    "addr": "127.0.0.1:23920",
    "version": 70062,
    "subver": "/Crown Core:0.14.0.7/",
    "inbound": false
  }
]
```

```json
// node B
[
  {
    "addr": "127.0.0.1:23920",
    "version": 70062,
    "subver": "/Crown Core:0.14.0.7/",
    "inbound": false
  }
]
```

```json
// node C
[
  {
    "addr": "127.0.0.1:35872",
    "version": 70062,
    "subver": "/Crown Core:0.14.0.7/",
    "inbound": true
  },
  {
    "addr": "127.0.0.1:35876",
    "version": 70062,
    "subver": "/Crown Core:0.14.0.7/",
    "inbound": true
  }
]
```

No public IPs or non-loopback peers appeared in the captured peer data.

## 5. Block propagation validation

### 5.1 Initial mining

Executed command on node A:

```bash
./src/crown-cli -datadir=/tmp/crown-phase1c/network3/nodeA -rpcuser=rt -rpcpassword=phase1c-temp-pass setgenerate true 101
```

Observed convergence:

- node A block height: `101`
- node B block height: `101`
- node C block height: `101`
- shared best block hash: `1ae68c0ba6ab525de74f672717aa0ade99ae1d1f367476a296e5cfd5702811f4`
- measured sync window in the harness: `~1.404s`

Representative `getblockchaininfo` after the 101-block generation:

```json
{
  "chain": "regtest",
  "blocks": 101,
  "headers": 101,
  "bestblockhash": "1ae68c0ba6ab525de74f672717aa0ade99ae1d1f367476a296e5cfd5702811f4",
  "difficulty": 0.0,
  "verificationprogress": 1.0
}
```

Notable runtime observation: after 101 blocks, node A exposed one mature spendable UTXO of `12.0` CRW rather than a 50-coin subsidy:

```json
[
  {
    "txid": "d766aefc5d6c1874afcbb852322f84c8e84fa78293c8f3f59cc114e3b8361723",
    "vout": 0,
    "address": "tCRWU4wtgrtDEpfNcEgRXYn7TC8SUbF97Hhyh",
    "scriptPubKey": "21026c44941fa8dcd49ff769f5568b04d59953ea31428042f71893135ba662d6f429ac",
    "amount": 12.0,
    "confirmations": 101,
    "spendable": true
  }
]
```

## 6. Runtime limitation discovered during wallet-address testing

A direct address-based wallet send path could **not** be validated on `regtest` because wallet-generated `tCRW...` addresses were rejected by the node's own address validator and send RPC.

Executed probe:

```bash
ADDR=$(./src/crown-cli -datadir=/tmp/crown-phase1c/addressprobe -rpcuser=rt -rpcpassword=phase1c-temp-pass getnewaddress)
./src/crown-cli -datadir=/tmp/crown-phase1c/addressprobe -rpcuser=rt -rpcpassword=phase1c-temp-pass validateaddress "$ADDR"
./src/crown-cli -datadir=/tmp/crown-phase1c/addressprobe -rpcuser=rt -rpcpassword=phase1c-temp-pass sendtoaddress "$ADDR" 1.0
```

Observed result:

```text
tCRWFdNmfzd4CDdzLwSo2nwbCZr1yKWZmoyEr
{
    "isvalid" : false
}
error: {"code":-5,"message":"Invalid Crown address"}
```

`sendtoaddress` exit status: `5`

This is an existing runtime limitation on the recovered codebase; no source change was made to alter address logic or consensus behaviour.

## 7. Transaction and mempool propagation validation

Because the standard `sendtoaddress` path failed on `regtest`, the private-network propagation check used wallet-signed raw transactions directed to the intended recipient key hashes, with no production source modification.

### 7.1 Transaction 1: node A -> node B

- amount: `1.0` CRW
- txid: `a935d6dcd79e8d378398f4fa402cf41826c8b18413449c236905754e72be5cce`
- measured propagation to all three mempools: `~0.496s`

Observed mempool state on all three nodes before confirmation:

```json
[
  "a935d6dcd79e8d378398f4fa402cf41826c8b18413449c236905754e72be5cce"
]
```

Node C then mined one block:

```bash
./src/crown-cli -datadir=/tmp/crown-phase1c/network3/nodeC -rpcuser=rt -rpcpassword=phase1c-temp-pass setgenerate true 1
```

Post-confirmation state:

- shared height: `102`
- shared best block hash: `3566ee33cb20bf3253c62e902e9d562b1642209cb0f35fe2796ad0f9aec69615`
- receiver-side `gettransaction` on node B showed a `receive` entry for `1.0` CRW with `1` confirmation

### 7.2 Transaction 2: node B -> node C

- amount: `0.5` CRW
- txid: `2453d72eabb250794f7acc6390820c5443d07698384d5cda8161cd7bb133b931`
- measured propagation to all three mempools: `~0.264s`

Observed mempool state on all three nodes before confirmation:

```json
[
  "2453d72eabb250794f7acc6390820c5443d07698384d5cda8161cd7bb133b931"
]
```

Node A then mined one block:

```bash
./src/crown-cli -datadir=/tmp/crown-phase1c/network3/nodeA -rpcuser=rt -rpcpassword=phase1c-temp-pass setgenerate true 1
```

Post-confirmation state:

- shared height: `103`
- shared best block hash: `6919d3876862fa172d2ddae03d54a6ba79316aeeac71c35b9652cbfcafd3a125`
- receiver-side `gettransaction` on node C showed a `receive` entry for `0.5` CRW with `1` confirmation

Wallet balances after the second confirmation:

- node A: `34.99990000`
- node B: `0.49990000`
- node C: `0.50000000`

## 8. Restart and resynchronization validation

### 8.1 Stop node B, advance chain, restart node B

Executed sequence:

```bash
./src/crown-cli -datadir=/tmp/crown-phase1c/network3/nodeB -rpcuser=rt -rpcpassword=phase1c-temp-pass stop
./src/crown-cli -datadir=/tmp/crown-phase1c/network3/nodeA -rpcuser=rt -rpcpassword=phase1c-temp-pass setgenerate true 1
./src/crownd -datadir=/tmp/crown-phase1c/network3/nodeB
./src/crown-cli -datadir=/tmp/crown-phase1c/network3/nodeB -rpcuser=rt -rpcpassword=phase1c-temp-pass addnode 127.0.0.1:23920 add
```

Observed results:

- while node B was offline, node A and node C advanced to height `104`
- node A mined block hash `443289a1119488ae2f795e35abe3ccc3d3836b54406a6d113db8a3f2c38dca5a`
- after restart and re-adding node C, node B reached the same height and bestblockhash as nodes A and C
- measured restart-plus-resync window in the harness: `~121.221s`

Final synchronized state captured after the restart:

```text
A 104 443289a1119488ae2f795e35abe3ccc3d3836b54406a6d113db8a3f2c38dca5a
B 104 443289a1119488ae2f795e35abe3ccc3d3836b54406a6d113db8a3f2c38dca5a
C 104 443289a1119488ae2f795e35abe3ccc3d3836b54406a6d113db8a3f2c38dca5a
```

Representative final `getpeerinfo`/`getblockchaininfo` evidence for node B after restart:

```json
[
  {
    "addr": "127.0.0.1:23920",
    "version": 70062,
    "subver": "/Crown Core:0.14.0.7/",
    "inbound": false,
    "startingheight": 104
  }
]
```

```json
{
  "chain": "regtest",
  "blocks": 104,
  "headers": 104,
  "bestblockhash": "443289a1119488ae2f795e35abe3ccc3d3836b54406a6d113db8a3f2c38dca5a",
  "difficulty": 0.0,
  "verificationprogress": 1.0
}
```

## 9. Debug log evidence

Representative `debug.log` excerpts from the executed run showed actual chain advancement and rejoin traffic rather than predicted behaviour. Examples captured from `/tmp/crown-phase1c/network3/node*/regtest/debug.log` include:

```text
2026-09-11 08:43:11 UpdateTip: new best=1ae68c0ba6ab525de74f672717aa0ade99ae1d1f367476a296e5cfd5702811f4  height=101
2026-09-11 08:43:13 UpdateTip: new best=3566ee33cb20bf3253c62e902e9d562b1642209cb0f35fe2796ad0f9aec69615  height=102
2026-09-11 08:43:15 UpdateTip: new best=6919d3876862fa172d2ddae03d54a6ba79316aeeac71c35b9652cbfcafd3a125  height=103
2026-09-11 08:43:16 UpdateTip: new best=443289a1119488ae2f795e35abe3ccc3d3836b54406a6d113db8a3f2c38dca5a  height=104
2026-09-11 08:45:16 receive version message: /Crown Core:0.14.0.7/: version 70062, blocks=104, us=0.0.0.0:0, peer=1
```

## 10. Phase 1C conclusion

### What was successfully validated

- recovered `master` built successfully on the runner with the established recovery flags after installing the same missing host packages already identified during recovery work
- three independent native `crownd` processes ran concurrently on isolated loopback-only `regtest` data
- block propagation across the three-node private network worked
- mempool propagation for two signed transactions worked across all three nodes
- the network continued forward while one node was offline
- the stopped node could be restarted and resynchronized to the common tip

### Limitation discovered

- wallet-generated `regtest` `tCRW...` addresses were rejected by `validateaddress` and `sendtoaddress`, so standard address-based wallet sends could not be exercised directly in this phase without altering Crown source

### Overall verdict

**PRIVATE THREE-NODE RUNTIME VALIDATION SUCCEEDED WITH A DOCUMENTED REGTEST ADDRESS/RPC LIMITATION.**

No consensus, monetary-policy, serialization, wallet-format, cryptographic, or public-network changes were introduced during this audit.
