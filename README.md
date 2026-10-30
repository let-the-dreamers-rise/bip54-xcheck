# bip54-xcheck

Cross-implementation conformance testing for [BIP-54 (Consensus Cleanup)](https://github.com/bitcoin/bips/blob/master/bip-0054.md).

BIP-54's rules are *contextual*: they depend on the header chain, on the outputs a
transaction spends, and on the block height. Unit vectors check each rule in
isolation; they do not show whether two nodes agree on the same chain. This harness
builds whole regtest chains from the BIP text and replays them, block by block, into
every implementation, then diffs the verdicts.

| Implementation | Version under test | How it is driven |
|---|---|---|
| Bitcoin Core | [PR #35793](https://github.com/bitcoin/bitcoin/pull/35793) @ `3f0f142b` | `bitcoind -regtest`, `submitblock` |
| btcd | [PR #2537](https://github.com/btcsuite/btcd/pull/2537) @ `374cbaf9` | `BlockChain.ProcessBlock` on a fresh chain per case |
| btclib | `main` @ `686f6255` (BIP-54 predicates, PR #2830) | `assert_bip54_*` on each case's final transaction |

## What is tested (53 cases)

- **sigops (26):** the 2,500 limit across scriptSig, spent scriptPubKey and P2SH redeem
  script; multi-input totals; BIP-16 accurate counting (`OP_1`..`OP_16` before
  `CHECKMULTISIG`, and `OP_0`, `OP_1NEGATE`, `OP_RESERVED`, pushed bytes, which count 20);
  `CHECKSIGVERIFY`/`CHECKMULTISIGVERIFY`; the tx's own outputs and witness scripts must
  not count.
- **coinbase (8):** `nLockTime = height-1`, `nSequence` non-final, and the interplay
  with BIP-34 (which BIP-54 does not remove).
- **64-byte transactions (7):** 63/64/65 bytes, segwit transactions whose
  *stripped* size is 64, and a 64-byte coinbase.
- **timestamps (7):** timewarp at a period's first block (±1 s around 7,200 s),
  Murch-Zawy at a period's last block (±1 s), and neighbouring blocks where the rules
  must *not* apply. Chains are up to 4,031 blocks and keep median-time-past low so that
  only BIP-54 can reject.
- **activation (5):** BIP9 deployment on bit 3 (Core's regtest window 144 / threshold
  108): the last block before activation, the first active block, and a chain that
  never signals.

Every expected verdict comes from the BIP. `gen/oracle.py` is an independent
implementation of the rules that must agree with all official BIP-54 vectors and with
every generated case before anything is run (CI step 1).

## Layout

```
gen/btc.py            stdlib-only Bitcoin serialization (no code shared with any implementation)
gen/cases.py          the case generator
gen/oracle.py         spec oracle, checked against bips/bip-0054/test_vectors
runners/core.py       Bitcoin Core runner (JSON-RPC)
runners/btcd/         btcd runner (Go test copied into btcd's blockchain package)
runners/btclib_run.py btclib runner
compare.py            diff vs spec and across implementations -> report/RESULTS.md
KNOWN.json            divergences that are understood and reported upstream
FINDINGS.md           what the harness found
```

## Run

CI (`.github/workflows/xcheck.yml`) does everything: generates the cases, builds
Core at the pinned commit, runs btcd and btclib, and publishes `RESULTS.md` in the
job summary. It fails on any divergence that is not explained in `KNOWN.json`.

Locally:

```sh
python3 gen/cases.py cases.json
python3 gen/oracle.py path/to/bips/bip-0054/test_vectors cases.json
python3 runners/core.py path/to/bitcoind cases.json results/core.json
python3 compare.py cases.json results report
```

MIT licensed.
