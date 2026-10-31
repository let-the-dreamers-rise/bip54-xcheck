# Findings

Status as of 30 Oct 2026. "Source" means confirmed by reading the pinned code; "CI" means
reproduced by the harness in this repo's workflow.

## F1. btcd stops enforcing BIP-34 once BIP-54 is active; Core does not (consensus divergence)

- **Where:** btcd PR #2537, commit `624b48cc` ("skip BIP-30 and BIP-34 checks when BIP-54 is
  active"), `blockchain/validate.go`:
  `if !bip54Active && ShouldHaveSerializedBlockHeight(header) && blockHeight >= BIP0034Height`.
- **Core PR #35793 @ `3f0f142b`:** `ContextualCheckBlock` keeps the `bad-cb-height` check
  under `DEPLOYMENT_HEIGHTINCB` regardless of BIP-54, then adds `bad-cb-locktime` /
  `bad-cb-sequence`.
- **BIP-54 text:** says BIP-30 validation can be skipped after activation "regardless of the
  BIP-34 activation status". It does not relax BIP-34, and its Backward compatibility section says the proposal "only
  tightens the block validation rules". The btcd PR description says the omission of BIP-34
  from the BIP is believed to be accidental.
- **Effect:** a block whose coinbase satisfies BIP-54 (`nLockTime = h-1`, non-final
  `nSequence`) but whose scriptSig does not start with the BIP-34 height push is accepted by
  btcd and rejected by Core. If both shipped as written, a miner could split btcd nodes off
  the network with one block.
- **Cases:** C07 (height push is h+1), C08 (no height push). Source: confirmed. **CI: reproduced** (first run, 30 Oct 2026): Core rejects both with `bad-cb-height`, btcd accepts both.
- **Why the existing vectors miss it:** BIP-54's `coinbases.json` chains are short mainnet
  chains, below mainnet's BIP-34 height (227,931), so BIP-34 never applies to them. btcd's
  own test uses those vectors on mainnet parameters.
- **Resolution needed:** either btcd keeps BIP-34, or BIP-54 states that BIP-34 is superseded
  and Core follows. This is a spec question for the BIP authors, which is exactly what
  inter-implementation testing is for.

## F2. btcd adds a method to the public `ChainCtx` interface; Neutrino implements it

- **Where:** btcd PR #2537 adds `BIP54Active(prevNode HeaderCtx) (bool, error)` to
  `blockchain.ChainCtx`.
- **Who breaks:** lightninglabs/neutrino (the light client used by LND) implements
  `blockchain.ChainCtx` as `lightChainCtx` (`blockmanager.go`) and calls
  `blockchain.CheckBlockHeaderContext` to validate headers. On upgrading btcd it will not
  compile until it implements the method, and how it answers decides whether light clients
  enforce BIP-54's timewarp and Murch-Zawy header rules at all.
- Not a consensus bug in btcd itself. It is an ecosystem follow-up that should be on the
  BIP-54 deployment checklist. Source: confirmed.

## F3. On regtest, Core and btcd apply the timestamp rules at different heights (informational)

- The BIP text says `N % 2016`. Core applies the rules at its network's
  `DifficultyAdjustmentInterval()`, which is 144 on regtest (`nPowTargetTimespan` of one
  day). btcd hard-codes 2016, as the BIP says.
- On mainnet, testnet4 and signet the interval is 2016, so the two agree there. On
  regtest they disagree: cases W05 and W07 show both directions.
- Why it matters: it is not a mainnet bug, but anyone writing BIP-54 regtest tests for one
  implementation and running them against another will get different answers. The BIP
  could say "the difficulty adjustment interval (2016 on mainnet)", or Core's functional
  tests could note it.

## Checked and found consistent (source)

- Sigop counting: btcd's `preciseLegacySigOps` + `GetPreciseSigOpCount` and btclib's
  `sig_op_count` + `p2sh_sig_op_count` match Core's
  `scriptSig.GetSigOpCount(true) + scriptPubKey.GetSigOpCount(scriptSig)` on: `OP_0`
  before `CHECKMULTISIG` (20), `OP_RESERVED` treated as push-only for P2SH, parse failure
  (count stops; P2SH redeem counts 0), empty last push.
- 64-byte rule uses the stripped size in all three.
- Timestamp rules: same comparisons (`< prev - 7200` at `h % 2016 == 0`, `< first` at
  `h % 2016 == 2015`). btcd hard-codes 2016 where Core uses the interval; equal on every
  network btcd ships.
- Deployment: btcd uses bit 31 for BIP-54 (a placeholder that can never signal under BIP9).
  Harmless while the deployment is `Failed`; must change before any real deployment.

## Not a gap (from the Core PR review)

- The "Murch-Zawy enforced one block late" mutant cannot be caught by any test: instagibbs
  noted that the BIP9 period equals the retarget interval, so a one-block delay is
  unobservable. This harness does not claim it.
