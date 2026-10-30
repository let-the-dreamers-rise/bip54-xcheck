"""bip54-xcheck runner for btclib's BIP-54 predicates (tx-level rules).

python3 runners/btclib_run.py cases.json btclib.json

btclib exposes the rules as functions rather than a node, so this checks the
final transaction of each sigops, txsize and coinbase case. Its coinbase
predicate covers BIP-54 only, not BIP-34, so C07/C08 are out of its scope.
"""

from __future__ import annotations

import json
import sys

from btclib.tx import tx_context
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut


def run(p: dict) -> dict:
    tx = Tx.parse(bytes.fromhex(p["tx"]), check_validity=False)
    try:
        if p["rule"] == "sigops":
            prevouts = [TxOut.parse(bytes.fromhex(o), check_validity=False) for o in p["prevouts"]]
            tx_context.assert_bip54_sig_ops(tx, prevouts)
        elif p["rule"] == "txsize":
            tx_context.assert_bip54_tx_size(tx)
        elif p["rule"] == "coinbase":
            tx_context.assert_bip54_coinbase(tx, p["height"])
    except Exception as e:  # noqa: BLE001 - every refusal is a verdict
        return {"verdict": "invalid", "at": 0, "reason": f"{type(e).__name__}: {e}"[:200]}
    return {"verdict": "valid", "at": None, "reason": ""}


def main(cases_path: str, out_path: str) -> None:
    doc = json.load(open(cases_path))
    results = {c["id"]: run(c["btclib"]) for c in doc["cases"] if c.get("btclib")}
    for k, v in results.items():
        print(k, v["verdict"], v["reason"])
    json.dump(results, open(out_path, "w"), indent=2)


if __name__ == "__main__":
    main(*sys.argv[1:3])
