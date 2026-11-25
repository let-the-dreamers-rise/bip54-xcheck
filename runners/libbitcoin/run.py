"""bip54-xcheck runner for libbitcoin-system.

python3 runners/libbitcoin/run.py <xcheck binary> cases.json libbitcoin.json

The "always" base runs with libbitcoin's own regtest settings (BIP-54 active from
genesis). The "vbits" bases run with all five of libbitcoin's BIP-54 deployments
moved to Core's regtest parameters (bit 3, period 144, threshold 108); see xcheck.cpp.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from flatten import main as flatten  # noqa: E402

RUNS = [(["always"], []), (["vbits", "vbits-nosignal"], ["vbits"])]


def main(binary: str, cases_path: str, out_path: str) -> None:
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        for bases, extra in RUNS:
            flat = Path(tmp) / "flat.txt"
            flatten(cases_path, str(flat), *bases)
            out = subprocess.run([binary, str(flat), *extra], check=True, capture_output=True, text=True).stdout
            for line in out.splitlines():
                cid, verdict, at, *reason = line.split(" ", 3)
                results[cid] = {"verdict": verdict, "at": None if at == "-" else int(at),
                                "reason": (reason[0] if reason else "").strip()}
                print(line)
    json.dump(results, open(out_path, "w"), indent=2)


if __name__ == "__main__":
    main(*sys.argv[1:4])
