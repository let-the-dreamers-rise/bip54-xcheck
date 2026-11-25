"""Flatten cases.json into the line format read by runners/libbitcoin/xcheck.

python3 runners/libbitcoin/flatten.py cases.json flat.txt [base ...]
"""

from __future__ import annotations

import json
import sys


def main(cases_path: str, out_path: str, *bases: str) -> None:
    doc = json.load(open(cases_path))
    wanted = list(bases) or list(doc["bases"])
    with open(out_path, "w") as f:
        for base in wanted:
            f.write(f"BASE {base}\n")
            for b in doc["bases"][base]:
                f.write(f"B {b}\n")
            for c in doc["cases"]:
                if c["base"] != base:
                    continue
                f.write(f"CASE {c['id']}\n")
                for b in c["blocks"]:
                    f.write(f"B {b}\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
