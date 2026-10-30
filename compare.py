"""Diff every implementation against the spec verdict and against each other.

python3 compare.py cases.json results/ report/

Writes report/RESULTS.md and report/results.json. Exits 1 if any
divergence is not listed (with an explanation) in KNOWN.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

IMPLS = ["core", "btcd", "btclib"]
# btclib's BIP-54 coinbase predicate does not cover BIP-34 by design.
OUT_OF_SCOPE = {("btclib", "C07"), ("btclib", "C08")}


def main(cases_path: str, results_dir: str, report_dir: str) -> int:
    doc = json.load(open(cases_path))
    res = {}
    for impl in IMPLS:
        p = Path(results_dir) / f"{impl}.json"
        res[impl] = json.loads(p.read_text()) if p.exists() else {}
    known = json.loads(Path(__file__).with_name("KNOWN.json").read_text())

    rows, divergences = [], []
    for c in doc["cases"]:
        exp = c["expect"]
        cells = []
        for impl in IMPLS:
            r = res[impl].get(c["id"])
            if r is None or (impl, c["id"]) in OUT_OF_SCOPE:
                cells.append("n/a")
                continue
            # btclib checks one transaction, so only the verdict is compared.
            ok = r["verdict"] == exp["verdict"] and (impl == "btclib" or r["at"] == (None if exp["verdict"] == "valid" else exp["at"]))
            short = r["verdict"] + (f" ({r['reason'].split(':')[0]})" if r["reason"] else "")
            if not ok:
                key = f"{impl}:{c['id']}"
                divergences.append({"key": key, "case": c["id"], "impl": impl, "desc": c["desc"],
                                    "expect": exp, "got": r, "known": key in known})
                short = "**DIVERGES** " + short
            cells.append(short)
        spec = exp["verdict"] + (f" ({exp['reason']})" if exp["reason"] else "")
        rows.append(f"| {c['id']} | {c['group']} | {c['desc']} | {spec} | " + " | ".join(cells) + " |")

    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)
    md = ["# bip54-xcheck results", "",
          f"{len(doc['cases'])} spec-derived cases. Implementations: " + ", ".join(
              f"{i} ({len(res[i])} results)" for i in IMPLS), "",
          f"**Divergences from the spec: {len(divergences)}** "
          f"({sum(not d['known'] for d in divergences)} not yet explained)", ""]
    for d in divergences:
        note = known.get(d["key"], "NOT YET EXPLAINED")
        md.append(f"- `{d['key']}` {d['desc']}: expected {d['expect']['verdict']}, got "
                  f"{d['got']['verdict']} `{d['got']['reason']}`. {note}")
    md += ["", "| case | rule | what | spec | " + " | ".join(IMPLS) + " |",
           "|---|---|---|---|" + "---|" * len(IMPLS), *rows]
    (out / "RESULTS.md").write_text("\n".join(md) + "\n")
    (out / "results.json").write_text(json.dumps({"results": res, "divergences": divergences}, indent=2))
    print("\n".join(md[:8 + len(divergences)]))
    missing = [i for i in IMPLS if not res[i]]
    if missing:
        print("missing results:", missing)
        return 1
    return 1 if any(not d["known"] for d in divergences) else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
