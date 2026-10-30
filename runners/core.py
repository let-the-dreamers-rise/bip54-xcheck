"""bip54-xcheck runner for Bitcoin Core (stdlib only).

python3 runners/core.py <bitcoind> cases.json core.json

One regtest node per base chain. The base is submitted once; every case is
submitted on top of it, then rewound with invalidateblock so the next case
starts from the same tip.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

NODE_ARGS = {
    "always": [],
    # Core regtest: bit 3, period 144, threshold 108; start 0, no timeout.
    "vbits": ["-vbparams=consensuscleanup:0:9999999999"],
    "vbits-nosignal": ["-vbparams=consensuscleanup:0:9999999999"],
}


def block_hash(hexblock: str) -> str:
    h = hashlib.sha256(hashlib.sha256(bytes.fromhex(hexblock[:160])).digest()).digest()
    return h[::-1].hex()


class Node:
    def __init__(self, bitcoind: str, extra: list[str], port: int):
        self.dir = tempfile.mkdtemp(prefix="xcheck-core-")
        self.url = f"http://127.0.0.1:{port}"
        self.auth = "Basic " + base64.b64encode(b"x:x").decode()
        self.proc = subprocess.Popen(
            [bitcoind, "-regtest", f"-datadir={self.dir}", f"-rpcport={port}", "-rpcuser=x",
             "-rpcpassword=x", "-listen=0", "-server=1", "-printtoconsole=0", "-rpcworkqueue=64",
             *extra],
        )
        for _ in range(600):
            try:
                self.rpc("getblockcount")
                return
            except Exception:
                time.sleep(0.2)
        raise RuntimeError("bitcoind did not start")

    def rpc(self, method: str, *params):
        req = urllib.request.Request(
            self.url, json.dumps({"id": 0, "method": method, "params": list(params)}).encode(),
            {"Authorization": self.auth, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = json.loads(e.read())
        if body.get("error"):
            raise RuntimeError(f"{method}: {body['error']}")
        return body["result"]

    def stop(self):
        try:
            self.rpc("stop")
            self.proc.wait(60)
        finally:
            shutil.rmtree(self.dir, ignore_errors=True)


def main(bitcoind: str, cases_path: str, out_path: str) -> None:
    doc = json.load(open(cases_path))
    results = {}
    for n, (base, extra) in enumerate(NODE_ARGS.items()):
        cases = [c for c in doc["cases"] if c["base"] == base]
        if not cases:
            continue
        node = Node(bitcoind, extra, 18600 + n)
        try:
            for i, b in enumerate(doc["bases"][base]):
                r = node.rpc("submitblock", b)
                if r is not None:
                    raise RuntimeError(f"{base}: base block {i + 1} rejected: {r}")
            base_tip = node.rpc("getbestblockhash")
            for c in cases:
                res = {"verdict": "valid", "at": None, "reason": ""}
                for i, b in enumerate(c["blocks"]):
                    r = node.rpc("submitblock", b)
                    if r is not None:
                        res = {"verdict": "invalid", "at": i, "reason": r}
                        break
                if res["at"] != 0:
                    node.rpc("invalidateblock", block_hash(c["blocks"][0]))
                tip = node.rpc("getbestblockhash")
                if tip != base_tip:
                    raise RuntimeError(f"{c['id']}: rewind failed")
                results[c["id"]] = res
                print(c["id"], res["verdict"], res["reason"], flush=True)
        finally:
            node.stop()
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    main(*sys.argv[1:4])
