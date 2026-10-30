"""Independent BIP-54 oracle (stdlib only), checked against the BIP's own vectors.

This is the "spec" side of the harness: rules written from the BIP text.
`python3 gen/oracle.py <bips>/bip-0054/test_vectors` must print 0 mismatches
before the generated cases are trusted.
"""

from __future__ import annotations

import io
import json
import struct
import sys
from pathlib import Path

OP_1, OP_16 = 0x51, 0x60
CS = {0xAC, 0xAD}
CMS = {0xAE, 0xAF}
MAX_BIP54_SIGOPS = 2500


def read_compact(s: io.BytesIO) -> int:
    n = s.read(1)[0]
    if n < 0xFD:
        return n
    return int.from_bytes(s.read({0xFD: 2, 0xFE: 4, 0xFF: 8}[n]), "little")


def parse_tx(raw: bytes) -> dict:
    s = io.BytesIO(raw)
    version = struct.unpack("<i", s.read(4))[0]
    n = read_compact(s)
    segwit = False
    if n == 0:
        assert s.read(1) == b"\x01"
        segwit, n = True, read_compact(s)
    vin = []
    for _ in range(n):
        prev = s.read(36)
        ss = s.read(read_compact(s))
        seq = struct.unpack("<I", s.read(4))[0]
        vin.append({"prev": prev, "script_sig": ss, "sequence": seq, "witness": []})
    vout = []
    for _ in range(read_compact(s)):
        value = struct.unpack("<q", s.read(8))[0]
        vout.append({"value": value, "spk": s.read(read_compact(s))})
    if segwit:
        for i in vin:
            i["witness"] = [s.read(read_compact(s)) for _ in range(read_compact(s))]
    locktime = struct.unpack("<I", s.read(4))[0]
    assert not s.read(1), "trailing bytes"
    stripped = 4 + len(_ser_body(vin, vout)) + 4
    return {"version": version, "vin": vin, "vout": vout, "locktime": locktime, "stripped_size": stripped}


def _compact(n: int) -> bytes:
    return bytes([n]) if n < 0xFD else b"\xfd" + struct.pack("<H", n) if n <= 0xFFFF else b"\xfe" + struct.pack("<I", n)


def _ser_body(vin, vout) -> bytes:
    out = _compact(len(vin))
    for i in vin:
        out += i["prev"] + _compact(len(i["script_sig"])) + i["script_sig"] + struct.pack("<I", i["sequence"])
    out += _compact(len(vout))
    for o in vout:
        out += struct.pack("<q", o["value"]) + _compact(len(o["spk"])) + o["spk"]
    return out


def ops(script: bytes):
    """Yield (opcode, data) until the end or the first parse failure."""
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op <= 0x4E:
            if op < 0x4C:
                n = op
            else:
                w = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
                if i + w > len(script):
                    return
                n = int.from_bytes(script[i:i + w], "little")
                i += w
            if i + n > len(script):
                return
            yield op, script[i:i + n]
            i += n
        else:
            yield op, b""


def sigops(script: bytes) -> int:
    """BIP16 'accurate' legacy count: CMS after OP_1..OP_16 costs n, else 20."""
    count, last = 0, None
    for op, _ in ops(script):
        if op in CS:
            count += 1
        elif op in CMS:
            count += (last - OP_1 + 1) if last is not None and OP_1 <= last <= OP_16 else 20
        last = op
    return count


def is_p2sh(spk: bytes) -> bool:
    return len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14 and spk[22] == 0x87


def redeem_script(script_sig: bytes) -> bytes | None:
    """Last push of a push-only scriptSig (ops <= OP_16), else None."""
    data, end, i = b"", 0, 0
    for op, d in ops(script_sig):
        if op > OP_16:
            return None
        data = d
    # ops() stops early on a parse failure: re-walk to see if we hit the end
    for op, d in ops(script_sig):
        end += 1 + (len(d) + ({0x4C: 1, 0x4D: 2, 0x4E: 4}.get(op, 0)) if op <= 0x4E else 0)
    return data if end == len(script_sig) else None


def bip54_sigops(tx: dict, spent: list[bytes]) -> int:
    total = 0
    for txin, spk in zip(tx["vin"], spent):
        total += sigops(txin["script_sig"]) + sigops(spk)
        if is_p2sh(spk):
            r = redeem_script(txin["script_sig"])
            total += sigops(r) if r else 0
    return total


def parse_txout(raw: bytes) -> bytes:
    s = io.BytesIO(raw)
    s.read(8)
    return s.read(read_compact(s))


def check_vectors(vdir: Path) -> int:
    bad = 0
    for v in json.loads((vdir / "sigops.json").read_text()):
        tx = parse_tx(bytes.fromhex(v["tx"]))
        spent = [parse_txout(bytes.fromhex(o)) for o in v["spent_outputs"]]
        got = bip54_sigops(tx, spent) <= MAX_BIP54_SIGOPS
        want = v["valid"] in (True, "True", "true")
        if got != want:
            bad += 1
            print("sigops MISMATCH:", v["comment"], bip54_sigops(tx, spent))
    for v in json.loads((vdir / "txsize.json").read_text()):
        tx = parse_tx(bytes.fromhex(v["tx"]))
        got = tx["stripped_size"] != 64
        want = v["valid"] in (True, "True", "true")
        if got != want:
            bad += 1
            print("txsize MISMATCH:", v["comment"], tx["stripped_size"])
    return bad




def check_cases(path: Path) -> int:
    """The generated cases' expected verdicts must agree with this oracle."""
    bad = 0
    for c in json.loads(path.read_text())["cases"]:
        p = c.get("btclib")
        if not p or p["rule"] == "coinbase":
            continue
        tx = parse_tx(bytes.fromhex(p["tx"]))
        if p["rule"] == "sigops":
            n = bip54_sigops(tx, [parse_txout(bytes.fromhex(o)) for o in p["prevouts"]])
            ok = n <= MAX_BIP54_SIGOPS
        else:
            ok = tx["stripped_size"] != 64
        if ok != (c["expect"]["verdict"] == "valid"):
            bad += 1
            print("case MISMATCH:", c["id"], c["desc"])
    return bad


if __name__ == "__main__":
    n = check_vectors(Path(sys.argv[1]))
    print(f"oracle vs BIP-54 vectors: {n} mismatches")
    if len(sys.argv) > 2:
        m = check_cases(Path(sys.argv[2]))
        print(f"oracle vs generated cases: {m} mismatches")
        n += m
    sys.exit(1 if n else 0)
