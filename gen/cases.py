"""Spec-derived BIP-54 cases: regtest block chains with a verdict from the BIP.

Every case is a list of blocks built on a named base chain. The expected
verdict and Core-style reject reason come from reading BIP-54 (and the rules
it leaves in place), never from running an implementation.

Run:  python3 gen/cases.py out/cases.json
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field

from btc import (
    OP_0, OP_1, OP_1NEGATE, OP_16, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY,
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_ENDIF, OP_IF, OP_RESERVED, OP_TRUE,
    REGTEST_GENESIS_HASH, REGTEST_GENESIS_TIME, SEQUENCE_FINAL,
    Block, Tx, TxIn, TxOut, add_witness_commitment, p2sh, p2wsh, push,
    script_num,
)

CMS, CS = OP_CHECKMULTISIG, OP_CHECKSIG
BIP54_BIT = 3  # Core PR #35793 regtest deployment bit
VBITS_VERSION = 0x20000000 | (1 << BIP54_BIT)


def dead(body: bytes) -> bytes:
    """Unexecuted branch: sigops are counted by BIP-54 but never run.

    Core counts every opcode above OP_16 toward the 201-op limit even when
    unexecuted, so each script stays under 199 sigop opcodes.
    """
    ops = sum(1 for b in body if b > OP_16)
    assert ops <= 199, ops
    return bytes([OP_0, OP_IF]) + body + bytes([OP_ENDIF])


def sig(cms: int = 0, cs: int = 0, extra: bytes = b"") -> bytes:
    """Body worth 20*cms + cs sigops (+ whatever `extra` is worth)."""
    return bytes([CMS]) * cms + bytes([CS]) * cs + extra


# ---------------------------------------------------------------- chain state


@dataclass
class Chain:
    tip: bytes = REGTEST_GENESIS_HASH
    height: int = 0
    times: list[int] = field(default_factory=lambda: [REGTEST_GENESIS_TIME])
    blocks: list[str] = field(default_factory=list)
    tag: bytes = b""
    version: int = 0x20000000

    def copy(self, tag: str) -> "Chain":
        return Chain(self.tip, self.height, list(self.times), [], tag.encode(), self.version)

    def mtp(self) -> int:
        return sorted(self.times[-11:])[len(self.times[-11:]) // 2]

    def coinbase(self, h: int, *, outs=None, locktime=None, sequence=0xFFFFFFFE,
                 script_sig=None) -> Tx:
        ss = script_sig if script_sig is not None else script_num(h) + push(self.tag or b"x")
        return Tx(
            [TxIn(b"\x00" * 32, 0xFFFFFFFF, ss, sequence)],
            outs if outs is not None else [TxOut(0, bytes([OP_TRUE]))],
            version=1,
            locktime=h - 1 if locktime is None else locktime,
        )

    def mine(self, txs=(), *, time=None, cb=None, version=None) -> Block:
        h = self.height + 1
        cbtx = cb if cb is not None else self.coinbase(h)
        t = time if time is not None else max(self.times[-1] + 600, self.mtp() + 1)
        blk = Block(self.tip, t, [cbtx, *txs], version=version or self.version)
        if any(tx.has_witness() for tx in txs):
            add_witness_commitment(blk)
        blk.solve()
        self.tip, self.height = blk.hash(), h
        self.times.append(t)
        self.blocks.append(blk.ser().hex())
        return blk


# -------------------------------------------------------------- base chains

# Funding outputs, all in the block-1 coinbase, mature from height 101.
REDEEMS = {
    "r2500": dead(sig(cms=125)) + bytes([OP_TRUE]),
    "r2501": dead(sig(cms=125, cs=1)) + bytes([OP_TRUE]),
    "r1250": dead(sig(cms=62, cs=10)) + bytes([OP_TRUE]),
    "r2500acc": dead(bytes([OP_16, CMS]) * 156 + bytes([CS]) * 4) + bytes([OP_TRUE]),
    "r2501acc": dead(bytes([OP_16, CMS]) * 156 + bytes([CS]) * 5) + bytes([OP_TRUE]),
}
WSCRIPT = dead(sig(cms=150)) + bytes([OP_TRUE])  # 3000 sigops in a witness script
FUND = {
    "true0": bytes([OP_TRUE]),
    "true1": bytes([OP_TRUE]),
    "spk2500": dead(sig(cms=125)) + bytes([OP_TRUE]),
    "spk2501": dead(sig(cms=125, cs=1)) + bytes([OP_TRUE]),
    "spk1250": dead(sig(cms=62, cs=10)) + bytes([OP_TRUE]),
    "spk1251": dead(sig(cms=62, cs=11)) + bytes([OP_TRUE]),
    **{k: p2sh(v) for k, v in REDEEMS.items()},
    "wsh3000": p2wsh(WSCRIPT),
    "wshtrue": p2wsh(bytes([OP_TRUE])),
    "shwsh3000": p2sh(p2wsh(WSCRIPT)),
}
FUND_VALUE = 1000


def build_base_always() -> tuple[Chain, dict]:
    c = Chain(tag=b"base")
    outs = [TxOut(FUND_VALUE, spk) for spk in FUND.values()]
    blk = c.mine(cb=c.coinbase(1, outs=outs))
    cb = blk.txs[0]
    utxo = {name: (cb.txid(), i, TxOut(FUND_VALUE, spk)) for i, (name, spk) in enumerate(FUND.items())}
    while c.height < 110:
        c.mine()
    return c, utxo


def build_base_vbits(signal: bool) -> tuple[Chain, dict]:
    c = Chain(tag=b"vb1" if signal else b"vb0",
              version=VBITS_VERSION if signal else 0x20000000)
    blk = c.mine(cb=c.coinbase(1, outs=[TxOut(FUND_VALUE, bytes([OP_TRUE]))]))
    utxo = {"true0": (blk.txs[0].txid(), 0, TxOut(FUND_VALUE, bytes([OP_TRUE])))}
    while c.height < 430:
        c.mine()
    return c, utxo


# -------------------------------------------------------------- tx helpers


def spend(utxo, inputs, outs=None) -> Tx:
    """inputs: list of (name, script_sig, witness)."""
    vin, total = [], 0
    for name, ss, wit in inputs:
        txid, n, txo = utxo[name]
        vin.append(TxIn(txid, n, ss, SEQUENCE_FINAL, list(wit)))
        total += txo.value
    return Tx(vin, outs if outs is not None else [TxOut(total, bytes([OP_TRUE]))])


def prevouts(utxo, inputs) -> list[str]:
    return [utxo[name][2].ser().hex() for name, _, _ in inputs]


# -------------------------------------------------------------- cases

CASES: list[dict] = []


def case(cid, group, base, desc, verdict, reason, chain, at=None, btclib=None):
    CASES.append({
        "id": cid, "group": group, "base": base, "desc": desc,
        "expect": {"verdict": verdict, "reason": reason,
                   "at": (len(chain.blocks) - 1) if at is None else at},
        "blocks": chain.blocks, "btclib": btclib,
    })


def sigop_cases(base: Chain, utxo: dict) -> None:
    def one(cid, desc, inputs, verdict, outs=None):
        c = base.copy(cid)
        tx = spend(utxo, inputs, outs)
        c.mine([tx])
        reason = None if verdict == "valid" else "bad-txns-legacy-sigops"
        case(cid, "sigops", "always", desc, verdict, reason, c,
             btclib={"rule": "sigops", "tx": tx.ser().hex(), "prevouts": prevouts(utxo, inputs)})

    ss = lambda body: dead(body)
    one("S01", "scriptSig 2500 (125 bare CMS)", [("true0", ss(sig(125)), [])], "valid")
    one("S02", "scriptSig 2501", [("true0", ss(sig(125, 1)), [])], "invalid")
    one("S03", "spent scriptPubKey 2500", [("spk2500", b"", [])], "valid")
    one("S04", "spent scriptPubKey 2501", [("spk2501", b"", [])], "invalid")
    one("S05", "scriptSig 1250 + spent spk 1250", [("spk1250", ss(sig(62, 10)), [])], "valid")
    one("S06", "scriptSig 1250 + spent spk 1251", [("spk1251", ss(sig(62, 10)), [])], "invalid")
    one("S07", "two inputs 1250 + 1250", [("true0", ss(sig(62, 10)), []), ("true1", ss(sig(62, 10)), [])], "valid")
    one("S08", "two inputs 1250 + 1251", [("true0", ss(sig(62, 10)), []), ("true1", ss(sig(62, 11)), [])], "invalid")
    one("S09", "P2SH redeem 2500", [("r2500", push(REDEEMS["r2500"]), [])], "valid")
    one("S10", "P2SH redeem 2501", [("r2501", push(REDEEMS["r2501"]), [])], "invalid")
    one("S11", "P2SH redeem 1250 + other input scriptSig 1250",
        [("r1250", push(REDEEMS["r1250"]), []), ("true0", ss(sig(62, 10)), [])], "valid")
    one("S12", "P2SH redeem 1250 + other input scriptSig 1251",
        [("r1250", push(REDEEMS["r1250"]), []), ("true0", ss(sig(62, 11)), [])], "invalid")
    one("S13", "accurate: (OP_16 CMS)*156 + 4 CS in scriptSig = 2500",
        [("true0", ss(bytes([OP_16, CMS]) * 156 + bytes([CS]) * 4), [])], "valid")
    one("S14", "accurate: (OP_16 CMS)*156 + 5 CS in scriptSig = 2501",
        [("true0", ss(bytes([OP_16, CMS]) * 156 + bytes([CS]) * 5), [])], "invalid")
    one("S15", "accurate in P2SH redeem = 2500", [("r2500acc", push(REDEEMS["r2500acc"]), [])], "valid")
    one("S16", "accurate in P2SH redeem = 2501", [("r2501acc", push(REDEEMS["r2501acc"]), [])], "invalid")
    one("S17", "OP_0 before CMS counts 20 (total 2501)",
        [("true0", ss(sig(124, 1) + bytes([OP_0, CMS])), [])], "invalid")
    one("S18", "OP_1NEGATE before CMS counts 20 (total 2501)",
        [("true0", ss(sig(124, 1) + bytes([OP_1NEGATE, CMS])), [])], "invalid")
    one("S19", "OP_RESERVED before CMS counts 20 (total 2501)",
        [("true0", ss(sig(124, 1) + bytes([OP_RESERVED, CMS])), [])], "invalid")
    one("S20", "pushed byte 0x10 before CMS counts 20 (total 2501)",
        [("true0", ss(sig(124, 1) + bytes([0x01, 0x10, CMS])), [])], "invalid")
    one("S21", "OP_1 CMS counts 1 (total 2500)",
        [("true0", ss(sig(124, 19) + bytes([OP_1, CMS])), [])], "valid")
    one("S22", "OP_16 CMSVERIFY counts 16 (total 2500)",
        [("true0", ss(sig(124, 4) + bytes([OP_16, OP_CHECKMULTISIGVERIFY])), [])], "valid")
    one("S23", "CHECKSIGVERIFY counts 1 (124 CMS + 21 CSV = 2501)",
        [("true0", ss(sig(124) + bytes([OP_CHECKSIGVERIFY]) * 21), [])], "invalid")
    one("S24", "sigops in the tx's own outputs do not count (3000)",
        [("true0", b"", [])], "valid", outs=[TxOut(FUND_VALUE, sig(150))])
    one("S25", "P2WSH witness script 3000 does not count", [("wsh3000", b"", [WSCRIPT])], "valid")
    one("S26", "P2SH-P2WSH witness script 3000 does not count",
        [("shwsh3000", push(p2wsh(WSCRIPT)), [WSCRIPT])], "valid")


def coinbase_cases(base: Chain) -> None:
    h = base.height + 1

    def one(cid, desc, verdict, reason, **kw):
        c = base.copy(cid)
        cb = c.coinbase(h, **kw)
        c.mine(cb=cb)
        case(cid, "coinbase", "always", desc, verdict, reason, c,
             btclib={"rule": "coinbase", "tx": cb.ser().hex(), "height": h})

    one("C01", "nLockTime = h-1, nSequence non-final (control)", "valid", None)
    one("C02", "nLockTime = h", "invalid", "bad-cb-locktime", locktime=h)
    one("C03", "nLockTime = h-2", "invalid", "bad-cb-locktime", locktime=h - 2)
    one("C04", "nLockTime = 0", "invalid", "bad-cb-locktime", locktime=0)
    one("C05", "nSequence final", "invalid", "bad-cb-sequence", sequence=SEQUENCE_FINAL)
    one("C06", "nSequence = 0", "valid", None, sequence=0)
    one("C07", "BIP-54 ok but BIP-34 height push is h+1", "invalid", "bad-cb-height",
        script_sig=script_num(h + 1) + push(b"C07"))
    one("C08", "BIP-54 ok but no BIP-34 height push", "invalid", "bad-cb-height",
        script_sig=push(b"C08-no-height"))


def size_cases(base: Chain, utxo: dict) -> None:
    def one(cid, desc, spk_len, verdict, witness=False):
        c = base.copy(cid)
        name, wit = ("wshtrue", [bytes([OP_TRUE])]) if witness else ("true0", [])
        tx = spend(utxo, [(name, b"", wit)], outs=[TxOut(FUND_VALUE, bytes([OP_TRUE]) * spk_len)])
        c.mine([tx])
        case(cid, "txsize", "always", f"{desc} (stripped {tx.stripped_size()} bytes)", verdict,
             None if verdict == "valid" else "bad-txns-size", c,
             btclib={"rule": "txsize", "tx": tx.ser().hex()})
        return tx

    assert one("T01", "64-byte transaction", 4, "invalid").stripped_size() == 64
    one("T02", "63-byte transaction", 3, "valid")
    one("T03", "65-byte transaction", 5, "valid")
    assert one("T04", "segwit tx, 64 bytes without witness", 4, "invalid", witness=True).stripped_size() == 64
    one("T05", "segwit tx, 65 bytes without witness", 5, "valid", witness=True)

    h = base.height + 1
    for cid, spk_len, verdict in (("T06", 2, "invalid"), ("T07", 3, "valid")):
        c = base.copy(cid)
        cb = c.coinbase(h, outs=[TxOut(0, bytes([OP_TRUE]) * spk_len)], script_sig=script_num(h))
        c.mine(cb=cb)
        assert cb.stripped_size() == (64 if verdict == "invalid" else 65)
        case(cid, "txsize", "always", f"coinbase of {cb.stripped_size()} bytes", verdict,
             None if verdict == "valid" else "bad-txns-size", c,
             btclib={"rule": "txsize", "tx": cb.ser().hex()})


def timestamp_cases(base: Chain) -> None:
    def to(c: Chain, height: int, plateau_from: int | None = None):
        while c.height < height - 1:
            if plateau_from is not None and c.height + 1 >= plateau_from:
                c.mine(time=c.times[-1] + 1)
            else:
                c.mine()

    # Timewarp: block 2005..2014 crawl by 1 s, 2015 jumps +20000, so the MTP
    # stays low and only the BIP-54 rule can reject block 2016.
    def timewarp(cid, delta, verdict, extra=None):
        c = base.copy(cid)
        to(c, 2015, plateau_from=2005)
        c.mine(time=c.times[-1] + 20000)  # 2015
        t2015 = c.times[-1]
        c.mine(time=t2015 - 7200 + delta)  # 2016
        if extra:
            extra(c)
        return c

    c = timewarp("W01", 0, "valid")
    case("W01", "timestamps", "always", "first block of period = prev - 7200", "valid", None, c)
    c = timewarp("W02", -1, "invalid")
    case("W02", "timestamps", "always", "first block of period = prev - 7201", "invalid",
         "time-timewarp-attack", c)
    c = timewarp("W03", 0, "valid", extra=lambda c: c.mine(time=c.times[-1] - 7201))
    case("W03", "timestamps", "always", "non-boundary block 2017 = prev - 7201 (rule must not apply)",
         "valid", None, c)

    # Murch-Zawy: block 2016 set far ahead, period runs at normal pace, last
    # block 4031 compared with 2016.
    def murch(cid, last_delta, stop=4031):
        c = base.copy(cid)
        to(c, 2016)
        c.mine(time=REGTEST_GENESIS_TIME + 600 * 4031 + 50000)  # 2016
        t2016 = c.times[-1]
        while c.height < 4029:
            c.mine(time=max(REGTEST_GENESIS_TIME + 600 * (c.height + 1), c.mtp() + 1))
        if stop == 4030:
            c.mine(time=t2016 - 1)  # 4030
            return c
        c.mine()  # 4030
        c.mine(time=t2016 + last_delta)  # 4031
        return c

    case("W04", "timestamps", "always", "last block of period = first block", "valid", None, murch("W04", 0))
    case("W05", "timestamps", "always", "last block of period = first block - 1", "invalid",
         "time-negative-interval", murch("W05", -1))
    case("W06", "timestamps", "always", "block 4030 < first block of period (rule must not apply)",
         "valid", None, murch("W06", 0, stop=4030))


def activation_cases(base_sig: Chain, utxo_sig: dict, base_nosig: Chain, utxo_nosig: dict) -> None:
    # Core: bit 3, period 144, threshold 108, start 0 -> STARTED at 144,
    # LOCKED_IN at 288, ACTIVE from 432. Base chains end at 430.
    bad_cb = dict(locktime=0, sequence=SEQUENCE_FINAL)

    c = base_sig.copy("A01")
    c.mine(cb=c.coinbase(431, **bad_cb))
    case("A01", "activation", "vbits", "block 431 breaks the coinbase rule (not active yet)", "valid", None, c)

    c = base_sig.copy("A02")
    c.mine()
    c.mine(cb=c.coinbase(432, **bad_cb))
    case("A02", "activation", "vbits", "block 432 breaks the coinbase rule (first active block)",
         "invalid", "bad-cb-locktime", c)

    for cid, height, verdict in (("A03", 431, "valid"), ("A04", 432, "invalid")):
        c = base_sig.copy(cid)
        if height == 432:
            c.mine()
        tx = spend(utxo_sig, [("true0", b"", [])], outs=[TxOut(FUND_VALUE, bytes([OP_TRUE]) * 4)])
        c.mine([tx])
        case(cid, "activation", "vbits", f"64-byte tx in block {height}", verdict,
             None if verdict == "valid" else "bad-txns-size", c)

    c = base_nosig.copy("A05")
    c.mine()
    c.mine(cb=c.coinbase(432, **bad_cb))
    case("A05", "activation", "vbits-nosignal", "no signalling: block 432 breaks the coinbase rule",
         "valid", None, c)


def main(out: str) -> None:
    base, utxo = build_base_always()
    sigop_cases(base, utxo)
    coinbase_cases(base)
    size_cases(base, utxo)
    timestamp_cases(base)
    vb1, u1 = build_base_vbits(True)
    vb0, u0 = build_base_vbits(False)
    activation_cases(vb1, u1, vb0, u0)
    doc = {
        "bases": {"always": base.blocks, "vbits": vb1.blocks, "vbits-nosignal": vb0.blocks},
        "cases": CASES,
    }
    with open(out, "w") as f:
        json.dump(doc, f)
    print(f"{len(CASES)} cases -> {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "cases.json")
