"""Minimal Bitcoin serialization for building regtest blocks (stdlib only).

Written from the protocol, not from any implementation under test, so the
harness has no code in common with Core, btcd or btclib.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

# Opcodes used by the cases.
OP_0 = 0x00
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_1NEGATE = 0x4F
OP_RESERVED = 0x50
OP_1 = 0x51
OP_16 = 0x60
OP_IF = 0x63
OP_ENDIF = 0x68
OP_RETURN = 0x6A
OP_DROP = 0x75
OP_EQUAL = 0x87
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF
OP_TRUE = OP_1

SEQUENCE_FINAL = 0xFFFFFFFF
REGTEST_BITS = 0x207FFFFF
REGTEST_GENESIS_TIME = 1296688602
REGTEST_GENESIS_HASH = bytes.fromhex(
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
)[::-1]


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hash256(b: bytes) -> bytes:
    return sha256(sha256(b))


def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", sha256(b)).digest()


def ser_compact(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def push(data: bytes) -> bytes:
    """Minimal push of `data` (as Core's CScript << vector)."""
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2]) + struct.pack("<H", n) + data
    raise ValueError("push too large")


def script_num(n: int) -> bytes:
    """CScript() << n, as BIP34 requires for the coinbase height."""
    if n == 0:
        return bytes([OP_0])
    if n == -1 or 1 <= n <= 16:
        return bytes([OP_1 + n - 1])
    neg = n < 0
    a = abs(n)
    out = bytearray()
    while a:
        out.append(a & 0xFF)
        a >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0)
    elif neg:
        out[-1] |= 0x80
    return push(bytes(out))


def p2sh(redeem: bytes) -> bytes:
    return bytes([OP_HASH160, 20]) + hash160(redeem) + bytes([OP_EQUAL])


def p2wsh(witness_script: bytes) -> bytes:
    return bytes([OP_0, 32]) + sha256(witness_script)


@dataclass
class TxIn:
    txid: bytes  # internal byte order
    vout: int
    script_sig: bytes = b""
    sequence: int = SEQUENCE_FINAL
    witness: list[bytes] = field(default_factory=list)


@dataclass
class TxOut:
    value: int
    spk: bytes

    def ser(self) -> bytes:
        return struct.pack("<q", self.value) + ser_compact(len(self.spk)) + self.spk


@dataclass
class Tx:
    vin: list[TxIn]
    vout: list[TxOut]
    version: int = 2
    locktime: int = 0

    def has_witness(self) -> bool:
        return any(i.witness for i in self.vin)

    def ser(self, with_witness: bool = True) -> bytes:
        w = with_witness and self.has_witness()
        out = struct.pack("<i", self.version)
        if w:
            out += b"\x00\x01"
        out += ser_compact(len(self.vin))
        for i in self.vin:
            out += i.txid + struct.pack("<I", i.vout)
            out += ser_compact(len(i.script_sig)) + i.script_sig
            out += struct.pack("<I", i.sequence)
        out += ser_compact(len(self.vout))
        for o in self.vout:
            out += o.ser()
        if w:
            for i in self.vin:
                out += ser_compact(len(i.witness))
                for item in i.witness:
                    out += ser_compact(len(item)) + item
        out += struct.pack("<I", self.locktime)
        return out

    def stripped_size(self) -> int:
        return len(self.ser(with_witness=False))

    def txid(self) -> bytes:
        return hash256(self.ser(with_witness=False))

    def wtxid(self) -> bytes:
        return hash256(self.ser(with_witness=True))


def merkle_root(hashes: list[bytes]) -> bytes:
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hash256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


WITNESS_RESERVED = b"\x00" * 32


@dataclass
class Block:
    prev: bytes
    time: int
    txs: list[Tx]
    version: int = 0x20000000
    bits: int = REGTEST_BITS
    nonce: int = 0

    def header(self) -> bytes:
        return (
            struct.pack("<i", self.version)
            + self.prev
            + merkle_root([t.txid() for t in self.txs])
            + struct.pack("<III", self.time, self.bits, self.nonce)
        )

    def hash(self) -> bytes:
        return hash256(self.header())

    def solve(self) -> None:
        exp, mant = self.bits >> 24, self.bits & 0xFFFFFF
        target = mant << (8 * (exp - 3))
        self.nonce = 0
        while int.from_bytes(self.hash(), "little") > target:
            self.nonce += 1

    def ser(self) -> bytes:
        out = self.header() + ser_compact(len(self.txs))
        for t in self.txs:
            out += t.ser()
        return out


def add_witness_commitment(block: Block) -> None:
    """BIP141 commitment in the coinbase, needed when any tx has a witness."""
    cb = block.txs[0]
    cb.vin[0].witness = [WITNESS_RESERVED]
    wtxids = [b"\x00" * 32] + [t.wtxid() for t in block.txs[1:]]
    commitment = hash256(merkle_root(wtxids) + WITNESS_RESERVED)
    cb.vout.append(TxOut(0, bytes([OP_RETURN, 0x24, 0xAA, 0x21, 0xA9, 0xED]) + commitment))
