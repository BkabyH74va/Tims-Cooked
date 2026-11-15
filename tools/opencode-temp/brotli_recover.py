#!/usr/bin/env python3
"""Recover the exact gen_trigger parameters used for the sample trigger files.

stage 2 is trivial: out[7]=b7, out[15:19]=d15, out[19:23]=d19, out[23:27]=d23 (LE).
stage 1: the only unknown is `body` (11-bit symbol). Brute force 0..2047 by
regenerating a short prefix and comparing with the real file.
"""
import struct

first = open(r"G:/REPO\tools\opencode-temp\brotli-poc\first.bin", "rb").read()
second = open(r"G:/REPO\tools\opencode-temp\brotli-poc\second.bin", "rb").read()

b7 = second[7]
d15, d19, d23 = struct.unpack_from("<III", second, 15)
print("stage2: b7=%d d15=0x%08x d19=0x%08x d23=0x%08x" % (b7, d15, d19, d23))
print("stage2 nonzero bytes:", [(i, b) for i, b in enumerate(second) if b])


class BW:
    def __init__(self, limit=None):
        self.out = bytearray()
        self.value = 0
        self.used = 0
        self.limit = limit

    def put(self, v, n):
        for i in range(n):
            self.value |= ((v >> i) & 1) << self.used
            self.used += 1
            if self.used == 8:
                self.out.append(self.value & 0xFF)
                self.value = 0
                self.used = 0
                if self.limit and len(self.out) >= self.limit:
                    raise StopIteration

    def flush(self):
        if self.used:
            self.out.append(self.value & 0xFF)
            self.value = 0
            self.used = 0


def bitlen(n):
    c = 0
    while n:
        c += 1
        n >>= 1
    return c


def ost(b, alpha, sym):
    b.put(1, 2)
    b.put(0, 2)
    b.put(sym, bitlen(alpha - 1))


def vu8(b, v):
    if v == 0:
        b.put(0, 1)
        return
    b.put(1, 1)
    if v == 1:
        b.put(0, 3)
        return
    w = bitlen(v) - 1
    b.put(w, 3)
    b.put(v - (1 << w), w)


def header(b, wbits):
    if wbits == 16:
        b.put(0, 1)
    elif 18 <= wbits <= 24:
        b.put(1, 1); b.put(wbits - 17, 3)
    elif 10 <= wbits <= 15:
        b.put(1, 1); b.put(0, 3); b.put(wbits - 8, 3)
    elif wbits == 17:
        b.put(1, 1); b.put(0, 3); b.put(0, 3)
    else:
        raise SystemExit("bad wbits")
    b.put(0, 1)
    b.put(2, 2)
    b.put(0xFFFFFF, 24)
    b.put(0, 1)
    vu8(b, 0)
    vu8(b, 1)
    ost(b, 4, 0)
    ost(b, 26, 25)
    b.put(0xFFFFFF, 24)
    vu8(b, 0)
    b.put(3, 6)
    b.put(0, 2)
    vu8(b, 0)
    vu8(b, 0)
    ost(b, 256, 0)
    ost(b, 704, 130)
    ost(b, 704, 130)
    ost(b, 400, 184)


PREFIX = 96
candidates = []
for body in range(2048):
    b = BW(limit=PREFIX)
    try:
        header(b, 13)
        for _ in range(64):
            b.put(body, 11)
    except StopIteration:
        pass
    got = bytes(b.out[:PREFIX])
    if got == first[:PREFIX]:
        candidates.append(body)

print("body candidates:", candidates)
if len(candidates) == 1:
    body = candidates[0]
    # full length check: header bits + 2^24 * 11 bits + 3 trailer bytes
    b = BW()
    header(b, 13)
    total = 1 << 24
    # emulate the "while used" loop
    completed = 0
    while b.used and completed < total:
        b.put(body, 11)
        completed += 1
    group = BW()
    for _ in range(8):
        group.put(body, 11)
    group.flush()
    gbytes = bytes(group.out)
    groups = (total - completed) // 8
    tail = (total - completed) % 8
    b.out.extend(gbytes * groups)
    for _ in range(tail):
        b.put(body, 11)
    b.flush()
    b.out.extend(b"\x00\x00\x00")
    print("regenerated len=%d expected=%d match=%s" % (len(b.out), len(first), len(b.out) == len(first)))
    print("prefix match:", bytes(b.out[:4096]) == first[:4096])
    print("tail match:", bytes(b.out[-64:]) == first[-64:])
