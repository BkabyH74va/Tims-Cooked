#!/usr/bin/env python3
"""Mnemonic-profile diff of the IOSurface kext between two kernelcaches.

Kernelcaches are rebased between builds, so a byte diff is useless.  Instead we
build a per-function histogram of ARM64 mnemonics (immune to register
allocation / address / displacement churn) and pair functions across builds by
(size, histogram similarity).  Changed functions are reported with the
mnemonic multiset delta.
"""
import struct
import sys
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import (parse_fileset, member_segments, member_load_commands,
                          function_starts, LC_SEGMENT_64)

KEXT = "com.apple.iokit.IOSurface"


def load_member(kc_path, name=KEXT):
    data = Path(kc_path).read_bytes()
    entries, _ = parse_fileset(data)
    hit = [e for e in entries if e["name"] == name]
    if not hit:
        raise SystemExit(f"{name} not found in {kc_path}")
    e = hit[0]
    segs = member_segments(data, e["fileoff"])
    seg = segs.get("__TEXT_EXEC") or segs.get("__TEXT")
    base = seg[0]
    text = data[seg[2]:seg[2] + seg[3]]
    fstarts = function_starts(data, e["fileoff"], e["vmaddr"])
    return base, text, fstarts


def profile(base, text, fstarts, md):
    out = []
    for i, s in enumerate(fstarts):
        e = fstarts[i + 1] if i + 1 < len(fstarts) else s + 0x40
        # trim trailing padding: functions are contiguous, next start is the end
        off = s - base
        n = e - s
        if off < 0 or off + n > len(text):
            continue
        hist = Counter()
        for ins in md.disasm(text[off:off + n], s):
            hist[ins.mnemonic] += 1
        out.append((s, e - s, hist))
    return out


def main():
    a_path, b_path = sys.argv[1], sys.argv[2]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    a_base, a_text, a_fs = load_member(a_path)
    b_base, b_text, b_fs = load_member(b_path)
    A = profile(a_base, a_text, a_fs, md)
    B = profile(b_base, b_text, b_fs, md)
    print(f"A: {len(A)} functions   B: {len(B)} functions")

    # index B by size bucket for candidate pairing
    b_by_size = {}
    for (s, sz, h) in B:
        b_by_size.setdefault(sz, []).append((s, h))

    pairs = []
    used = set()
    for (sa, sza, ha) in A:
        best = None
        best_score = 0.0
        for dsz in range(-48, 49):
            for (sb, hb) in b_by_size.get(sza + dsz, []):
                if sb in used:
                    continue
                ta = sum(ha.values())
                tb = sum(hb.values())
                if not ta or not tb:
                    continue
                common = sum(min(ha[m], hb[m]) for m in set(ha) | set(hb))
                score = common / max(ta, tb)
                if score > best_score:
                    best_score = score
                    best = (sb, sza + dsz, hb)
        if best and best_score >= 0.92:
            used.add(best[0])
            pairs.append((sa, sza, ha, best[0], best[1], best[2], best_score))

    print(f"paired {len(pairs)} functions; scanning for changed ones\n")
    changed = []
    for (sa, sza, ha, sb, szb, hb, score) in pairs:
        delta = {m: (hb.get(m, 0) - ha.get(m, 0)) for m in set(ha) | set(hb)}
        delta = {m: v for m, v in delta.items() if v != 0}
        if delta:
            changed.append((sa, sza, sb, szb, delta, score))
    changed.sort(key=lambda c: -sum(abs(v) for v in c[4].values()))
    for (sa, sza, sb, szb, delta, score) in changed[:25]:
        print(f"A 0x{sa:x} ({sza})   B 0x{sb:x} ({szb})   sim={score:.2f}")
        print(f"    mnemonic delta: {delta}")
    print(f"\n{len(changed)} changed functions")


if __name__ == "__main__":
    main()
