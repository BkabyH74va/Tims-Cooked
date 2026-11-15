#!/usr/bin/env python3
"""Chained-fixup decoder + indirect-reference finder for the iOS arm64e kernelcache.

Two independent facilities, both validated against LC_FUNCTION_STARTS:

1. `chainrefs` — decode the LC_DYLD_CHAINED_FIXUPS blob (pointer_format 8,
   DYLD_CHAINED_PTR_64_KERNEL_CACHE on the iOS 27 kernelcache) and report every
   pointer slot whose resolved value equals a target address. This is how
   "called only through a pointer table" functions are reached, because raw
   quadwords in the file carry only a 32-bit runtime offset, not the address.

   Decoding rule measured here: the stored value is an offset from the __TEXT
   vmaddr; auth entries use the low 32 bits, unauth kernel-cache rebases the low
   30 bits. Validated on 24A446: 24,643 chain entries, 7,930 resolve exactly to
   function starts.

2. `callers` — numpy-free BL/B site scan over every executable segment, reporting
   the containing function for each hit.

Usage:
    python kz_chainfind.py chainrefs <build> <hex-target> [hex-target ...]
    python kz_chainfind.py callers   <build> <hex-target> [hex-target ...]
"""
import bisect
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
BASE = ROOT / "firmware"
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))

from kc_fstarts import load_build, func_of  # noqa: E402

# __TEXT vmaddr of the 27.0.1 kernelcache; chain rebase targets are offsets from it.
TEXT_VMADDR_DEFAULT = 0xfffffe0007004000


def segments(d):
    ncmds = struct.unpack_from("<I", d, 16)[0]
    off = 32
    out = []
    cf = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            nm = d[off + 8:off + 24].rstrip(b"\0").decode(errors="replace")
            vm, vsz, fo, fsz = struct.unpack_from("<QQQQ", d, off + 24)
            out.append((nm, vm, vsz, fo, fsz))
        elif cmd == 0x80000034:
            cf = struct.unpack_from("<II", d, off + 8)
        off += cmdsize
    return out, cf


def decode_chains(d, segs, cf, text_vm):
    """Yield (seg_index, offset_in_seg, raw, resolved_va)."""
    cf_off, _ = cf
    hdr = struct.unpack_from("<7I", d, cf_off)
    starts_off = hdr[1]
    sioff = cf_off + starts_off
    seg_count = struct.unpack_from("<I", d, sioff)[0]
    for i in range(min(seg_count, len(segs))):
        ent_off = struct.unpack_from("<I", d, sioff + 4 + 4 * i)[0]
        if not ent_off:
            continue
        p = sioff + ent_off
        page_size = struct.unpack_from("<H", d, p + 4)[0]
        pf = struct.unpack_from("<H", d, p + 6)[0]
        page_count = struct.unpack_from("<H", d, p + 20)[0]
        stride = 4 if pf in (7, 10) else 8
        for j in range(page_count):
            ps = struct.unpack_from("<H", d, p + 22 + 2 * j)[0]
            if ps == 0xFFFF:
                continue
            cur = j * page_size + ps
            guard = 0
            while guard < 100000:
                guard += 1
                fo = segs[i][3] + cur
                if fo + 8 > len(d):
                    break
                raw = struct.unpack_from("<Q", d, fo)[0]
                if (raw >> 63) & 1:
                    val = text_vm + (raw & 0xFFFFFFFF)
                else:
                    val = text_vm + (raw & 0x3FFFFFFF)
                yield i, cur, raw, val & ((1 << 64) - 1)
                nxt = (raw >> 51) & 0x7FF
                if nxt == 0:
                    break
                cur += nxt * stride


def cmd_chainrefs(build, targets):
    p = BASE / build / "kernelcache.release.macho"
    d = p.read_bytes()
    segs, cf = segments(d)
    b = load_build(build)
    starts = b["starts"]
    text_vm = TEXT_VMADDR_DEFAULT
    tset = {t: name for t, name in targets}
    hits = {}
    n = nhit = 0
    for i, cur, raw, val in decode_chains(d, segs, cf, text_vm):
        n += 1
        if val in starts:
            nhit += 1
        if val in tset:
            slotva = segs[i][1] + cur
            fi = bisect.bisect_right(starts, slotva) - 1
            owner = starts[fi] if fi >= 0 else None
            hits.setdefault(tset[val], []).append((segs[i][0], slotva, raw, owner))
    print(f"{build}: chain entries={n} resolving to function starts={nhit}")
    for t, name in targets:
        rows = hits.get(name, [])
        print(f"  {name} {t:#x}: {len(rows)} indirect slot(s)")
        for segname, slotva, raw, owner in rows:
            print(f"      {segname:<12} slot {slotva:#x} raw {raw:#018x} owner_func {owner if owner is None else hex(owner)}")


def cmd_callers(build, targets):
    p = BASE / build / "kernelcache.release.macho"
    d = p.read_bytes()
    segs, cf = segments(d)
    b = load_build(build)
    starts = b["starts"]
    for target, name in targets:
        hits = []
        for nm, vm, vsz, fo, fsz in segs:
            if "__TEXT" not in nm:
                continue
            blob = d[fo:fo + fsz]
            n4 = len(blob) // 4
            for i in range(n4):
                w = struct.unpack_from("<I", blob, i * 4)[0]
                op = w & 0xFC000000
                if op != 0x94000000 and op != 0x14000000:
                    continue
                imm = w & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                va = vm + i * 4
                if va + imm * 4 == target:
                    kind = "BL" if op == 0x94000000 else "B"
                    fi = bisect.bisect_right(starts, va) - 1
                    owner = starts[fi] if fi >= 0 else None
                    hits.append((kind, va, owner))
        print(f"  {name} {target:#x}: {len(hits)} direct branch(es)")
        for kind, va, owner in sorted(hits, key=lambda r: r[1]):
            print(f"      {kind} at {va:#x} in func {owner if owner is None else hex(owner)}")


if __name__ == "__main__":
    mode = sys.argv[1]
    build = sys.argv[2]
    targets = []
    for spec in sys.argv[3:]:
        addr, _, name = spec.partition(":")
        targets.append((int(addr, 16), name or hex(int(addr, 16))))
    if mode == "chainrefs":
        cmd_chainrefs(build, targets)
    elif mode == "callers":
        cmd_callers(build, targets)
    else:
        raise SystemExit(f"unknown mode {mode}")
