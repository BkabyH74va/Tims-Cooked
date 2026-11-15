#!/usr/bin/env python3
"""Find IOExternalMethodDispatch-style tables in an extracted kext.

Scans every non-LINKEDIT section for runs of records:
    { cb(low32 chained-fixup), w1 = scalarIn | structIn<<32, w2 = scalarOut | structOut<<32 }
with stride 24 (3 qwords) or 32 (4 qwords, + extra qword).

Only records whose callback resolves into THIS member's __TEXT/__TEXT_EXEC
are kept, so noise is low.
"""
import struct, sys
import resolve as R
import kx

MEMBER = sys.argv[1] if len(sys.argv) > 1 else "com.apple.driver.AppleJPEGDriver"
m = kx.MachO(kx.EXTRACT / MEMBER)
syms = kx.load_symjson()

# this member's exec ranges, per the kernelcache resolver
mine = None
for mem in R.members():
    if mem["name"] == MEMBER:
        mine = mem
        break
if mine is None:
    raise SystemExit(f"member {MEMBER} not found in kernelcache")

exec_ranges = [(vm, vm + vms) for (n, vm, vms, so, ss) in mine["segs"]
               if n in ("__TEXT", "__TEXT_EXEC")]

def target_for(low32):
    t = R.BASE + low32 + mine["delta"]
    for lo, hi in exec_ranges:
        if lo <= t < hi:
            return t
    return None

def qwords(seg, sect=None):
    for s in m.sections:
        if s["seg"] != seg:
            continue
        if sect and s["sect"] != sect:
            continue
        if s["size"] == 0 or s["offset"] == 0:
            continue
        b = m.data[s["offset"]:s["offset"] + s["size"]]
        n = len(b) // 8
        yield s, [struct.unpack_from("<Q", b, i * 8)[0] for i in range(n)]

def scan(seg, sect, stride, minrun):
    hits = []
    for s, vals in qwords(seg, sect):
        n = len(vals)
        used = set()
        for start in range(n):
            if start in used:
                continue
            run = []
            i = start
            while i < n:
                cbv = vals[i]
                low = cbv & 0xFFFFFFFF
                t = target_for(low)
                if t is None:
                    break
                if i + 2 >= n:
                    break
                w1, w2 = vals[i + 1], vals[i + 2]
                lo1, hi1 = w1 & 0xFFFFFFFF, (w1 >> 32) & 0xFFFFFFFF
                lo2, hi2 = w2 & 0xFFFFFFFF, (w2 >> 32) & 0xFFFFFFFF
                if max(lo1, hi1, lo2, hi2) > 0x100000:
                    break
                run.append((t, lo1, hi1, lo2, hi2))
                i += stride
            if len(run) >= minrun:
                for k in range(start, i, stride):
                    used.add(k)
                hits.append((s, start, run))
    return hits

for stride, name in ((3, "24B"), (4, "32B")):
    for minrun in (3,):
        for seg in ("__TEXT", "__DATA_CONST", "__DATA"):
            hits = scan(seg, None, stride, minrun)
            for s, start, run in hits:
                print(f"\n=== {name} table in {s['seg']}.{s['sect']} @ "
                      f"0x{s['addr'] + start*8:018x}  ({len(run)} entries) ===")
                for k, (t, si, sti, so, sto) in enumerate(run):
                    sn = syms.get(t, "")
                    print(f"  sel {k:3d}: cb={t:#018x} scIn={si:#x} stIn={sti:#x} "
                          f"scOut={so:#x} stOut={sto:#x}  {sn}")
