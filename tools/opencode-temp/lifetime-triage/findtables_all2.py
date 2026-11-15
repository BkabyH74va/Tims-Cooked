#!/usr/bin/env python3
"""Robust IOExternalMethodDispatch / IOUserClientMethodDispatch table finder.

Tries two layouts:
  A (24B): q0=function, q1=(scalarIn|structIn<<32), q2=(scalarOut|structOut<<32)
  B (32B): q0=function, q1=check-function, q2=(scalarIn|structIn<<32), q3=(scalarOut|structOut<<32)
Counts may be 0xffffffff (kIOUCVariableStructureSize).
"""
import struct, sys
import resolve as R
import kx

MEMBER = sys.argv[1] if len(sys.argv) > 1 else "com.apple.driver.AppleJPEGDriver"
m = kx.MachO(kx.EXTRACT / MEMBER)
syms = kx.load_symjson()
mem = [x for x in R.members() if x["name"] == MEMBER][0]
exec_ranges = [(vm, vm + vms) for n, vm, vms, so, ss in mem["segs"]
               if n in ("__TEXT", "__TEXT_EXEC")]

def tgt(q):
    t = R.BASE + (q & 0xFFFFFFFF) + mem["delta"]
    for lo, hi in exec_ranges:
        if lo <= t < hi:
            return t
    return None

def ok_count(v):
    return v <= 0x100000 or v == 0xFFFFFFFF

def sections():
    for s in m.sections:
        if s["size"] == 0 or s["offset"] == 0 or s["seg"] == "__LINKEDIT":
            continue
        b = m.data[s["offset"]:s["offset"] + s["size"]]
        n = len(b) // 8
        yield s, [struct.unpack_from("<Q", b, i * 8)[0] for i in range(n)]

def scan(seg_filter, layout, minrun):
    hits = []
    for s, v in sections():
        if seg_filter and s["seg"] not in seg_filter:
            continue
        n = len(v)
        used = set()
        for start in range(n):
            if start in used:
                continue
            run = []
            i = start
            stride = 3 if layout == "A" else 4
            while i + 2 < n:
                f = tgt(v[i])
                if f is None:
                    break
                if layout == "A":
                    w1, w2 = v[i + 1], v[i + 2]
                else:
                    if i + 3 >= n:
                        break
                    if tgt(v[i + 1]) is None and v[i + 1] != 0:
                        break
                    w1, w2 = v[i + 2], v[i + 3]
                si, sti = w1 & 0xFFFFFFFF, (w1 >> 32) & 0xFFFFFFFF
                so, sto = w2 & 0xFFFFFFFF, (w2 >> 32) & 0xFFFFFFFF
                if not (ok_count(si) and ok_count(sti) and ok_count(so) and ok_count(sto)):
                    break
                # implausible: structure counts in the low dword and scalar counts huge
                if sti < si:
                    break
                run.append((f, si, sti, so, sto))
                i += stride
            if len(run) >= minrun:
                for k in range(start, i, stride):
                    used.add(k)
                hits.append((s, start, run))
    return hits

for layout in ("A", "B"):
    for minrun in (4,):
        for s, start, run in scan(None, layout, minrun):
            print(f"\n=== layout {layout} @ {s['seg']}.{s['sect']}+0x{start*8:x} "
                  f"({len(run)} entries) ===")
            for k, (f, si, sti, so, sto) in enumerate(run):
                print(f"  sel {k:3d}: cb={f:#018x} scIn={si:#x} stIn={sti:#x} "
                      f"scOut={so:#x} stOut={sto:#x}  {syms.get(f,'')}")
