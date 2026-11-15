#!/usr/bin/env python3
"""Scan a kext's own __DATA/__DATA_CONST for IOExternalMethodDispatch-style
tables: runs of 24-byte records whose first word is a chained-fixup pointer to
a function inside this kext and whose next two words hold size/limit fields."""
import struct
import sys
import resolve as R
import kx


def main():
    member = sys.argv[1]
    m = kx.MachO(kx.EXTRACT / member)
    syms = kx.load_symjson()
    # executable range of this member
    exec_ranges = []
    for s in m.segments:
        if s["name"] in ("__TEXT_EXEC", "__TEXT"):
            exec_ranges.append((s["vmaddr"], s["vmaddr"] + s["vmsize"]))

    def in_exec(v):
        return any(lo <= v < hi for lo, hi in exec_ranges)

    for seg in m.segments:
        if seg["name"] not in ("__DATA", "__DATA_CONST"):
            continue
        if seg["filesize"] == 0:
            continue
        base = seg["vmaddr"]
        data = m.data[seg["fileoff"]:seg["fileoff"] + seg["filesize"]]
        n = len(data) // 8
        vals = [struct.unpack_from("<Q", data, i * 8)[0] for i in range(n)]
        lows = [v & 0xFFFFFFFF for v in vals]
        runs = []
        i = 0
        while i + 3 <= n:
            cands = R.resolve(lows[i])
            if cands and in_exec(cands[0][0]):
                j = i
                run = []
                while j + 3 <= n:
                    c = R.resolve(lows[j])
                    if not (c and in_exec(c[0][0])):
                        break
                    w1 = vals[j + 1]
                    w2 = vals[j + 2]
                    lo1, hi1 = w1 & 0xFFFFFFFF, (w1 >> 32) & 0xFFFFFFFF
                    lo2, hi2 = w2 & 0xFFFFFFFF, (w2 >> 32) & 0xFFFFFFFF
                    if hi1 > 0x100000 or hi2 > 0x100000 or lo1 > 0x100000 or lo2 > 0x100000:
                        break
                    run.append((j, c[0][0], lo1, hi1, lo2, hi2))
                    j += 3
                if len(run) >= 2:
                    runs.append((i, run))
                    i = j
                    continue
            i += 1
        for start, run in runs:
            print(f"\n=== candidate dispatch table @ {base + start*8:#018x} "
                  f"({seg['name']}), {len(run)} entries ===")
            for k, (j, fn, lo1, hi1, lo2, hi2) in enumerate(run):
                sn = syms.get(fn, "")
                print(f"  sel {k:3d}: cb={fn:#018x} {sn:45s} "
                      f"w1=({lo1:#x},{hi1:#x}) w2=({lo2:#x},{hi2:#x})")


if __name__ == "__main__":
    main()
