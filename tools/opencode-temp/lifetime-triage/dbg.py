#!/usr/bin/env python3
import sys, struct
import kx, resolve as R

member = sys.argv[1]
m = kx.MachO(kx.EXTRACT / member)
print("segments:")
for s in m.segments:
    print(f"  {s['name']:14s} vm={s['vmaddr']:#018x} vms={s['vmsize']:#x} foff={s['fileoff']:#x} fsz={s['filesize']:#x}")
print("sections:")
for s in m.sections:
    print(f"  {s['seg']}/{s['sect']:24s} addr={s['addr']:#018x} size={s['size']:#x} off={s['offset']:#x}")

# locate this member in the kernelcache member list
for mem in R.members():
    if mem["name"] == member:
        print("kc member:", mem["name"], f"vm={mem['vmaddr']:#x}", f"delta={mem['delta']:#x}")
        for sg in mem["segs"]:
            print("   kc seg:", sg)
        break
else:
    print("member not found in kc list")

# try resolving known addresses
for a in sys.argv[2:]:
    t = int(a, 0)
    # compute expected encoded low32 for each member
    for mem in R.members():
        low = (t - R.BASE) - mem["delta"]
        cands = R.resolve(low & 0xFFFFFFFF)
        if cands:
            for c in cands:
                print(f"{t:#018x}: low={low & 0xFFFFFFFF:#010x} via {mem['name']} -> {c[0]:#018x} {c[1]} {c[2]}")
            break
