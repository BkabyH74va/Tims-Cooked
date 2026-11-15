import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments

KC = Path("../../firmware/24A446/kernelcache.release.macho")
DIS = Path("iosurface_27_0_1.disasm.txt")
SELS = [0x1e, 0x22, 0x1a, 0x2e, 0x36, 0x0a, 0x13, 0x18, 0x2f, 0x30, 0x32, 0x09]

data = KC.read_bytes()
entries, _ = parse_fileset(data)
e = [x for x in entries if x["name"] == "com.apple.iokit.IOSurface"][0]
segs = member_segments(data, e["fileoff"])
memb = [(s, vm, fo, fs) for s, (vm, vms, fo, fs) in segs.items() if fs]
tex = segs["__TEXT_EXEC"]


def fo_to_vm(fo):
    for s, vm, foff, fs in memb:
        if foff <= fo < foff + fs:
            return vm + (fo - foff)
    return None


ins = {}
for ln in DIS.read_text(errors="replace").splitlines():
    m = re.match(r"^([0-9a-f]{16})\s+(.*)$", ln)
    if m:
        ins[int(m.group(1), 16)] = m.group(2).strip()

base = segs["__DATA_CONST"][2] + 0x2638
for sel in SELS:
    q = struct.unpack_from("<Q", data[base + sel * 40: base + sel * 40 + 40])[0]
    plain = q & 0x0000FFFFFFFFFFFF
    low = q & 0xFFFFFFFF
    h = plain if tex[0] <= plain < tex[0] + tex[1] else None
    if h is None:
        r = fo_to_vm(low)
        h = r if (r is not None and tex[0] <= r < tex[0] + tex[1]) else None
    if h is None:
        print("0x%02x unresolved" % sel)
        continue
    print("\n===== sel 0x%02x  thunk 0x%x =====" % (sel, h))
    fn = h
    for k in range(8):
        t = ins.get(h + k * 4)
        if t is None:
            break
        print("   thunk: " + t)
        m = re.match(r"b\s+#0x([0-9a-f]{16})", t)
        if m:
            fn = int(m.group(1), 16)
            break
    print("   --- real fn 0x%x ---" % fn)
    n = 0
    for a in range(fn, fn + 0x140, 4):
        t = ins.get(a)
        if t is None:
            break
        if t.startswith("bti"):
            continue
        print("   0x%x  %s" % (a, t))
        n += 1
        if n >= 26:
            break
