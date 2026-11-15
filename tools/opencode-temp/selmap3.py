#!/usr/bin/env python3
"""Map IOSurfaceRootUserClient selectors to the method names in their asserts."""
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments

KC = Path(sys.argv[1] if len(sys.argv) > 1 else "../../firmware/24A446/kernelcache.release.macho")
DIS = Path(sys.argv[2] if len(sys.argv) > 2 else "iosurface_27_0_1.disasm.txt")

data = KC.read_bytes()
entries, _ = parse_fileset(data)
e = [x for x in entries if x["name"] == "com.apple.iokit.IOSurface"][0]
segs = member_segments(data, e["fileoff"])
memb = [(s, vm, fo, fs) for s, (vm, vms, fo, fs) in segs.items() if fs]


def cstr(vm):
    for s, svm, fo, fs in memb:
        if svm <= vm < svm + fs:
            off = fo + (vm - svm)
            end = data.find(b"\x00", off, off + 400)
            if end < 0:
                return None
            try:
                return data[off:end].decode("ascii")
            except Exception:
                return None
    return None


ins = {}
for ln in DIS.read_text(errors="replace").splitlines():
    m = re.match(r"^([0-9a-f]{16})\s+(.*)$", ln)
    if m:
        ins[int(m.group(1), 16)] = m.group(2).strip()

starts = sorted(a for a, t in ins.items() if t.startswith("bti"))


def fn_end(a):
    for f in starts:
        if f > a:
            return f
    return a + 0x1000


RE_ADRP = re.compile(r"adrp\s+(x\d+), #0x([0-9a-f]+)")
RE_ADD = re.compile(r"add\s+(x\d+), (x\d+), #0x([0-9a-f]+)")
RE_B = re.compile(r"b\s+#0x([0-9a-f]{16})")


def method_names(fn):
    out = []
    page = None
    end = fn_end(fn)
    for a in range(fn, end, 4):
        t = ins.get(a)
        if t is None:
            continue
        m = RE_ADRP.match(t)
        if m:
            page = int(m.group(2), 16)
            continue
        m = RE_ADD.match(t)
        if m and page is not None:
            vm = page + int(m.group(3), 16)
            if 0xfffffe0007a180000 <= vm < 0xfffffe0007a200000:
                s = cstr(vm)
                if s and len(s) > 3 and s.isprintable() and s not in out:
                    out.append(s)
            page = None
    return out


def resolve(handler):
    for k in range(8):
        t = ins.get(handler + k * 4)
        if t is None:
            break
        m = RE_B.match(t)
        if m:
            return int(m.group(1), 16)
    return handler


base = segs["__DATA_CONST"][2] + 0x2638
texlo, texhi = segs["__TEXT_EXEC"][0], segs["__TEXT_EXEC"][0] + segs["__TEXT_EXEC"][1]
for i in range(0x3C):
    q = struct.unpack_from("<Q", data[base + i * 40: base + i * 40 + 40])[0]
    plain = q & 0x0000FFFFFFFFFFFF
    low = q & 0xFFFFFFFF
    h = None
    if texlo <= plain < texhi:
        h = plain
    else:
        for s, svm, fo, fs in memb:
            if fo <= low < fo + fs:
                r = svm + (low - fo)
                if texlo <= r < texhi:
                    h = r
    if h is None:
        print("0x%02x  unresolved" % i)
        continue
    fn = resolve(h)
    nm = [s for s in method_names(fn) if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", s)
          and not s.startswith("site.")]
    print("0x%02x  fn=0x%x  %s" % (i, fn, "; ".join(nm[:4]) if nm else "-"))
