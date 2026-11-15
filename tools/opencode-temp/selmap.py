#!/usr/bin/env python3
"""Map IOSurfaceRootUserClient selectors to their method names.

The kext's assert strings ("create_surface", "create_surface_client_mem", ...)
sit in __TEXT next to the code.  Each handler references one with an
adrp/add pair, so we resolve the pair and read the string out of the
kernelcache.
"""
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments

KEXT = "com.apple.iokit.IOSurface"
STRIDE = 40
TABLE_OFF = 0x2638
TEXT_PAGES = (0xfffffe0007a190000, 0xfffffe0007a1a0000, 0xfffffe0007a1b0000,
              0xfffffe0007a1c0000, 0xfffffe0007a1d0000, 0xfffffe0007a1e0000,
              0xfffffe0007a1f0000, 0xfffffe0007a180000)


def main():
    kc = Path(sys.argv[1])
    dis = Path(sys.argv[2])
    data = kc.read_bytes()
    entries, _ = parse_fileset(data)
    e = [x for x in entries if x["name"] == KEXT][0]
    segs = member_segments(data, e["fileoff"])
    memb = [(s, vm, fo, fs) for s, (vm, vms, fo, fs) in segs.items() if fs]

    def vm_to_off(vm):
        for s, svm, fo, fs in memb:
            if svm <= vm < svm + fs:
                return fo + (vm - svm)
        return None

    def cstr(vm):
        off = vm_to_off(vm)
        if off is None:
            return None
        end = data.find(b"\x00", off, off + 300)
        if end < 0:
            return None
        try:
            return data[off:end].decode("ascii")
        except Exception:
            return None

    # ---- disassembly index -------------------------------------------------
    lines = dis.read_text(errors="replace").splitlines()
    ins = {}
    for ln in lines:
        m = re.match(r"^([0-9a-f]{16})\s+(.*)$", ln)
        if m:
            ins[int(m.group(1), 16)] = m.group(2).strip()

    starts = sorted(a for a, t in ins.items() if t.startswith("bti"))

    def fn_end(a):
        for f in starts:
            if f > a:
                return f
        return a + 0x1000

    # ---- dispatch table ----------------------------------------------------
    dcvm, dcvms, dcfo, dcfs = segs["__DATA_CONST"]
    base = dcfo + TABLE_OFF

    def thunk_target(h):
        for i in range(8):
            t = ins.get(h + i * 4)
            if t is None:
                return None
            m = re.match(r"b\s+#0x([0-9a-f]{16})", t)
            if m:
                return int(m.group(1), 16)
        return None

    def strings_in(fn):
        """resolve adrp/add pairs inside the function to cstrings"""
        out = []
        page = None
        page_at = None
        end = fn_end(fn)
        for a in range(fn, end, 4):
            t = ins.get(a)
            if t is None:
                continue
            m = re.match(r"adrp\s+(x\d+), #0x([0-9a-f]+)", t)
            if m:
                page = int(m.group(2), 16)
                page_at = a
                continue
            m = re.match(r"add\s+(x\d+), (x\d+), #0x([0-9a-f]+)", t)
            if m and page is not None and page_at is not None and a - page_at <= 32:
                vm = page + int(m.group(3), 16)
                if any(p <= vm < p + 0x10000 for p in TEXT_PAGES):
                    s = cstr(vm)
                    if s and len(s) > 3 and s.isprintable():
                        out.append((a, vm, s))
                page = None
        return out

    print("sel  method")
    for i in range(0x3C):
        raw = data[base + i * STRIDE: base + i * STRIDE + STRIDE]
        q = struct.unpack_from("<Q", raw)[0]
        low = q & 0xFFFFFFFF
        plain = q & 0x0000FFFFFFFFFFFF
        tex = segs.get("__TEXT_EXEC") or segs["__TEXT"]
        h = None
        if tex[0] <= plain < tex[0] + tex[1]:
            h = plain
        elif low:
            r = None
            for s, svm, fo, fs in memb:
                if fo <= low < fo + fs:
                    r = svm + (low - fo)
            if r is not None and tex[0] <= r < tex[0] + tex[1]:
                h = r
        if h is None:
            continue
        fn = thunk_target(h) or h
        names = []
        for a, vm, s in strings_in(fn):
            if s not in names:
                names.append(s)
        # keep only plausible method names
        keep = [s for s in names if re.match(r"^[a-z_][A-Za-z0-9_]*$", s) and len(s) > 4
                and not s.startswith("site.") and "IOSurface" not in s or "create" in s]
        print("0x%02x  fn=0x%x  %s" % (i, fn, ", ".join(names[:3]) if names else "-"))


if __name__ == "__main__":
    main()
