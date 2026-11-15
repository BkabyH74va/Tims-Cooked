#!/usr/bin/env python3
"""Map IOSurface external-method selectors -> handler -> real function, and
flag which of those functions reach the drain/dispatchNotify path.

Dispatch table: kext __DATA_CONST, stride 40, entry i == selector i.
Handlers are short thunks; the real function is the target of the first
`b` inside the thunk.
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
DRAIN = 0xFFFFFE000A3338CC


def main():
    kc = Path(sys.argv[1])
    dis = Path(sys.argv[2])
    nmax = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x3C

    text = dis.read_text(errors="replace").splitlines()
    addr_line = []
    for ln in text:
        m = re.match(r"^([0-9a-f]{16})\s+(.*)$", ln)
        if m:
            addr_line.append((int(m.group(1), 16), m.group(2)))
    addr_line.sort()
    by_addr = {a: t for a, t in addr_line}
    addrs = [a for a, _ in addr_line]

    # function starts: a line whose text starts with "bti"
    func_starts = [a for a, t in addr_line if t.startswith("bti")]
    fstart_set = set(func_starts)

    def fn_end(addr):
        for f in func_starts:
            if f > addr:
                return f
        return addr + 0x1000

    def thunk_target(handler):
        # scan up to 8 instructions of the thunk for the branch
        for i in range(8):
            a = handler + i * 4
            t = by_addr.get(a)
            if t is None:
                return None
            m = re.match(r"b\s+#0x([0-9a-f]{16})", t)
            if m:
                return int(m.group(1), 16)
        return None

    def fn_calls_drain(fn):
        end = fn_end(fn)
        for a in addrs:
            if a < fn:
                continue
            if a >= end:
                break
            t = by_addr[a]
            if ("bl" in t) and ("#0xfffffe000a3338cc" in t):
                return True
        return False

    data = kc.read_bytes()
    entries, _ = parse_fileset(data)
    e = [x for x in entries if x["name"] == KEXT][0]
    segs = member_segments(data, e["fileoff"])
    memb = [(s, vm, fo, fs) for s, (vm, vms, fo, fs) in segs.items() if fs]
    tex = segs.get("__TEXT_EXEC") or segs["__TEXT"]

    def fo_to_vm(foff):
        for s, vm, fo, fs in memb:
            if fo <= foff < fo + fs:
                return vm + (foff - fo)
        return None

    dcvm, dcvms, dcfo, dcfs = segs["__DATA_CONST"]
    base_fo = dcfo + TABLE_OFF

    print("sel  handler          real fn           drain?")
    for i in range(nmax):
        raw = data[base_fo + i * STRIDE: base_fo + i * STRIDE + STRIDE]
        q = struct.unpack_from("<Q", raw)[0]
        low = q & 0xFFFFFFFF
        h = None
        plain = q & 0x0000FFFFFFFFFFFF
        if tex[0] <= plain < tex[0] + tex[1]:
            h = plain
        elif low:
            r = fo_to_vm(low)
            if r is not None and tex[0] <= r < tex[0] + tex[1]:
                h = r
        if h is None:
            print("0x%02x  unresolved raw=0x%016x" % (i, q))
            continue
        fn = thunk_target(h) or h
        print("0x%02x  0x%-14x 0x%-16x %s" % (i, h, fn, "DRAIN" if fn_calls_drain(fn) else ""))


if __name__ == "__main__":
    main()
