#!/usr/bin/env python3
"""Byte-exact census of the 27.2 `and ...,#~0x100 ; str ...,[...+8]` idiom.

Motivation (2026-11-16): `kz_mask_by_member.py` counts the idiom by *disassembling*
each member's __TEXT_EXEC slice, which is correct but slow and depends on
capstone staying in sync. This tool instead counts the exact 8-byte instruction
pair as raw bytes inside each member's own segment window, so the result cannot
be perturbed by literal pools or by a disassembly desync.

IMPORTANT METHOD RULE this exists to enforce: **never compare a literal VA
across builds.** Members are laid out differently between 24A446 and 24B119, so
the same VM address (and even the same file offset) holds unrelated code in the
other build -- e.g. `0xfffffe000a14b460` is IOHIDFamily's external-method
dispatcher in 24B119 but `IOMobileGraphicsFamily-DCP` code at the *same file
offset* in 24A446. Attribute only through a member's own segment window, or by
shape/index pairing, never by carrying an address from one build into another.

Usage:
    python kz_mask_bytes.py                 # per-member census, both builds
    python kz_mask_bytes.py --pairs HID     # pair thunk-shaped fns by index
"""
import argparse
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))

from kc_iosurface import parse_fileset, member_segments  # noqa: E402

# `and x11, x11, #0xfffffffffffffeff` ; `str x11, [x23, #8]`
IDIOM_X11_X23 = bytes.fromhex("6bf97792eb0600f9")
# The thunk prologue constant pair `mov w?,#0x2bf ; movk w?,#0xe000,lsl#16`,
# i.e. the baked default kIOReturnIPCError (0xE00002BF).
THUNK_SHAPE = bytes.fromhex("f35780521300bc72")

BUILDS = ("24A446", "24B119")


def member_exec_windows(data):
    """name -> {segname: (vmaddr, vmsize, fileoff, filesize)} for real segments."""
    entries, _ = parse_fileset(data)
    out = {}
    for e in entries:
        try:
            segs = member_segments(data, e["fileoff"])
        except Exception:
            continue
        live = {nm: s for nm, s in segs.items() if s[3]}
        if live:
            out[e["name"]] = live
    return out


def count_idiom(blob, needle=IDIOM_X11_X23):
    n = 0
    i = 0
    while True:
        i = blob.find(needle, i)
        if i < 0:
            break
        n += 1
        i += 1
    return n


def census(topn=20):
    res = {}
    for bld in BUILDS:
        data = (ROOT / "firmware" / bld / "kernelcache.release.macho").read_bytes()
        wins = member_exec_windows(data)
        per = {}
        for name, segs in wins.items():
            te = segs.get("__TEXT_EXEC")
            if not te:
                continue
            vm, vsz, fo, fsz = te
            per[name] = (
                count_idiom(data[fo:fo + fsz]),
                count_idiom(data[fo:fo + fsz], THUNK_SHAPE),
            )
        res[bld] = per
    keys = sorted(set(res["24A446"]) | set(res["24B119"]),
                  key=lambda k: -(res["24B119"].get(k, (0, 0))[0]
                                  - res["24A446"].get(k, (0, 0))[0]))
    print("%-52s %9s %9s %9s   %9s %9s" %
          ("member", "A idiom", "B idiom", "delta", "A shape", "B shape"))
    ta = tb = 0
    for k in keys[:topn]:
        a = res["24A446"].get(k, (0, 0))
        b = res["24B119"].get(k, (0, 0))
        ta += a[0]
        tb += b[0]
        print("%-52s %9d %9d %+9d   %9d %9d" % (k, a[0], b[0], b[0] - a[0], a[1], b[1]))
    print("totals over listed members: A=%d B=%d" % (ta, tb))
    print("image-wide: A=%d B=%d" % (
        sum(v[0] for v in res["24A446"].values()),
        sum(v[0] for v in res["24B119"].values())))


def pairs(member):
    """Pair the thunk-shaped functions of one member across builds by sequence
    index and report the byte-size delta and whether the idiom is present."""
    import bisect
    import capstone
    from capstone.arm64 import ARM64_OP_IMM

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    MASK = 0xFFFFFFFFFFFFFEFF

    def collect(bld):
        from kc_member import load_member
        b = load_member(bld, member)
        d = b["data"]
        te = b["segs"]["__TEXT_EXEC"]
        vm, vsz, fo, fsz = te
        st = sorted(b["starts"])
        blob = d[fo:fo + fsz]
        out = []
        i = 0
        while True:
            i = blob.find(THUNK_SHAPE, i)
            if i < 0:
                break
            if i % 4 == 0:
                va = vm + i
                k = bisect.bisect_right(st, va) - 1
                if k >= 0:
                    fn = st[k]
                    nxt = st[k + 1] if k + 1 < len(st) else vm + vsz
                    body = d[fo + (fn - vm):fo + (fn - vm) + (nxt - fn)]
                    clear = False
                    for ins in md.disasm(body, fn):
                        if ins.mnemonic != "and":
                            continue
                        try:
                            ops = ins.operands
                        except Exception:
                            continue
                        if (len(ops) >= 3 and ops[-1].type == ARM64_OP_IMM
                                and (ops[-1].imm & ((1 << 64) - 1)) == MASK):
                            clear = True
                            break
                    out.append((fn, nxt - fn, clear))
            i += 1
        return out

    A = collect("24A446")
    B = collect("24B119")
    print("%s: A thunks=%d B thunks=%d" % (member, len(A), len(B)))
    print("%3s %18s %7s %7s %7s %7s  %s" %
          ("#", "A fn", "A sz", "B fn", "B sz", "dsz", "A->B clear"))
    gained = 0
    for k in range(min(len(A), len(B))):
        fa, sa, ca = A[k]
        fb, sb, cb = B[k]
        print("%3d %#18x %#7x %#18x %#7x %+7x  %s->%s" %
              (k, fa, sa, fb, sb, sb - sa, ca, cb))
        if cb and not ca:
            gained += 1
    print("pairs where B clears and A does not: %d/%d" % (gained, min(len(A), len(B))))


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", metavar="MEMBER",
                    help="pair thunk-shaped functions of MEMBER across builds")
    ap.add_argument("--topn", type=int, default=20)
    a = ap.parse_args(argv[1:])
    if a.pairs:
        pairs(a.pairs)
    else:
        census(a.topn)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
