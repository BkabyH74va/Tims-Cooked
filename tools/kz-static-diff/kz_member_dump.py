#!/usr/bin/env python3
"""Annotate one function of a fileset member: string refs + direct call targets.

`annot.py` only covers the `com.apple.kernel` entry (`kc_fstarts.load_build`).
Kext members need their own segment table, so this tool wraps
`kc_member.load_member` and performs the same annotation: ADRP+ADD / ADRP+LDR
literal resolution, BL/B target resolution, and printable-string decoding at
the resolved VA. Nothing is normalised away.

Usage:
    python kz_member_dump.py 24A446 com.apple.iokit.IOSkywalkFamily 0xfffffe000a2ea33c 0x618 [out.s]
"""
import bisect
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM  # noqa: E402
from kc_member import load_member, v2o, func_of  # noqa: E402

MD = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True
MD.skipdata = True
u = lambda x: x & ((1 << 64) - 1)  # noqa: E731


def cstr(b, va, maxlen=120):
    """Printable NUL-terminated run at va, or None."""
    try:
        off = v2o(b, va)
    except KeyError:
        return None
    d = b["data"]
    end = d.find(b"\x00", off, off + maxlen)
    if end < 0:
        return None
    raw = d[off:end]
    if len(raw) < 4:
        return None
    if all(32 <= c < 127 or c in (9, 10) for c in raw):
        return raw.decode("ascii")
    return None


def seg_of(b, va):
    for nm, (vm, vsz, fo, fsz) in b["segs"].items():
        if vm <= va < vm + vsz:
            return nm
    return None


def annotate(bld, member, va, sz, out):
    b = load_member(bld, member)
    w = out.open("w") if hasattr(out, "open") else out
    try:
        w.write("; %s %s fn %#x sz %#x\n" % (bld, member, va, sz))
        st = func_of(b, va)
        w.write("; starts: %s\n" % ("none" if not st else
                                    "%#x..%s" % (st[0], hex(st[1]) if st[1] else "?")))
        off = v2o(b, va)
        code = b["data"][off:off + sz]
        adrp = {}
        for ins in MD.disasm(code, va):
            site = ins.address
            ops = ins.operands
            if ins.mnemonic == "adrp":
                adrp[ins.reg_name(ops[0].reg)] = u(ops[1].imm)
                continue
            if ins.mnemonic == "add" and len(ops) >= 3 and ops[2].type == ARM64_OP_IMM:
                src = ins.reg_name(ops[1].reg)
                if src in adrp:
                    tgt = adrp[src] + ops[2].imm
                    s = seg_of(b, tgt)
                    txt = cstr(b, tgt)
                    tag = "STRING" if txt else (s or "EXT")
                    w.write("%#018x  %-8s -> %#018x [%s] %s\n" %
                            (site, ins.mnemonic, tgt, tag, ('"%s"' % txt) if txt else ""))
                    continue
            if ins.mnemonic.startswith("ldr") and len(ops) >= 2 and \
                    ops[-1].type == ARM64_OP_MEM and ops[-1].mem.base == 0:
                tgt = u(site + ops[-1].mem.disp)
                s = seg_of(b, tgt)
                txt = cstr(b, tgt)
                tag = "STRING" if txt else (s or "EXT")
                w.write("%#018x  %-8s -> %#018x [%s] %s\n" %
                        (site, ins.mnemonic, tgt, tag, ('"%s"' % txt) if txt else ""))
                continue
            if ins.mnemonic in ("bl", "b") and ops and ops[0].type == ARM64_OP_IMM:
                tgt = u(ops[0].imm)
                f = func_of(b, tgt)
                w.write("%#018x  %-8s -> %#018x %s\n" %
                        (site, ins.mnemonic, tgt,
                         ("FUNC" if f and f[0] == tgt else seg_of(b, tgt) or "EXT")))
                continue
    finally:
        if w is not out:
            w.close()


def main(argv):
    if len(argv) < 5:
        raise SystemExit(__doc__)
    out = sys.stdout if argv[5] == "-" else Path(argv[5])
    annotate(argv[1], argv[2], int(argv[3], 16), int(argv[4], 16), out)


if __name__ == "__main__":
    main(sys.argv)
