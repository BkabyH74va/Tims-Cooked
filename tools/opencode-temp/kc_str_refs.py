#!/usr/bin/env python3
"""Resolve the printable C strings a kernelcache kext function references.

Numpy-free. Tracks ADRP page registers across the function and decodes both
ADRP+ADD and ADRP+LDR/LDUR pairs into absolute VAs, then prints any target that
lands on an ASCII string.

Pitfalls this encodes:
  * use instruction.reg_name(reg) / md.reg_name(reg); there is no
    capstone.arm64.reg_name (an AttributeError here silently becomes "no refs"
    inside a broad try/except);
  * md.skipdata = True or literal pools truncate the disassembly;
  * mask immediates with & (2**64 - 1) before comparing against VAs.

Usage:
    python kc_str_refs.py 24A446 com.apple.iokit.IOSurface 0xfffffe000a359b78 0x5c [...]
"""
import sys

sys.path.insert(0, "G:/iOS 27.0.1/iOS/tools/opencode-temp")
sys.path.insert(0, "G:/iOS 27.0.1/iOS/tools/pylibs")
from kc_member import load_member, v2o              # noqa: E402
import capstone                                    # noqa: E402

MASK = (2 ** 64) - 1


def cstr_at(b, va, maxlen=110):
    try:
        off = v2o(b, va)
    except KeyError:
        return None
    data = b["data"]
    end = data.find(b"\0", off, off + maxlen)
    if end < 0 or end - off < 4:
        return None
    try:
        t = data[off:end].decode("ascii")
    except Exception:
        return None
    return t if all(32 <= ord(c) < 127 for c in t) else None


def refs(md, b, va, size):
    off = v2o(b, va)
    page = {}
    seen = []
    for ins in md.disasm(b["data"][off:off + size], va):
        m, ops = ins.mnemonic, ins.operands
        try:
            if m == "adrp" and len(ops) == 2:
                page[ins.reg_name(ops[0].reg)] = ops[1].imm & MASK
            elif m == "add" and len(ops) == 3 and ops[2].type == capstone.arm64.ARM64_OP_IMM:
                rn = ins.reg_name(ops[1].reg)
                if rn in page:
                    t = (page[rn] + ops[2].imm) & MASK
                    s = cstr_at(b, t)
                    if s and (t, s) not in seen:
                        seen.append((t, s))
            elif m in ("ldr", "ldur") and len(ops) == 2 and ops[1].type == capstone.arm64.ARM64_OP_MEM:
                rn = ins.reg_name(ops[1].mem.base)
                if rn in page:
                    t = (page[rn] + ops[1].mem.disp) & MASK
                    s = cstr_at(b, t)
                    if s and (t, s) not in seen:
                        seen.append((t, s))
        except Exception:
            continue
    return seen


def main(argv):
    if len(argv) < 4:
        raise SystemExit(__doc__)
    build, member = argv[1], argv[2]
    specs = []
    for a in argv[3:]:
        va, sz = a.split(":")
        specs.append((int(va, 16), int(sz, 16)))
    b = load_member(build, member)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    md.detail = True
    for va, size in specs:
        print("=== %s %s %#x sz=%#x ===" % (build, member, va, size))
        seen = refs(md, b, va, size)
        if seen:
            for t, s in seen:
                print("   %#x %r" % (t, s[:95]))
        else:
            print("   (no string refs)")


if __name__ == "__main__":
    sys.exit(main(sys.argv))