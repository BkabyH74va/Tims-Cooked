#!/usr/bin/env python3
"""Annotated arm64 kernelcache function dump.

Resolves, per instruction:
  - BL / conditional branches -> absolute target VA (and callee size + top strings)
  - ADRP+ADD / ADRP+LDR sequences -> absolute target, tagged as STRING / FUNC / DATA
Output is meant for reading control flow, so nothing is normalised away.
"""
import bisect
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "opencode-temp"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "pylibs"))
import capstone
from kc_fstarts import load_build, v2o, func_of, cstr_at

def u(x):
    """capstone stores arm64 immediates as signed int64; recover the unsigned VA."""
    return x & ((1 << 64) - 1)


md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True


def build_strings(b):
    """Map VA -> ascii string for every printable NUL-terminated literal."""
    out = {}
    d = b["data"]
    for nm, (vm, vsz, fo, fsz) in b["segs"].items():
        if "__TEXT" not in nm:
            continue
        blob = d[fo:fo + fsz]
        i = 0
        n = len(blob)
        while i < n:
            j = blob.find(b"\x00", i)
            if j < 0:
                break
            s = blob[i:j]
            if len(s) >= 4:
                try:
                    t = s.decode("ascii")
                    if all(32 <= ord(c) < 127 for c in t):
                        out[vm + i] = t
                except UnicodeDecodeError:
                    pass
            i = j + 1
    return out


def dump(bld, va, size, outpath):
    b = load_build(bld)
    strs = build_strings(b)
    starts = b["starts"]
    off = v2o(b, va)
    code = b["data"][off:off + size]

    # pre-compute per-function top strings for call annotation
    ref_cache = {}

    def callee_info(tgt):
        r = func_of(b, tgt)
        if not r:
            return None
        st, nx = r
        sz = (nx - st) if nx else 0
        key = st
        if key not in ref_cache:
            if sz > 0:
                try:
                    refs = sorted(func_refs(b, st, st + sz), key=len, reverse=True)[:3]
                except Exception:
                    refs = []
            else:
                refs = []
            ref_cache[key] = (sz, refs)
        return ref_cache[key]

    from kc_fstarts import func_refs

    # first pass: collect adrp results
    adrp = {}
    lines = []
    for ins in md.disasm(code, va):
        note = ""
        m = ins.mnemonic
        ops = ins.op_str
        try:
            op0 = int(ins.operands[0].imm) if False else None
        except Exception:
            op0 = None

        if m == "adrp":
            rd = ins.reg_name(ins.operands[0].reg)
            tgt = u(ins.operands[1].imm)
            adrp[rd] = tgt
            note = f"; page {tgt:#x}"
        elif m == "add":
            rd = ins.reg_name(ins.operands[0].reg)
            rn = ins.reg_name(ins.operands[1].reg)
            imm = u(ins.operands[2].imm)
            if rn in adrp:
                tgt = adrp[rn] + imm
                adrp[rd] = tgt
                tag = "?"
                if tgt in strs:
                    tag = f'STR "{strs[tgt]}"'
                else:
                    r = func_of(b, tgt)
                    if r and r[0] == tgt:
                        tag = f"FUNC {tgt:#x}"
                note = f"; {tgt:#x} {tag}"
        elif m in ("ldr", "ldrh", "ldrb", "ldrsw"):
            rn = ins.reg_name(ins.operands[1].mem.base) if len(ins.operands) > 1 else None
            if rn and rn in adrp:
                tgt = adrp[rn] + ins.operands[1].mem.disp
                tag = "?"
                if tgt in strs:
                    tag = f'STR "{strs[tgt]}"'
                else:
                    r = func_of(b, tgt)
                    if r and r[0] == tgt:
                        tag = f"FUNC {tgt:#x}"
                note = f"; [{tgt:#x}] {tag}"
                if m.startswith("ldr") and "w" not in m:
                    pass
        elif m == "bl":
            tgt = u(ins.operands[0].imm)
            ci = callee_info(tgt)
            if ci:
                sz, refs = ci
                rs = "; ".join(repr(x) for x in refs)
                note = f"; CALL {tgt:#x} sz={sz:#x} {rs}"
            else:
                note = f"; CALL {tgt:#x} NOFUNC"
        elif m.startswith("b") or m.startswith("cb") or m.startswith("tb"):
            if ins.operands and ins.operands[0].type == capstone.arm64.ARM64_OP_IMM:
                tgt = u(ins.operands[0].imm)
                r = func_of(b, tgt)
                tag = f"FUNC {r[0]:#x}" if r else "?"
                note = f"; -> {tgt:#x} {tag}"

        lines.append(f"{ins.address:#018x}  {ins.bytes.hex():<8} {m:<9}{ops}{note}")

    with open(outpath, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{bld} {va:#x}+{size:#x}: {len(lines)} insns -> {outpath}")


if __name__ == "__main__":
    dump(sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16), sys.argv[4])
