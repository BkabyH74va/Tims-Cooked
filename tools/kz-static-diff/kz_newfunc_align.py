#!/usr/bin/env python3
"""Find functions added/removed in one kernelcache fileset member between two builds.

Method (numpy-free):
  1. LC_FUNCTION_STARTS per member gives exact function boundaries.
  2. Each function is fingerprinted by its disassembled instruction stream with
     kernel-slide-sensitive operands normalised:
       - ADRP page literals                      -> #A
       - ADD of an ADRP-derived register         -> #S
       - absolute branch targets inside the fn   -> L+off, outside -> E
       - memory displacements on ADRP bases      -> #G
  3. The two ordered function lists are aligned with difflib.SequenceMatcher.
     Pure insert/delete opcodes (no counterpart at all) are the strongest
     "new function" signal; replace blocks whose function counts differ are
     mixed additions/rewrites and need per-function review.

Usage:
    python kz_newfunc_align.py <member> [buildA buildB]

Example:
    python kz_newfunc_align.py com.apple.kernel
    python kz_newfunc_align.py com.apple.iokit.IOSkywalkFamily
"""
import sys, os, re, json, hashlib, pickle, difflib
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "opencode-temp"))
sys.path.insert(0, os.path.join(HERE, "..", "pylibs"))
from kc_member import load_member          # noqa: E402
from kc_fstarts import func_refs           # noqa: E402
import capstone                            # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402

TOK = re.compile(r"(#0x[0-9a-f]+|#\-?\d+)")
MEM = re.compile(r"\[([a-z][a-z0-9]*|\w+)((?:,[^\\]]*)?)\]")
ABSKVA = re.compile(r"#0xfffffe[0-9a-f]+")
LOADS = {"ldr", "ldp", "ldur", "ldurs", "ldrsw", "ldrb", "ldrsb", "ldrh",
         "ldrsh", "ldar", "ldarb", "ldarh", "ldxr", "ldxp", "ldadd", "ldadda"}
ARITH = {"add", "sub", "orr", "and", "eor", "bic", "mov", "movz", "movk",
         "adrl", "adr", "csel", "lsl", "lsr", "asr"}
MD = None


def reg_name(op):
    try:
        return MD.reg_name(op.reg)
    except Exception:
        return None


def ops_of(ins):
    try:
        return ins.operands
    except Exception:
        return []


def fp(b, va, size):
    off = None
    for nm, (vm, vsz, fo, fsz) in b["segs"].items():
        if vm <= va < vm + vsz:
            off = fo + (va - vm)
            break
    if off is None:
        raise KeyError(hex(va))
    code = b["data"][off:off + size]
    end = va + size
    glob = set()
    out = []
    for ins in MD.disasm(code, va):
        mn = ins.mnemonic
        ops = ins.op_str
        if mn == "adrp":
            rd = reg_name(ops_of(ins)[0]) if ops_of(ins) else None
            if rd:
                glob.add(rd)
            out.append("adrp %s,#A" % (rd or "?"))
            continue

        def repl(m):
            tok = m.group(0)
            try:
                tgt = int(tok.lstrip("#"), 0)
            except ValueError:
                return tok
            if tgt >= 0xfffffe0000000000:
                if va <= tgt < end:
                    return "L%+d" % (tgt - va)
                return "E"
            return tok
        ops = TOK.sub(repl, ops)

        def memrepl(m):
            base = m.group(1)
            if base in glob:
                return "[%s,#G]" % base
            return m.group(0)
        ops = MEM.sub(memrepl, ops)
        ops = ABSKVA.sub("#A", ops)
        _ops = ops_of(ins)
        if mn == "add" and len(_ops) >= 3 and \
           _ops[1].type == capstone.arm64.ARM64_OP_REG and \
           _ops[2].type == capstone.arm64.ARM64_OP_IMM:
            base = reg_name(_ops[1])
            dst = reg_name(_ops[0])
            if base in glob:
                ops = "add %s,%s,#S" % (dst, base)
        out.append("%s %s" % (mn, ops))
        if not _ops:
            continue
        op0 = _ops[0]
        dst = reg_name(op0) if op0.type == capstone.arm64.ARM64_OP_REG else None
        if mn in LOADS:
            continue
        if mn in ("str", "stp", "stur", "sturb", "sturh", "strb", "strh", "stlr",
                  "stlrb", "stlrh", "stxr", "stxp", "swpal", "casa", "casl", "cas"):
            continue
        if dst:
            if dst in glob:
                glob.discard(dst)
            if mn in ARITH:
                srcs = [reg_name(o) for o in _ops[1:]
                        if o.type == capstone.arm64.ARM64_OP_REG]
                if any(s in glob for s in srcs):
                    glob.add(dst)
    return "\n".join(out)


def build_all(member, build):
    cachedir = os.environ.get("KZ_NEWFUNC_CACHE") or os.path.join(
        os.path.expanduser("~"), ".cache", "kz-newfunc")
    os.makedirs(cachedir, exist_ok=True)
    cache = os.path.join(cachedir, "%s_%s.pkl" % (member.replace(".", "_"), build))
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    b = load_member(build, member)
    st = b["starts"]
    rows = []
    for i, s in enumerate(st):
        e = st[i + 1] if i + 1 < len(st) else s + 0x40
        f = fp(b, s, e - s)
        h = hashlib.sha1(f.encode()).hexdigest()[:16]
        refs = tuple(sorted(func_refs(b, s, e)))[:8]
        rows.append({"start": s, "size": e - s, "h": h, "refs": refs})
    pickle.dump(rows, open(cache, "wb"))
    return rows


def main(argv):
    global MD
    if len(argv) < 2:
        raise SystemExit(__doc__)
    member = argv[1]
    build_a = argv[2] if len(argv) > 2 else "24A446"
    build_b = argv[3] if len(argv) > 3 else "24B119"
    md = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    md.detail = True
    MD = md
    A = build_all(member, build_a)
    B = build_all(member, build_b)
    la = [r["h"] for r in A]
    lb = [r["h"] for r in B]
    sm = difflib.SequenceMatcher(None, la, lb, autojunk=False)
    ca, cb = Counter(la), Counter(lb)
    print("%s: A=%d funcs, B=%d funcs, shared exact fingerprints=%d"
          % (member, len(A), len(B), len(set(ca) & set(cb))))
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        na, nb = i2 - i1, j2 - j1
        sa = sum(A[k]["size"] for k in range(i1, i2))
        sb = sum(B[k]["size"] for k in range(j1, j2))
        marker = "  <-- COUNT DIFF" if na != nb else ""
        print("%-7s A=%-3d B=%-3d szA=%-7d szB=%-7d A@%s..%s B@%s..%s%s" % (
            tag, na, nb, sa, sb,
            "%#x" % A[i1]["start"] if i1 < i2 else "-",
            "%#x" % A[i2 - 1]["start"] if i1 < i2 else "-",
            "%#x" % B[j1]["start"] if j1 < j2 else "-",
            "%#x" % B[j2 - 1]["start"] if j1 < j2 else "-", marker))
        if tag in ("insert", "delete") or na != nb:
            for k in range(j1, j2):
                print("    B %#x sz=%#x refs=%s" % (B[k]["start"], B[k]["size"],
                                                    list(B[k]["refs"])[:3]))
            for k in range(i1, i2):
                print("    A %#x sz=%#x" % (A[k]["start"], A[k]["size"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
