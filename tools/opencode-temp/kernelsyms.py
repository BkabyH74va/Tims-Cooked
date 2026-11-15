#!/usr/bin/env python3
"""Resolve kernel virtual addresses to symbol names using the 27.0.1 kernelcache's
symbol table(s), and annotate an ipsw disassembly dump with resolved names."""
import bisect
import struct
import sys

sys.path.insert(0, r"G:/REPO\tools\opencode-temp")
from kc import KC, parse_fileset, cstr

KC_DATA = KC.read_bytes()
ENTRIES, _ = parse_fileset(KC_DATA)


def load_symtab(base):
    """Return {addr: name} from the Mach-O at *base* (absolute file offset)."""
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", KC_DATA, base)
    off = base + 32
    symoff = stroff = nsyms = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", KC_DATA, off)
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, _ = struct.unpack_from("<IIII", KC_DATA, off + 8)
        off += cmdsize
    if symoff is None:
        return {}
    out = {}
    for i in range(nsyms):
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(
            "<IBBHQ", KC_DATA, symoff + i * 16)
        if n_value == 0:
            continue
        name = cstr(KC_DATA, stroff + n_strx, 256)
        if name:
            out.setdefault(n_value, name)
    return out


def all_symbols():
    syms = {}
    for name, vmaddr, fileoff, eid, cmdoff in ENTRIES:
        if fileoff == 0 or fileoff >= len(KC_DATA):
            continue
        try:
            s = load_symtab(fileoff)
        except Exception:
            continue
        if s:
            syms[name] = s
    return syms


def merge(syms):
    m = {}
    for per in syms.values():
        for a, n in per.items():
            m.setdefault(a, n)
    return m


if __name__ == "__main__":
    per = all_symbols()
    for k, v in per.items():
        print(f"{k}: {len(v)} symbols")
    m = merge(per)
    print(f"merged: {len(m)} symbols")
    import pickle
    with open(r"G:/REPO\tools\opencode-temp\kernelsyms.pkl", "wb") as f:
        pickle.dump(m, f)
