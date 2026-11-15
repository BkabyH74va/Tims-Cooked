import struct, sys

path = sys.argv[1]
data = open(path, "rb").read()
magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
assert magic == 0xFEEDFACF
off = 32
entries = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x80000035:  # LC_FILESET_ENTRY
        vmaddr, fileoff = struct.unpack_from("<QQ", data, off+8)
        name = data[off+24:off+24+64].split(b"\0", 1)[0].decode()
        entries.append((name, vmaddr, fileoff))
    off += cmdsize

def segs(moff):
    m, _, _, _, n, _, _, _ = struct.unpack_from("<IiiIIIII", data, moff)
    o = moff + 32
    out = []
    for _ in range(n):
        c, cs = struct.unpack_from("<II", data, o)
        if c == 0x19:
            name = data[o+8:o+24].rstrip(b"\0").decode()
            vm, vs = struct.unpack_from("<QQ", data, o+24)
            fo, fs = struct.unpack_from("<QQ", data, o+40)
            out.append((name, vm, vs, fo, fs))
        o += cs
    return out

targets = [0xfffffe00084ada84, 0xfffffe00084b1960]
print("entries", len(entries))
for name, vm, fo in entries:
    try:
        ss = segs(fo)
    except Exception as e:
        print("parse fail", name, e); continue
    hay = " ".join(f"{s[0]}:{s[1]:#x}-{s[1]+s[2]:#x}" for s in ss)
    for t in targets:
        if any(s[1] <= t < s[1]+s[2] for s in ss):
            print("target", hex(t), "owned by", name)
            print("   segs", hay)
