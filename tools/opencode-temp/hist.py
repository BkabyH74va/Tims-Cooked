import struct, collections, sys

def sections(path):
    d = open(path, "rb").read()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", d, 0)
    off = 32; out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            seg = d[off+8:off+24].rstrip(b"\0").decode()
            nsects = struct.unpack_from("<I", d, off+64)[0]
            so = off + 72
            for _ in range(nsects):
                sn = d[so:so+16].rstrip(b"\0").decode()
                addr, size = struct.unpack_from("<QQ", d, so+32)
                fo = struct.unpack_from("<I", d, so+48)[0]
                out.append((seg, sn, addr, size, fo)); so += 80
        off += cmdsize
    return d, out

path = sys.argv[1] if len(sys.argv) > 1 else r"G:/REPO\analysis\agx\2701\com.apple.AGXG18P"
d, secs = sections(path)
for seg, sn, addr, size, fo in secs:
    if sn in ("__const", "__mod_init_func", "__auth_got", "__got", "__auth_ptr", "__data"):
        vals = [struct.unpack_from("<Q", d, fo+i)[0] for i in range(0, size - size % 8, 8)]
        hi = collections.Counter(v >> 32 for v in vals)
        print("==", seg, sn, "n", len(vals), "distinct hi32", len(hi))
        for h, c in hi.most_common(8):
            print("   hi32", hex(h), c)
        nz = [v for v in vals if v]
        print("   sample", " ".join(hex(v) for v in nz[:6]))
