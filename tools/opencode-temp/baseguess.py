import struct

def load(path):
    d = open(path, "rb").read()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", d, 0)
    off = 32; secs = []
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
                secs.append((seg, sn, addr, size, fo)); so += 80
        off += cmdsize
    return d, secs

lab = "2701"
d, secs = load(r"G:/REPO\analysis\agx\2701\com.apple.AGXG18P")
starts = set(int(x, 16) for x in open(r"G:/REPO\tools\opencode-temp\starts2701.txt", encoding="utf-16"))
vals = []
for seg, sn, addr, size, fo in secs:
    if sn == "__mod_init_func":
        vals = [struct.unpack_from("<Q", d, fo+i*8)[0] & 0xFFFFFFFF for i in range(size//8)]
print("n", len(vals))
for base in [0xfffffe0007000000, 0xfffffe0007004000, 0xfffffe000700c000,
             0xfffffe0007123140, 0xfffffe00084b1960, 0xfffffe0008498000,
             0xfffffe0007000000 - 0x3edc, 0xfffffe0007004000 - 0x3edc]:
    ts = [base + v for v in vals]
    hits = sum(1 for t in ts if t in starts)
    print(hex(base), "hits", hits, "/", len(ts), "first", hex(ts[0]))
