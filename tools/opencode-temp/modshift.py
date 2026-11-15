import struct, bisect

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

base = 0xfffffe0007000000
for lab, path in [("2701", r"G:/REPO\analysis\agx\2701\com.apple.AGXG18P"),
                  ("272",  r"G:/REPO\analysis\agx\272\com.apple.AGXG18P")]:
    d, secs = sections(path)
    starts = sorted(int(x, 16) for x in open(r"G:/REPO\tools\opencode-temp\starts" + lab + ".txt", encoding="utf-16"))
    ss = set(starts)
    print("====", lab, "text", hex(starts[0]), hex(starts[-1]))
    for seg, sn, addr, size, fo in secs:
        if sn == "__mod_init_func":
            ts = [base + struct.unpack_from("<Q", d, fo+i*8)[0] % (1 << 32) for i in range(size//8)]
            for shift in (0, 0x3edc, 4, 8):
                hit = sum(1 for t in ts if (t + shift) in ss)
                print(" shift", hex(shift), "exact-start hits", hit, "/", len(ts))
            t = ts[0]
            print(" first target", hex(t), "candidates near:", [hex(s) for s in starts[:3]])
