import struct, sys

BASE = 0xfffffe0007004000

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

def scan(path, targets):
    d, secs = load(path)
    print("== scan", path)
    for t in targets:
        rel = (t - BASE) & 0xFFFFFFFF
        print(f"-- target {t:#x} rel {rel:#x}")
        hits = 0
        for seg, sn, addr, size, fo in secs:
            for i in range(0, size - 7, 8):
                v = struct.unpack_from("<Q", d, fo+i)[0]
                low = v & 0xFFFFFFFF
                if low == rel:
                    print(f"   {addr+i:#018x} = {v:#018x}  {seg}.{sn}")
                    hits += 1
        print("   hits", hits)

if __name__ == "__main__":
    path = sys.argv[1]
    targets = [int(x, 16) for x in sys.argv[2:]]
    scan(path, targets)
