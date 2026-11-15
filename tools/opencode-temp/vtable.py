import struct

BASE = 0xfffffe0007004000
path = r"G:/REPO\analysis\agx\2701\com.apple.AGXG18P"
d = open(path, "rb").read()
magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", d, 0)
off = 32; secs = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", d, off)
    if cmd == 0x19:
        seg = d[off+8:off+24].rstrip(b"\0").decode()
        n = struct.unpack_from("<I", d, off+64)[0]
        so = off + 72
        for _ in range(n):
            sn = d[so:so+16].rstrip(b"\0").decode()
            addr, size = struct.unpack_from("<QQ", d, so+32)
            fo = struct.unpack_from("<I", d, so+48)[0]
            secs.append((seg, sn, addr, size, fo)); so += 80
    off += cmdsize
starts = sorted(int(x, 16) for x in open(r"G:/REPO\tools\opencode-temp\starts2701.txt", encoding="utf-16"))
ss = set(starts)
import bisect
for seg, sn, addr, size, fo in secs:
    if sn == "__const" and seg == "__DATA_CONST":
        for va in range(0xfffffe0007f2c240, 0xfffffe0007f2c600, 8):
            v = struct.unpack_from("<Q", d, fo + (va-addr))[0]
            target = BASE + (v & 0xFFFFFFFF) if v else 0
            tag = ""
            if v and (v & 0xFFFFFFFF) < 0x2000000:
                j = bisect.bisect_left(starts, target)
                tag = "START" if target in ss else ("nearest %+#x" % (target - starts[max(0, j-1)]))
            print(f"{va:#018x} = {v:#018x}  -> {target:#018x} {tag}")
