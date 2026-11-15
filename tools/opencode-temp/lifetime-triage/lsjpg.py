import struct

f = "disasm\\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt"
m = "G:/REPO\\tools\\opencode-temp\\lifetime-triage\\extract\\com.apple.driver.AppleJPEGDriver"

off = 32
base = None
fs_off = fs_size = None
data = open(m, "rb").read()
for _ in range(200):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x26:
        fs_off, fs_size = struct.unpack_from("<II", data, off + 8)
    off += cmdsize
text = None
for _ in range(200):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        segname = data[off+8:off+24].rstrip(b"\0").decode()
        nsects = struct.unpack_from("<I", data, off+80)[0]
        if segname == "__TEXT_EXEC":
            stroff = struct.unpack_from("<I", data, off+72)[0]
            fsize = struct.unpack_from("<I", data, off+84)[0]
            text = (stroff, fsize)
    off += cmdsize

stroff, fsize = text
base = 0xFFFFFE0009002170
starts = []
i = 0
addr = base
d = data[stroff:stroff+fsize]
i = 0
cur = base
vals = []
while i < len(d):
    val = 0
    shift = 0
    while True:
        b = d[i]
        i += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    if val == 0:
        break
    cur += val
    vals.append(cur)
    addr = cur

with open("/tmp/jpg_fs.txt", "w") as fh:
    for v in vals:
        fh.write("%x\n" % v)
print("count", len(vals))
print("first", [hex(v) for v in vals[:10]])
print("last", [hex(v) for v in vals[-10:]])
