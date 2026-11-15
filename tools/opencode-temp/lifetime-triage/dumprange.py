import re

f = r"disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt"
LO = 0xFFFFFE0009030000
HI = 0xFFFFFE0009030900
out = []
cur = None
started = False
for ln in open(f, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+):", ln)
    if m:
        cur = int(m.group(1), 16)
    if cur is None:
        continue
    if not started and cur >= LO:
        started = True
    if started and cur < HI:
        out.append(ln.rstrip())
    elif started and cur >= HI:
        break

d = "\n".join(out)
open("/tmp/jpg2.txt", "w").write(d)
print("LINES", len(out))
print(d[:2500])
