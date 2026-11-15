f = "disasm\\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt"
lo = 0xFFFFFE0007530000
hi = 0xFFFFFE0007530900
hits = []
cur = None
for ln in open(f, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+):", ln) if False else None
import re

cur = None
for ln in open(f, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+):", ln)
    if m:
        cur = int(m.group(1), 16)
    if cur is None:
        continue
    if lo <= cur < hi and ("RequestHandling" in ln or "AppleJPEGHal" in ln or "AppleJPEGDart" in ln):
        hits.append((cur, ln.rstrip()))

with open("/tmp/jpg_hits.txt", "w") as fh:
    for a, l in hits:
        fh.write("%x  %s\n" % (a, l))
print("hits", len(hits))
