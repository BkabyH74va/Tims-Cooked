#!/usr/bin/env python3
"""For each JPEG method reference address, find its enclosing function start,
then search the extracted kext for chained-fixup encodings of that start."""
import re, struct
import resolve as R
import kx

DIS = r"G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt"
M = "com.apple.driver.AppleJPEGDriver"
mem = [x for x in R.members() if x["name"] == M][0]
m = kx.MachO(kx.EXTRACT / M)
syms = kx.load_symjson()

rows = []
for l in open(DIS, "r", errors="replace"):
    mm = re.match(r"\s*(?:0x)?(fffffe[0-9a-f]+):", l)
    if mm:
        rows.append((int(mm.group(1), 16), l.rstrip()))

refs = {
    "startDecoder":     0xfffffe000900bf58,
    "startDecoderExt":  0xfffffe000900c93c,
    "startEncoder":     0xfffffe000900d0d4,
    "startEncoderExt":  0xfffffe000900d4e8,
    "startDecoder2024": 0xfffffe000900d950,
    "startEncoder2024": 0xfffffe000900dfec,
}

def func_start(addr):
    prev = None
    for a, l in rows:
        if a > addr:
            break
        if "pacibsp" in l or ("bti\tc" in l):
            prev = a
    return prev

starts = {}
for name, a in refs.items():
    s = func_start(a)
    starts[name] = s
    print(f"{name:18s} ref={a:#018x} start={s:#018x}  {syms.get(s,'')}")

print("\n=== occurrences of chained-fixup low32 in the kext ===")
for name, s in starts.items():
    if s is None:
        continue
    low = (s - R.BASE - mem["delta"]) & 0xFFFFFFFF
    print(f"\n{name}: start={s:#x} low32={low:#010x}")
    needle = struct.pack("<I", low)
    for sec in m.sections:
        if sec["size"] == 0 or sec["offset"] == 0 or sec["seg"] == "__LINKEDIT":
            continue
        blob = m.data[sec["offset"]:sec["offset"] + sec["size"]]
        i = blob.find(needle)
        while i >= 0:
            if i % 4 == 0:
                va = sec["addr"] + i
                print(f"   {sec['seg']}.{sec['sect']} +0x{i:x}  va={va:#018x}")
            i = blob.find(needle, i + 1)
