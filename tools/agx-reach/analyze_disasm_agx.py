#!/usr/bin/env python3
"""
Search AGXG18P disassembly for externalMethod dispatch logic.
Reads UTF-16LE disassembly and looks for:
1. externalMethod implementation
2. getTargetAndMethodForIndex
3. Switch statements on selector values
4. Calls to known helper functions
"""
from pathlib import Path

DISASM = Path("G:/REPO/analysis/agx/2701.disasm.txt")

with open(DISASM, "r", encoding="utf-16-le") as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")

# Search for key patterns
patterns = {
    "externalMethod": "externalMethod",
    "getTargetAndMethod": "getTargetAndMethodForIndex",
    "IOUserClient": "IOUserClient",
    "AGXDeviceUserClient": "AGXDeviceUserClient",
    "IOExternalMethodDispatch": "IOExternalMethodDispatch",
}

for pat_name, pat in patterns.items():
    hits = []
    for i, line in enumerate(lines):
        if pat in line:
            hits.append((i + 1, line.strip()))
    print(f"\n=== '{pat_name}' ({len(hits)} hits) ===")
    for ln, text in hits[:20]:
        print(f"  {ln:5d}: {text[:120]}")

# Look for cmp instructions against selector values (0x100, 0x101, 0x102, 0x105, 0x110)
print(f"\n=== CMP instructions against selector values ===")
selector_vals = ["#0x100", "#0x101", "#0x102", "#0x105", "#0x110", "#0x103", "#0x104", "#0x106", "#0x107", "#0x108", "#0x109", "#0x10A", "#0x10B", "#0x10C", "#0x10D", "#0x10E", "#0x10F"]
for sel in selector_vals:
    hits = []
    for i, line in enumerate(lines):
        if f"cmp" in line.lower() and sel in line:
            hits.append((i + 1, line.strip()))
    if hits:
        print(f"\n  {sel}:")
        for ln, text in hits[:10]:
            print(f"    {ln:5d}: {text[:120]}")

# Look for adrp instructions that reference the cstring page (where AGXDeviceUserClient string lives)
print(f"\n=== ADRP to cstring page (0xfffffe000712c000) ===")
adrp_hits = []
for i, line in enumerate(lines):
    if "adrp" in line.lower() and "0xfffffe000712c000" in line:
        adrp_hits.append((i + 1, line.strip()))
print(f"  Total: {len(adrp_hits)}")
for ln, text in adrp_hits[:20]:
    print(f"    {ln:5d}: {text[:120]}")

# Look for blraa (authenticated branch) instructions - these are vtable calls
print(f"\n=== blraa instructions (first 30) ===")
blraa_hits = []
for i, line in enumerate(lines):
    if "blraa" in line.lower():
        blraa_hits.append((i + 1, line.strip()))
print(f"  Total: {len(blraa_hits)}")
for ln, text in blraa_hits[:30]:
    print(f"    {ln:5d}: {text[:120]}")
