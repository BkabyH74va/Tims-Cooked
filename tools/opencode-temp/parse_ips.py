#!/usr/bin/env python3
import json, sys

p = "/tmp/crashlogs/AGXProbe-2026-11-08-151733.ips"
raw = open(p, "r", errors="replace").read()
# crash .ips = one JSON header line + one JSON body
body = raw.split("\n", 1)[1]
d = json.loads(body)

print("exception:", d.get("exception"))
print("termination:", d.get("termination"))
print("faultingThread:", d.get("faultingThread"))
print()
th = d["threads"][d["faultingThread"]]
print("thread name:", th.get("name"), "queue:", th.get("queue"))
print("frames:")
for i, f in enumerate(th.get("frames", [])[:40]):
    img = f.get("imageIndex")
    imgname = d["usedImages"][img].get("name") if img is not None and img < len(d.get("usedImages", [])) else "?"
    sym = f.get("symbol", "")
    off = f.get("symbolLocation", "")
    print(f"  {i:2d} {imgname:28s} {sym} +{off}  (0x{f.get('imageOffset',0):x})")
