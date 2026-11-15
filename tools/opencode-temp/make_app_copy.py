#!/usr/bin/env python3
"""Write an app-only copy of brotlirepro.swift (no CLI block) and report what
the build system thinks it is compiling."""
import os, re, subprocess

src_path = "/tmp/br.swift"
dst_path = os.path.expanduser("~/agx-probe-project/AGXProbe/brotlirepro.swift")

src = open(src_path, "r", encoding="utf-8").read()
i = src.find("#if BROTLI_CLI")
print("cli block at:", i)
if i < 0:
    print("REFUSING: marker not found")
    raise SystemExit(1)
app = src[:i].rstrip() + "\n"
open(dst_path, "w", encoding="utf-8").write(app)
print("wrote app copy:", len(app), "bytes (full:", len(src), ")")
print("tail of app copy:")
print("\n".join(app.splitlines()[-4:]))
