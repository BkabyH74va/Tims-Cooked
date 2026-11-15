#!/usr/bin/env python3
"""Scan the 27.0.1 split dyld shared cache for Brotli decoder strings.

Purpose: verify the CVE-2026-111497 claim that Apple's bundled libcompression
Brotli decoder on 27.0.1 is vulnerable (i.e. the patched BLOCK_SWITCH error
code/string is absent).

The patched build (27.2.1) extends BrotliDecoderErrorString with a
"BLOCK_SWITCH" entry; the vulnerable build has no such string.
"""
import os
import sys

CACHE = r"G:/REPO\analysis\ios\dsc\private\preboot\Cryptexes\OS\System\Library\Caches\com.apple.dyld"

needles = [
    b"BLOCK_SWITCH",
    b"EXUBERANT",          # classic brotli error string, proves decoder present
    b"BROTLI_DECODER_ERROR",
    b"BrotliDecoderErrorString",
]

parts = []
for name in sorted(os.listdir(CACHE)):
    if not name.startswith("dyld_shared_cache_arm64e"):
        continue
    suf = name[len("dyld_shared_cache_arm64e"):]
    if suf == "" or (suf.startswith(".") and suf[1:].isdigit()):
        p = os.path.join(CACHE, name)
        if os.path.isfile(p):
            parts.append((suf or "base", p))

print("parts:", len(parts))
hits = {n: [] for n in needles}
for label, path in parts:
    with open(path, "rb") as f:
        data = f.read()
    for n in needles:
        start = 0
        while True:
            i = data.find(n, start)
            if i < 0:
                break
            # print a bit of surrounding printable text
            s = max(0, i - 32)
            e = min(len(data), i + len(n) + 48)
            ctx = data[s:e]
            ctx = "".join(chr(c) if 32 <= c < 127 else "." for c in ctx)
            hits[n].append((label, i, ctx))
            start = i + 1
            if len(hits[n]) > 6:
                break

for n in needles:
    print("\n===", n.decode(), "->", len(hits[n]), "hit(s)")
    for (label, off, ctx) in hits[n][:6]:
        print("  part %-4s off 0x%x  |%s|" % (label, off, ctx))
