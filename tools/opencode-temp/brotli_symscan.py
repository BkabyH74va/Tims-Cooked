#!/usr/bin/env python3
"""Check how Apple exposes the Brotli decoder on 24A446.

Two questions:
  1. Is there a public/exported Brotli entry point we can call directly
     (e.g. BrotliDecoderDecompress), or is it only reachable through
     libcompression / CFNetwork?
  2. Does libcompression expose a brotli stream/decode API (COMPRESSION_BROTLI)?

Scans the split shared cache symbol file plus the raw parts for symbol-ish
strings.
"""
import os
import re

CACHE = r"G:/REPO\analysis\ios\dsc\private\preboot\Cryptexes\OS\System\Library\Caches\com.apple.dyld"

symbols_path = os.path.join(CACHE, "dyld_shared_cache_arm64e.symbols")

patterns = [
    rb"Brotli[A-Za-z_]{0,40}",
    rb"_BrotliDecoder[A-Za-z_]{0,40}",
    rb"brotli[A-Za-z_]{0,40}",
    rb"COMPRESSION_BROTLI",
    rb"_compression_(?:stream|decode|encode)[A-Za-z_]{0,30}",
    rb"_BrotliDecoderDecompress",
    rb"_BrotliDecoderCreateInstance",
]

print("symbols file:", os.path.exists(symbols_path))
if os.path.exists(symbols_path):
    data = open(symbols_path, "rb").read()
    print("size: 0x%x" % len(data))
    for pat in patterns:
        found = {}
        for m in re.finditer(pat, data):
            s = m.group(0)
            found[s] = found.get(s, 0) + 1
        print("\n--- %s -> %d unique" % (pat.decode(), len(found)))
        for s in sorted(found)[:40]:
            print("   ", s.decode("latin-1"), "x%d" % found[s])
else:
    # fall back: scan the parts for the strings
    print("no .symbols, scanning parts")
    for name in sorted(os.listdir(CACHE)):
        if not name.startswith("dyld_shared_cache_arm64e"):
            continue
        p = os.path.join(CACHE, name)
        if not os.path.isfile(p):
            continue
        data = open(p, "rb").read()
        for pat in patterns:
            n = len(re.findall(pat, data))
            if n:
                print("%-40s %s x%d" % (name, pat.decode(), n))
