#!/usr/bin/env python3
"""Find the image that owns a symbol in the dyld shared cache .symbols file.

The .symbols file is a stream of NUL-separated records: an image path (starting
with '/') followed by that image's local symbols, then the next path, etc.
"""
import os
import sys

CACHE = r"G:/REPO\analysis\ios\dsc\private\preboot\Cryptexes\OS\System\Library\Caches\com.apple.dyld"
SYM = os.path.join(CACHE, "dyld_shared_cache_arm64e.symbols")

targets = sys.argv[1:] or [
    "_BrotliDecoderDecompress",
    "_BrotliDecoderCreateInstance",
    "_BrotliDecoderDecompressStream",
    "_brotli_decode_buffer",
    "_compression_decode_buffer",
    "_compression_stream_init",
]

data = open(SYM, "rb").read()
records = data.split(b"\x00")

# Build index of path positions
paths = [(i, r.decode("latin-1")) for i, r in enumerate(records) if r.startswith(b"/") and len(r) > 3]
print("records: %d  images: %d" % (len(records), len(paths)))

import bisect
path_idx = [p[0] for p in paths]

for t in targets:
    tb = t.encode()
    hits = [i for i, r in enumerate(records) if r == tb]
    print("\n=== %s -> %d" % (t, len(hits)))
    for h in hits[:8]:
        j = bisect.bisect_right(path_idx, h) - 1
        img = paths[j][1] if j >= 0 else "?"
        # is the symbol exported (global) or local? local symbols come after the
        # path record; exported ones are only in the export trie, not here.
        print("   record %d  image: %s" % (h, img))
