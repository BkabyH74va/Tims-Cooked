#!/bin/bash
APP="$HOME/tw_work/Payload/Terminal.app"
python3 - "$APP" <<'PY'
import os, sys, struct, collections
root = sys.argv[1]
magics = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe"}
count = 0
dirs = collections.Counter()
examples = collections.defaultdict(list)
files = 0
for dp, dn, fn in os.walk(root):
    for f in fn:
        p = os.path.join(dp, f)
        files += 1
        try:
            with open(p, "rb") as fh:
                h = fh.read(4)
        except OSError:
            continue
        if h in magics:
            count += 1
            rel = os.path.relpath(p, root)
            top = rel.split(os.sep)[0]
            dirs[top] += 1
            if len(examples[top]) < 3:
                examples[top].append(rel)
print("files scanned:", files)
print("mach-o found:", count)
for k, v in dirs.most_common():
    print("  %-14s %6d  e.g. %s" % (k, v, examples[k][0]))
PY
