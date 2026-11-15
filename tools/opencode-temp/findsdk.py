import os, re

roots = [
    "/Users/USER",
    "/Users/USER/Applications",
    "/Library/Developer",
]
paths = []
for r in roots:
    if not os.path.isdir(r):
        continue
    for dirpath, dirnames, filenames in os.walk(r):
        if dirpath.count(os.sep) - r.count(os.sep) > 6:
            dirnames[:] = []
            continue
        for fn in filenames:
            if fn.endswith(".h") and ("IOKit" in fn or "IOSurface" in fn):
                paths.append(os.path.join(dirpath, fn))
        for fn in filenames:
            if fn.endswith(".h"):
                paths.append(os.path.join(dirpath, fn))

paths = list(dict.fromkeys(paths))
print("HEADERS FOUND:", len(paths))

hits1 = []
for p in paths:
    try:
        with open(p, "r", errors="replace") as f:
            t = f.read()
    except Exception:
        continue
    if "IOConnectMethod" in t:
        hits1.append(p)
print("IOConnectMethod in:", len(hits1))
for p in hits1[:10]:
    print("   ", p)

hits2 = []
for p in paths:
    try:
        with open(p, "r", errors="replace") as f:
            t = f.read()
    except Exception:
        continue
    if "IOExternalMethodDispatch" in t:
        hits2.append(p)
print("IOExternalMethodDispatch in:", len(hits2))
for p in hits2[:10]:
    print("   ", p)

with open("/tmp/sdkhits.txt", "w") as f:
    for p in hits2:
        f.write(p + "\n")
print("WROTE /tmp/sdkhits.txt")
