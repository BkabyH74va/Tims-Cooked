import re
from pathlib import Path
b=Path("iosurface_text.bin").read_bytes()
base=0x1c2fd8000
print("size",hex(len(b)))
# find the key strings
for pat in [b"IOSurfaceSliceCount", b"BytesPerSlice", b"IOSurfacePlaneInfo", b"IOSurfaceAllocSize",
            b"IOSurfaceCreate", b"headerPerSlice", b"dataPerSlice", b"IOSurfacePropertyKey"]:
    idxs=[m.start() for m in re.finditer(re.escape(pat), b)]
    print(pat.decode(), [hex(base+i) for i in idxs][:8])