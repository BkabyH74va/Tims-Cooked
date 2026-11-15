import sys
from pathlib import Path
sys.path.insert(0,".")
from kc_iosurface import parse_fileset, member_segments
kc=Path("../../firmware/24A446/kernelcache.release.macho")
print("kc exists", kc.exists(), kc.resolve())
data=kc.read_bytes()
print("len(data)", hex(len(data)))
entries,_=parse_fileset(data)
e=[x for x in entries if x["name"]=="com.apple.iokit.IOSurface"][0]
segs=member_segments(data,e["fileoff"])
for k,v in segs.items(): print(k, [hex(x) for x in v])