import struct,sys
from pathlib import Path
sys.path.insert(0,".")
from kc_iosurface import parse_fileset, member_segments
data=Path("../../firmware/24A446/kernelcache.release.macho").read_bytes()
entries,_=parse_fileset(data)
e=[x for x in entries if x["name"]=="com.apple.iokit.IOSurface"][0]
segs=member_segments(data,e["fileoff"])
dcvm,dcvms,dcfo,dcfs=segs["__DATA_CONST"]
base=dcfo+0x2638
for sel in [0x04,0x06,0x07,0x22,0x24,0x25,0x2b]:
    raw=data[base+sel*40:base+sel*40+40]
    q=struct.unpack_from("<Q",raw)[0]
    u32=struct.unpack_from("<10I",raw)
    print("sel 0x%02x handler=0x%x  u32=%s"%(sel,q,u32))