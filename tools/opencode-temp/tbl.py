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
print("sel  scalarIn structIn scalarOut structOut  handler")
for i in range(0x3c):
    raw=data[base+i*40:base+i*40+40]
    q=struct.unpack_from("<Q",raw)[0]
    u32=struct.unpack_from("<10I",raw)
    print("0x%02x  %8d %8d %9d %9d   0x%x"%(i,u32[2],u32[3],u32[4],u32[5],q&0xffffffffffff))