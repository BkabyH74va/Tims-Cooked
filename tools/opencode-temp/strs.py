import re
from pathlib import Path
b=Path("iosurface_text.bin").read_bytes()
base=0x1c2fd8000
strs=[]
cur=b""
start=0
for i,ch in enumerate(b):
    if 32 <= ch < 127:
        if not cur: start=i
        cur+=bytes([ch])
    else:
        if len(cur)>=6:
            strs.append((base+start, cur.decode()))
        cur=b""
for a,s in strs[:60]:
    print(hex(a), s)
print("total strings", len(strs))