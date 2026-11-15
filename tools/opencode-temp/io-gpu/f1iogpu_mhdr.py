import struct
p=r"G:/REPO\tools\opencode-temp\io-gpu\iosurf-extract\com.apple.iokit.IOSurface"
d=open(p,'rb').read()
print(len(d))
print(d[:64].hex())
m=struct.unpack_from('<IiiIIIII',d,0)
print(m)
