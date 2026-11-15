import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

# 1. add IOSurfaceIsGlobal (and a couple of shared-surface keys) to the payload
old = """<key>IOSurfacePixelFormat</key><integer>1111970369</integer><key>IOSurfaceAllocSize</key><integer>\\(alloc)</integer>"""
new = """<key>IOSurfacePixelFormat</key><integer>1111970369</integer><key>IOSurfaceAllocSize</key><integer>\\(alloc)</integer><key>IOSurfaceIsGlobal</key><true/><key>IOSurfacePurgeWhenNotInUse</key><false/>"""
assert old in t
t = t.replace(old, new)

# 2. report whether the surface became importable and how big its GPU mapping is
old2 = """            if let tex = device.makeTexture(descriptor: desc, iosurface: csRef, plane: 0) {
                texInfo = "texture ok w=\\(tex.width) h=\\(tex.height)"
            } else {
                texInfo = "texture creation FAILED"
            }"""
new2 = """            if let tex = device.makeTexture(descriptor: desc, iosurface: csRef, plane: 0) {
                texInfo = "texture ok w=\\(tex.width) h=\\(tex.height)"
            } else {
                texInfo = "texture creation FAILED"
                // try again with a plain (non-ARGB) format and a private mode
                let d2 = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .bgra8Unorm,
                                                                    width: 64, height: 64, mipmapped: false)
                d2.usage = [.shaderRead, .shaderWrite]
                d2.storageMode = .private
                if let tex2 = device.makeTexture(descriptor: d2, iosurface: csRef, plane: 0) {
                    texInfo = "texture ok (private) w=\\(tex2.width) h=\\(tex2.height)"
                }
            }"""
assert old2 in t
t = t.replace(old2, new2)

p.write_text(t)
print("patched: IOSurfaceIsGlobal + texture fallback")
