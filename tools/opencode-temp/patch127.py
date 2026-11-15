import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

old = """        // a control buffer allocated after it (the F1 transcript relies on the
        // allocator handing out increasing addresses)"""
new = """        // MEASURE THE SURFACE'S GPU MAPPING SIZE.
        // If the bogus geometry reaches the driver, the IOSurface-backed
        // texture's GPU allocation is huge (the bogus per-slice size), and the
        // GPU-VA gap between a buffer allocated before it and one allocated
        // after it grows to match.  If the gap stays small, the driver only
        // ever saw the real 64 KiB and the F1 route is inert on this build.
        let gapBefore = device.makeBuffer(length: 0x1000, options: .storageModeShared)
        emit("probe buffer before: gpuAddress=0x\\(String(gapBefore?.gpuAddress ?? 0, radix: 16))")
        var texInfo = "no texture"
        if let cs = lookupFn(sid) {
            let desc = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .bgra8Unorm,
                                                                 width: 64, height: 64, mipmapped: false)
            desc.usage = [.shaderRead, .shaderWrite, .renderTarget]
            desc.storageMode = .shared
            if let tex = device.makeTexture(descriptor: desc, iosurface: cs, plane: 0) {
                texInfo = "texture ok w=\\(tex.width) h=\\(tex.height)"
            } else {
                texInfo = "texture creation FAILED"
            }
        }
        let gapAfter = device.makeBuffer(length: 0x1000, options: .storageModeShared)
        let ga = Int64(gapBefore?.gpuAddress ?? 0)
        let gb = Int64(gapAfter?.gpuAddress ?? 0)
        emit("\\(texInfo); buffer after: gpuAddress=0x\\(String(gb, radix: 16))")
        emit("GPU-VA gap across the IOSurface mapping = 0x\\(String(gb - ga, radix: 16)) (0x10000 would mean the driver only saw the real allocation)")

        // a control buffer allocated after it (the F1 transcript relies on the
        // allocator handing out increasing addresses)"""
assert old in t
t = t.replace(old, new)
p.write_text(t)
print("patched: GPU-VA gap measurement")
