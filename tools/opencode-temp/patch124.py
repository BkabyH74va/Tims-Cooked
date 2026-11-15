import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

# readAt takes the buffer to read from
old = """        func readAt(_ offset: UInt32) -> UInt32 {
            guard let cb = queue.makeCommandBuffer(),
                  let enc = cb.makeComputeCommandEncoder() else { return 0 }
            enc.setComputePipelineState(readPipe)
            enc.setBuffer(f1buf, offset: 0, index: 0)"""
new = """        func readAt(_ offset: UInt32, _ buf: MTLBuffer? = nil) -> UInt32 {
            guard let cb = queue.makeCommandBuffer(),
                  let enc = cb.makeComputeCommandEncoder() else { return 0 }
            enc.setComputePipelineState(readPipe)
            enc.setBuffer(buf ?? f1buf, offset: 0, index: 0)"""
assert old in t
t = t.replace(old, new)

# after the write, read the control buffer back through the GPU
old2 = """            let cp = ctrl.contents().assumingMemoryBound(to: UInt32.self)
            var hit = -1
            for i in 0..<(alloc / 4) where cp[i] == marker { hit = i; break }
            if hit >= 0 {
                emit("*** CROSS-OBJECT HIT: control buffer word \\(hit) == 0x\\(String(marker, radix: 16)) ***")
            } else {
                emit("no hit in the control buffer (first words: 0x\\(String(cp[0], radix: 16)) 0x\\(String(cp[1], radix: 16)))")
            }
            // restore
            _ = writeAt(UInt32(delta), 0)"""
new2 = """            let cp = ctrl.contents().assumingMemoryBound(to: UInt32.self)
            var hit = -1
            for i in 0..<(alloc / 4) where cp[i] == marker { hit = i; break }
            emit("CPU view of the control buffer: hit=\\(hit) word0=0x\\(String(cp[0], radix: 16))")
            // read it back through the GPU (the CPU view of shared memory can
            // be stale)
            let g0 = readAt(0, ctrl)
            let g1 = readAt(4, ctrl)
            emit("GPU view of the control buffer: word0=0x\\(String(g0, radix: 16)) word1=0x\\(String(g1, radix: 16))")
            if g0 == marker || g1 == marker {
                emit("*** CROSS-OBJECT HIT: the control buffer holds our marker ***")
            } else {
                emit("no marker in the control buffer (GPU view)")
            }
            // restore
            _ = writeAt(UInt32(delta), 0)"""
assert old2 in t
t = t.replace(old2, new2)

p.write_text(t)
print("patched: GPU-side readback of the control buffer")
