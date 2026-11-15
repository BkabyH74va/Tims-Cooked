import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

block = '''
        // ---- descriptor / memory-pool family -------------------------------
        // 0x1a reads:  x23 = [args+0x30] (struct in)   w25 = [args+0x38] (size)
        //              x0  = [args+0x40]  -> dereferenced as an object pointer
        //              x24 = [args+0x58] (struct out)   w27 = [args+0x60] (size)
        // The kext's own field names for this family are "Descriptor address",
        // "Pool Id", "Components" and per-component "Length"/"Options", so the
        // structure is  { u64 descriptorAddress; u32 poolId; u32 componentCount; ... }
        // and the component array is read through the user pointer.
        let descSels: [(UInt32, Int, Int)] = [(0x1a, 0, 0), (0x2e, 0, 0), (0x36, 0, 0),
                                            (0x13, 0, 0), (0x18, 0, 0),
                                            (0x2f, 1, 0), (0x30, 1, 0), (0x32, 2, 0)]
        let descPtr = UnsafeMutableRawPointer.allocate(byteCount: 0x4000, alignment: 16)
        descPtr.initializeMemory(as: UInt64.self, repeating: 0x0000000041414141, count: 0x800)
        let descAddr = UInt64(UInt(bitPattern: descPtr))
        var hist4: [String: Int] = [:]
        for (sel, nsc, _so) in descSels {
            for compCount in [UInt64(0), 1, 2, 8, 64, 1024] {
                for poolId in [UInt64(0), 1] {
                    var words: [UInt64] = [descAddr, poolId, compCount, 0, 0, 0, 0, 0,
                                           0x1000, 0, 0, 0, 0, 0, 0, 0]
                    var out = [UInt8](repeating: 0, count: 0x1000)
                    var outSize: UInt64 = 0x1000
                    var sc: [UInt64] = [UInt64](repeating: 0, count: max(nsc, 1))
                    let r: Int32 = sc.withUnsafeMutableBufferPointer { sb in
                        words.withUnsafeMutableBufferPointer { wb in
                            out.withUnsafeMutableBytes { ob in
                                callMethod(conn, sel, nsc > 0 ? UnsafePointer(sb.baseAddress) : nil,
                                           UInt32(nsc),
                                           UnsafeRawPointer(wb.baseAddress!), 0x80,
                                           ob.baseAddress, &outSize)
                            }
                        }
                    }
                    hist4["sel0x\\(String(sel, radix: 16)) n=\\(nsc) c=\\(compCount) p=\\(poolId): \\(krN(r))"] = 1
                    if r == 0 {
                        emit("   0x\\(String(sel, radix: 16)) OK n=\\(nsc) comps=\\(compCount) pool=\\(poolId) outSize=0x\\(String(outSize, radix: 16)) head=\\(out.prefix(24).map { String(format: "%02x", $0) }.joined())")
                    }
                }
            }
        }
        for k in hist4.keys.sorted() { emit("   desc " + k) }
'''

anchor = '        emit("=== probe done ===")'
assert anchor in t
t = t.replace(anchor, block + anchor)
p.write_text(t)
print("patched: descriptor-family probe")
