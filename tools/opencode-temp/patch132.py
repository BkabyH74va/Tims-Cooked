import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

probe = '''
    // ---- probe the two paths that reach real code -------------------------
    //  sel 0x22: one scalar, 0xc68 out.  It dispatches an IPC and answers
    //            "asked to allocate client shared id %08x not known by
    //            IOSurfaceRoot" -> the scalar is a client-shared id.
    //  sel 0x1e: one scalar + variable struct; it answers BadMatching, i.e.
    //            it looks a service up by a NAME taken from the struct.
    func runProbeMode() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        var iter: io_iterator_t = 0
        let kr = xq_IOServiceGetMatchingServices(0, xq_IOServiceMatching("IOSurfaceRoot"), &iter)
        guard kr == 0 else { emit("[-] no IOSurfaceRoot"); status = "Complete"; isRunning = false; return }
        let svc = xq_IOIteratorNext(iter)
        var conn: io_connect_t = 0
        guard xq_IOServiceOpen(svc, mach_task_self(), 0, &conn) == 0, conn != 0 else {
            emit("[-] open failed"); status = "Complete"; isRunning = false; return
        }

        // ---- 0x22: client shared id sweep ---------------------------------
        var hist: [String: Int] = [:]
        var oks: [String] = []
        for sid in 0...256 {
            var sc: [UInt64] = [UInt64(sid)]
            var out = [UInt8](repeating: 0, count: 0xc68)
            var outSize: UInt64 = 0xc68
            let r: Int32 = sc.withUnsafeMutableBufferPointer { sb in
                out.withUnsafeMutableBytes { ob in
                    callMethod(conn, 0x22, UnsafePointer(sb.baseAddress), 1, nil, 0,
                               ob.baseAddress, &outSize)
                }
            }
            let k = krN(r)
            hist[k, default: 0] += 1
            if r == 0 {
                oks.append("sid=\\(sid) outSize=0x\\(String(outSize, radix: 16)) head=\\(out.prefix(24).map { String(format: "%02x", $0) }.joined())")
            }
        }
        emit("sel0x22 client-shared-id sweep 0...256: " + hist.map { "\\($0.key)=\\($0.value)" }.sorted { $0.key < $1.key }.joined(separator: " "))
        for o in oks { emit("   0x22 OK " + o) }

        // ---- 0x1e: name lookup -------------------------------------------
        let names = ["IOSurfaceDescriptorContext", "IOSurfaceMemoryPoolBunch",
                     "IOSurfaceDescriptorComponent", "IOSurfaceShared", "IOSurfaceRoot",
                     "IOSurfaceRootUserClient", "IOSurfaceClient"]
        var hist2: [String: Int] = [:]
        for n in names {
            for scalar in [UInt64(0), 1, 2] {
                var sc: [UInt64] = [scalar]
                var buf = Array(n.utf8) + [0]
                var out = [UInt8](repeating: 0, count: 0xc68)
                var outSize: UInt64 = 0xc68
                let r: Int32 = sc.withUnsafeMutableBufferPointer { sb in
                    buf.withUnsafeBufferPointer { pb in
                        out.withUnsafeMutableBytes { ob in
                            callMethod(conn, 0x1e, UnsafePointer(sb.baseAddress), 1,
                                       pb.baseAddress, buf.count,
                                       ob.baseAddress, &outSize)
                        }
                    }
                }
                hist2["\\(n) s\\(scalar): \\(krN(r))"] = 1
                if r == 0 {
                    emit("   0x1e OK name=\\(n) scalar=\\(scalar) outSize=0x\\(String(outSize, radix: 16))")
                }
            }
        }
        for k in hist2.keys.sorted() { emit("   0x1e \\(k)") }
        emit("=== probe done ===")
        _ = xq_IOServiceClose(conn)
        status = "Complete"; isRunning = false
    }
'''

anchor = "    // ---- the Metal half -----------------------------------------------------"
assert anchor in t
t = t.replace(anchor, probe + "\n" + anchor)

old = """        if args.contains("--fuzz") { await runFuzzMode(); return }"""
new = """        if args.contains("--fuzz") { await runFuzzMode(); return }
        if args.contains("--probe") { await runProbeMode(); return }"""
assert old in t
t = t.replace(old, new)

p.write_text(t)
print("patched: --probe mode")
