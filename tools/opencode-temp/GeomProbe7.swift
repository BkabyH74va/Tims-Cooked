//
//  ContentView.swift
//  AGXProbe — v7: IOSurfaceRoot selector-0 payload-format matrix
//
//  v5/v6 showed: IOServiceOpen ok, but selector 0 returns 0xe00002c2
//  (kIOReturnBadArgument) for XML, stripped XML, and scalar shapes {len,0,1,none}.
//
//  This probe tests whether the payload *encoding* is the problem:
//    - XML plist (with/without NUL, with/without wrappers)
//    - binary plist (bplist00)
//    - length-prefixed variants
//
//  Bounded: 16 calls, all creation attempts, no Metal, no writes.
//

import SwiftUI
import Darwin

@main
struct AGXProbeApp: App {
    var body: some Scene { WindowGroup { ContentView() } }
}

struct ContentView: View {
    @StateObject private var vm = GeomViewModel()
    var body: some View {
        VStack(spacing: 12) {
            Text("AGXProbe — v7 payload format").font(.headline)
            Text("iPhone18,1 / t8150 / iOS 27.0.1 (24A446)")
                .font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing…" : "Run v7")
                    .font(.headline).foregroundColor(.white)
                    .frame(maxWidth: .infinity).padding(10)
                    .background(vm.isRunning ? Color.gray : Color.blue).cornerRadius(8)
            }.disabled(vm.isRunning)
            Text("Status: \(vm.status)").font(.caption2).foregroundColor(.secondary)
            Spacer(minLength: 0)
        }
        .padding().task { await vm.autoRunIfRequested() }
    }
}

@MainActor
final class GeomViewModel: ObservableObject {
    @Published var log = ""
    @Published var status = "Ready"
    @Published var isRunning = false

    private var didAutoRun = false
    private let PF_BGRA: UInt32 = 0x42475241
    private let OUT_SIZE = 0xc68

    private var logFileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("geom7.log")
    }

    private func log(_ m: String) {
        log += m + "\n"; print(m); fflush(stdout)
        try? log.write(to: logFileURL, atomically: true, encoding: .utf8)
    }

    func autoRunIfRequested() async {
        guard !didAutoRun else { return }
        didAutoRun = true
        guard ProcessInfo.processInfo.arguments.contains("--autorun") else { return }
        await runProbe()
    }

    // ------------------------------------------------------------------

    private func dictXML(_ d: [String: Any], binary: Bool = false) -> Data? {
        try? PropertyListSerialization.data(
            fromPropertyList: d,
            format: binary ? .binary : .xml,
            options: 0)
    }

    private func stripPlist(_ data: Data) -> Data? {
        guard let s = String(data: data, encoding: .utf8) else { return nil }
        guard let a = s.range(of: "<dict"),
              let b = s.range(of: "</dict>", options: .backwards) else { return nil }
        return String(s[a.lowerBound..<b.upperBound]).data(using: .utf8)
    }

    private func prefixed(_ data: Data, width: Int, value: UInt64) -> Data {
        var out = Data()
        var v = value
        if width == 4 {
            var w = UInt32(truncatingIfNeeded: v)
            withUnsafeBytes(of: &w) { out.append(contentsOf: $0) }
        } else {
            withUnsafeBytes(of: &v) { out.append(contentsOf: $0) }
        }
        out.append(data)
        return out
    }

    private func openRoot() -> io_connect_t? {
        let service = IOServiceGetMatchingService(
            kIOMainPortDefault, IOServiceMatching("IOSurfaceRoot"))
        guard service != 0 else { log("IOSurfaceRoot service = NULL"); return nil }
        defer { IOObjectRelease(service) }
        var conn: io_connect_t = 0
        let kr = IOServiceOpen(service, mach_task_self_, 0, &conn)
        log(String(format: "IOServiceOpen kr=0x%x conn=0x%x", kr, conn))
        return kr == 0 ? conn : nil
    }

    private func plane(_ extra: [String: Any] = [:]) -> [String: Any] {
        var p: [String: Any] = [
            "IOSurfacePlaneWidth": 64,
            "IOSurfacePlaneHeight": 64,
            "IOSurfacePlaneBytesPerRow": 256,
            "IOSurfacePlaneBytesPerElement": 4,
            "IOSurfacePlaneOffset": 0,
            "IOSurfacePlaneSize": 0x4000,
        ]
        for (k, v) in extra { p[k] = v }
        return p
    }

    private func baseDict(_ alloc: Int, _ planes: [[String: Any]],
                          _ extra: [String: Any] = [:]) -> [String: Any] {
        var d: [String: Any] = [
            "IOSurfaceWidth": 64, "IOSurfaceHeight": 64,
            "IOSurfaceBytesPerElement": 4, "IOSurfaceBytesPerRow": 256,
            "IOSurfaceAllocSize": alloc, "IOSurfacePixelFormat": PF_BGRA,
            "IOSurfacePlaneInfo": planes,
        ]
        for (k, v) in extra { d[k] = v }
        return d
    }

    private func call(conn: io_connect_t, xml: Data, scalarLen: UInt64,
                      useScalar: Bool, tag: String) -> UnsafeMutableRawPointer? {
        let out = UnsafeMutableRawPointer.allocate(byteCount: OUT_SIZE, alignment: 8)
        memset(out, 0, OUT_SIZE)
        var outLen = OUT_SIZE
        var s = scalarLen
        let kr: kern_return_t = xml.withUnsafeBytes { raw in
            if useScalar {
                return IOConnectCallMethod(conn, 0, &s, 1,
                                           raw.baseAddress, xml.count,
                                           nil, nil, out, &outLen)
            } else {
                return IOConnectCallMethod(conn, 0, nil, 0,
                                           raw.baseAddress, xml.count,
                                           nil, nil, out, &outLen)
            }
        }
        log(String(format: "  %-28@ scalar=%@ n=%lu kr=0x%x out=0x%lx",
                   tag as NSString,
                   useScalar ? String(scalarLen) : "none" as NSString,
                   xml.count, kr, outLen))
        if kr != 0 { out.deallocate(); return nil }
        let base  = out.loadUnaligned(fromByteOffset: 0,    as: UInt64.self)
        let idv   = out.loadUnaligned(fromByteOffset: 0x18, as: UInt64.self)
        let alloc = out.loadUnaligned(fromByteOffset: 0x20, as: UInt64.self)
        let h     = out.loadUnaligned(fromByteOffset: 0x28, as: UInt64.self)
        log(String(format: "      base=0x%llx id=%llu alloc=0x%llx h=%llu",
                   base, idv, alloc, h))
        return out
    }

    // ------------------------------------------------------------------

    func runProbe() async {
        isRunning = true; status = "Running…"; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)

        log("=== AGXProbe v7 — payload format === build 24A446 / t8150")
        log("SAFETY: creation attempts only; no Metal, no writes")

        guard let conn = openRoot() else { status = "Failed"; isRunning = false; return }
        defer { IOServiceClose(conn) }

        let dict = baseDict(0x4000, [plane()])
        guard let xml = dictXML(dict), let bin = dictXML(dict, binary: true) else {
            status = "Failed"; isRunning = false; return
        }
        let stripped = stripPlist(xml) ?? xml
        var xmlNul = xml; xmlNul.append(0)
        var strippedNul = stripped; strippedNul.append(0)

        let variants: [(String, Data)] = [
            ("xml", xml),
            ("xml+nul", xmlNul),
            ("binary", bin),
            ("stripped", stripped),
            ("stripped+nul", strippedNul),
            ("u32-prefix+xml", prefixed(xml, width: 4, value: UInt64(xml.count))),
            ("u64-prefix+xml", prefixed(xml, width: 8, value: UInt64(xml.count))),
            ("u32zero+xml", prefixed(xml, width: 4, value: 0)),
        ]

        var won = false
        for (name, payload) in variants {
            for (sname, useScalar) in [("len", true), ("none", false)] {
                let sl = UInt64(payload.count)
                if let out = call(conn: conn, xml: payload, scalarLen: sl,
                                  useScalar: useScalar, tag: "\(name)/\(sname)") {
                    out.deallocate(); won = true
                }
            }
            if won { break }
        }

        if !won {
            log("\nall payload forms rejected (0xe00002c2) -> selector-0 route closed")
        }
        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
