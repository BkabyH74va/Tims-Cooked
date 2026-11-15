//
//  ContentView.swift
//  AGXProbe — v6: IOSurfaceRoot selector-0 input shape matrix
//
//  v5 result: IOServiceOpen(IOSurfaceRoot) = kr 0, but
//             IOConnectCallStructMethod(sel=0, XML) = 0xe00002c2
//             (kIOReturnBadArgument)
//
//  Static dispatch entry (kext file offset ~0x46638) shows selector 0 as:
//      scalarInputCount   = 1
//      structureInputSize = 0xffffffff (variable)
//      scalarOutputCount  = 0
//      structureOutputSize= 0xc68
//
//  So the call needs exactly ONE scalar plus the payload. This probe tries
//  the plausible combinations, cheapest first.
//
//  SAFETY: creation attempts only. No Metal, no writes, no cross-object.
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
            Text("AGXProbe — v6 input shape").font(.headline)
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
                Text(vm.isRunning ? "Probing…" : "Run v6")
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
            .appendingPathComponent("geom6.log")
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

    private func dictXML(_ d: [String: Any]) -> Data? {
        try? PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0)
    }

    /// Strip the <?xml ?>, DOCTYPE and <plist> wrapper, leaving <dict>…</dict>.
    private func stripPlist(_ data: Data) -> Data? {
        guard let s = String(data: data, encoding: .utf8) else { return nil }
        guard let a = s.range(of: "<dict"),
              let b = s.range(of: "</dict>", options: .backwards) else { return nil }
        return String(s[a.lowerBound..<b.upperBound]).data(using: .utf8)
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

    private enum ScalarShape { case none, length, zero, one }

    private func call(conn: io_connect_t, selector: UInt32, xml: Data,
                      shape: ScalarShape, tag: String) -> UnsafeMutableRawPointer? {
        let out = UnsafeMutableRawPointer.allocate(byteCount: OUT_SIZE, alignment: 8)
        memset(out, 0, OUT_SIZE)
        var outLen = OUT_SIZE
        var scalar = UInt64(xml.count)
        if shape == .zero { scalar = 0 }
        if shape == .one { scalar = 1 }

        let kr: kern_return_t = xml.withUnsafeBytes { raw in
            switch shape {
            case .none:
                return IOConnectCallMethod(conn, selector, nil, 0,
                                           raw.baseAddress, xml.count,
                                           nil, nil, out, &outLen)
            default:
                return IOConnectCallMethod(conn, selector, &scalar, 1,
                                           raw.baseAddress, xml.count,
                                           nil, nil, out, &outLen)
            }
        }
        log(String(format: "%@: sel=%u shape=%@ xml=%lu kr=0x%x outLen=0x%lx",
                   tag, selector, String(describing: shape), xml.count, kr, outLen))
        if kr != 0 { out.deallocate(); return nil }
        return out
    }

    private func describe(_ p: UnsafeMutableRawPointer, _ tag: String) {
        let base  = p.loadUnaligned(fromByteOffset: 0,    as: UInt64.self)
        let idv   = p.loadUnaligned(fromByteOffset: 0x18, as: UInt64.self)
        let alloc = p.loadUnaligned(fromByteOffset: 0x20, as: UInt64.self)
        let h     = p.loadUnaligned(fromByteOffset: 0x28, as: UInt64.self)
        log(String(format: "  %@: base=0x%llx id=%llu alloc=0x%llx h=%llu",
                   tag, base, idv, alloc, h))
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

    // ------------------------------------------------------------------

    func runProbe() async {
        isRunning = true; status = "Running…"; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)

        log("=== AGXProbe v6 — selector-0 input shape === build 24A446 / t8150")
        log("SAFETY: creation attempts only; no Metal, no writes")

        guard let conn = openRoot() else { status = "Failed"; isRunning = false; return }
        defer { IOServiceClose(conn) }

        let benign = baseDict(0x4000, [plane()])
        guard let full = dictXML(benign) else { status = "Failed"; isRunning = false; return }
        let stripped = stripPlist(full) ?? full
        log("payload: full=\(full.count) B, stripped=\(stripped.count) B")
        if let s = String(data: full, encoding: .utf8) {
            log("first 160 chars: \(s.prefix(160))")
        }

        // Try the scalar shapes, then the stripped payload, then nearby selectors.
        var won = false
        for (tag, payload) in [("full", full), ("stripped", stripped)] {
            for shape in [ScalarShape.length, .zero, .one, .none] {
                if let out = call(conn: conn, selector: 0, xml: payload,
                                  shape: shape, tag: "S1-\(tag)") {
                    describe(out, "S1"); out.deallocate(); won = true; break
                }
            }
            if won { break }
        }

        if !won {
            log("\n--- selector sweep 1..5 with scalar=length, full payload ---")
            for sel in UInt32(1)...UInt32(5) {
                if let out = call(conn: conn, selector: sel, xml: full,
                                  shape: .length, tag: "sweep sel\(sel)") {
                    describe(out, "sel\(sel)"); out.deallocate(); won = true; break
                }
            }
        }

        if !won {
            log("\nno input shape accepted; route not usable with this payload form")
        }

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
