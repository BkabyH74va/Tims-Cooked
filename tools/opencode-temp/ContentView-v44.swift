import SwiftUI
import Darwin

@main
struct AGXProbeApp: App {
    var body: some Scene { WindowGroup { ContentView() } }
}

struct ContentView: View {
    @StateObject private var vm = ReachViewModel()
    var body: some View {
        VStack(spacing: 12) {
            Text("AGXProbe v44 — SKVLENT exact shape (17 Pro)").font(.headline)
            Text("HTPC-compressed plane shape with all tile keys").font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v44")
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
final class ReachViewModel: ObservableObject {
    @Published var log = ""
    @Published var status = "Ready"
    @Published var isRunning = false
    private var didAutoRun = false

    private let logFileURL: URL = {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("reach.log")
    }()

    private func log(_ m: String) {
        log += m + "\n"; print(m); fflush(stdout)
        try? log.write(to: logFileURL, atomically: true, encoding: .utf8)
    }

    func autoRunIfRequested() async {
        guard !didAutoRun else { return }
        didAutoRun = true
        if ProcessInfo.processInfo.arguments.contains("--autorun") { await runProbe() }
    }

    private func stripNul(_ data: Data, tag: String) -> Data? {
        guard let s = String(data: data, encoding: .utf8) else { return nil }
        guard let a = s.range(of: "<\(tag)"),
              let b = s.range(of: "</\(tag)>", options: .backwards) else { return nil }
        return (String(s[a.lowerBound..<b.upperBound]).data(using: .utf8) ?? Data()) + Data([0])
    }

    private func xmlNul(_ d: Any) -> Data? {
        guard let data = try? PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0) else { return nil }
        return data + Data([0])
    }

    private func num(_ v: UInt64) -> Int64 { Int64(bitPattern: v) }

    private func callIO(_ conn: io_connect_t, sel: UInt32, scalars: [UInt64], sdata: [UInt8], outSize: Int) -> (UInt32, [UInt8]) {
        var inScalar = [UInt64](repeating: 0, count: 4)
        for i in 0..<scalars.count { inScalar[i] = scalars[i] }
        var outScalar = [UInt64](repeating: 0, count: 8)
        var outScalarCount: UInt32 = 0
        var outBuff = [UInt8](repeating: 0xCC, count: max(outSize, 1))
        var outSz: Int = outSize
        let kr: Int32 = sdata.withUnsafeBytes { raw in
            outBuff.withUnsafeMutableBytes { ob in
                IOConnectCallMethod(conn, sel,
                                    &inScalar, UInt32(scalars.count),
                                    raw.baseAddress, sdata.count,
                                    &outScalar, &outScalarCount,
                                    ob.baseAddress, &outSz)
            }
        }
        let k = UInt32(bitPattern: kr)
        var outBytes = [UInt8](outBuff.prefix(Int(outSz)))
        return (k, outBytes)
    }

    private func idFrom(_ out: [UInt8]) -> UInt32? {
        guard out.count >= 0x1C else { return nil }
        return UInt32(out[0x18]) | (UInt32(out[0x19]) << 8) | (UInt32(out[0x1A]) << 16) | (UInt32(out[0x1B]) << 24)
    }

    private func u64(_ out: [UInt8], _ o: Int) -> UInt64 {
        guard out.count >= o + 8 else { return 0 }
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(out[o + i]) << (8 * i) }
        return v
    }

    private func probeService(_ name: String, _ type: UInt32) {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(name))
        guard service != 0 else { log("\(name): service NOT FOUND"); return }
        log("\(name): service found")
        var conn: io_connect_t = 0
        let okr = IOServiceOpen(service, mach_task_self_, type, &conn)
        IOObjectRelease(service)
        if okr != 0 { log("\(name) type=\(type): IOServiceOpen kr=0x\(String(okr, radix:16))"); return }
        log("\(name) type=\(type): IOServiceOpen ok conn=0x\(String(conn, radix:16))")
        defer { IOServiceClose(conn) }

        // SKVLENT exact IOSurface shape with HTPC-compressed planes
        // HBR = 1073741824 = 0x40000000 (1 GiB)
        log("\n--- sel0: SKVLENT exact HTPC shape (HBR=0x40000000) ---")
        let skvXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>IOSurfaceWidth</key><integer>64</integer><key>IOSurfaceHeight</key><integer>64</integer><key>IOSurfaceBytesPerElement</key><integer>4</integer><key>IOSurfacePixelFormat</key><integer>1111970369</integer><key>IOSurfaceAllocSize</key><integer>65536</integer><key>IOSurfaceSliceCount</key><integer>4</integer><key>IOSurfacePlaneInfo</key><array><dict><key>IOSurfacePlaneWidth</key><integer>64</integer><key>IOSurfacePlaneHeight</key><integer>64</integer><key>IOSurfacePlaneBytesPerElement</key><integer>4</integer><key>IOSurfacePlaneBytesPerRow</key><integer>512</integer><key>IOSurfacePlaneSize</key><integer>65536</integer><key>IOSurfacePlaneCompressionType</key><integer>4</integer><key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>16384</integer><key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>1073741824</integer><key>IOSurfacePlaneCompressedTileWidth</key><integer>32</integer><key>IOSurfacePlaneCompressedTileHeight</key><integer>32</integer><key>IOSurfacePlaneBytesPerCompressedTileHeader</key><integer>8</integer><key>IOSurfacePlaneBytesPerTileData</key><integer>4096</integer><key>IOSurfacePlaneWidthInCompressedTiles</key><integer>2</integer><key>IOSurfacePlaneHeightInCompressedTiles</key><integer>2</integer><key>IOSurfacePlaneBytesPerRowOfTileData</key><integer>8192</integer><key>IOSurfacePlaneCompressedTileHeaderRegionOffset</key><integer>65536</integer><key>IOSurfacePlaneCompressedTileDataRegionOffset</key><integer>0</integer><key>IOSurfacePlaneBytesPerRowOfCompressedTileHeaderGroups</key><integer>0</integer></dict></array></dict></plist>
        """
        let skvLen = skvXML.utf8.count + 1
        var outBuf = [UInt8](repeating: 0, count: 0xc68)
        var outSize = 0xc68
        var scalarIn: UInt64 = 0
        var kr: kern_return_t = -1
        skvXML.withCString { cs in
            kr = cs.withMemoryRebound(to: UInt8.self, capacity: skvLen) { p in
                outBuf.withUnsafeMutableBytes { ob in
                    IOConnectCallMethod(conn, 0, &scalarIn, 1, p, skvLen,
                                        nil, nil, ob.baseAddress, &outSize)
                }
            }
        }
        log("sel0 SKVLENT HTPC: kr=0x\(String(kr, radix:16)) outSz=\(outSize)")
        if kr == 0, let sid = idFrom(outBuf) {
            log("  surface id=\(sid) a0=0x\(String(u64(outBuf, 0x00), radix:16)) alloc=0x\(String(u64(outBuf, 0x20), radix:16)) planes=\(u64(outBuf, 0x58))")
        } else {
            log("  create FAILED - no surface created")
        }

        // AGX sel8 like SKVLENT f1Probe
        log("\n--- AGX sel8 on surface ---")
        let agxService = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AGXAcceleratorG18P"))
        guard agxService != 0 else {
            log("AGXAcceleratorG18P service NOT FOUND"); return
        }
        var agxConn: io_connect_t = 0
        let aokr = IOServiceOpen(agxService, mach_task_self_, 1, &agxConn)
        IOObjectRelease(agxService)
        if aokr != 0 { log("AGX open kr=0x\(String(aokr, radix:16))"); return }
        log("AGX open ok conn=0x\(String(agxConn, radix:16))")
        defer { IOServiceClose(agxConn) }

        var inStruct = [UInt8](repeating: 0, count: 0x100)
        inStruct[0] = 0x82
        // surface ID at offset 0x38
        let sidVal = idFrom(outBuf) ?? 0
        inStruct[0x38] = UInt8(sidVal & 0xFF)
        inStruct[0x39] = UInt8((sidVal >> 8) & 0xFF)
        inStruct[0x3a] = UInt8((sidVal >> 16) & 0xFF)
        inStruct[0x3b] = UInt8((sidVal >> 24) & 0xFF)
        var agxOut = [UInt8](repeating: 0, count: 0x1000)
        var agxOutSize = 0x1000
        var akr: kern_return_t = -1
        inStruct.withUnsafeBytes { ib in
            agxOut.withUnsafeMutableBytes { ob in
                IOConnectCallMethod(agxConn, 8, nil, 0, ib.baseAddress, 0x100,
                                    nil, nil, ob.baseAddress, &agxOutSize)
            }
        }
        func rd64(_ off: Int) -> UInt64 {
            guard off + 8 <= agxOut.count else { return 0 }
            var v: UInt64 = 0
            for i in 0..<8 { v |= UInt64(agxOut[off + i]) << (8 * i) }
            return v
        }
        log("AGX sel8: kr=0x\(String(akr, radix:16)) outSz=\(agxOutSize)")
        log("  out00=0x\(String(rd64(0), radix:16)) out20=0x\(String(rd64(0x20), radix:16)) out28=0x\(String(rd64(0x28), radix:16))")

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        log("=== AGXProbe v44 — SKVLENT exact HTPC shape ===")

        probeService("IOSurfaceRoot", 0)

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
