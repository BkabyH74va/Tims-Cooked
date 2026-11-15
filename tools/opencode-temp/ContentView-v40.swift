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
            Text("AGXProbe v40 — AppleJPEGDriver sweep (13 Pro)").font(.headline)
            Text("sel 1-7, struct sizes 0x58/0x1000/0xda0").font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v40")
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

    private func callIO(conn: io_connect_t, sel: UInt32, scalars: [UInt64], sdata: [UInt8],
                        outSize: Int) -> (UInt32, [UInt8], [UInt64]) {
        var inScalar = [UInt64](repeating: 0, count: 4)
        for i in 0..<scalars.count { inScalar[i] = scalars[i] }
        var outScalar = [UInt64](repeating: 0, count: 8)
        var outScalarCount: UInt32 = 0
        var outBuff = [UInt8](repeating: 0, count: max(outSize, 1))
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
        let os = Array(outScalar.prefix(Int(outScalarCount)))
        return (k, outBytes, os)
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

        // Selectors 1-7 (codec path), sizes: 0x58=88, 0x1000=4096, 0xda0=3488
        let testCases: [(UInt32, Int, String)] = [
            (1, 0x58, "startDecoder"),
            (3, 0x58, "startEncoder"),
            (4, 0x1000, "startEncoderExt"),
            (5, 0x1000, "startDecoderExt"),
            (6, 0xda0, "startEncoder2024"),
            (7, 0xda0, "startDecoder2024"),
        ]

        let fillPatterns: [(String, UInt8)] = [
            ("zeros", 0x00),
            ("0x41", 0x41),
            ("0xff", 0xff),
        ]

        for (sel, stSize, name) in testCases {
            for (fillName, fillByte) in fillPatterns {
                let sdata = [UInt8](repeating: fillByte, count: stSize)
                let (k, out, os) = callIO(conn: conn, sel: sel, scalars: [], sdata: sdata, outSize: stSize)
                let osStr = os.count > 0 ? " osc=\(os.count)" : ""
                if k != 0xe00002c2 {
                    let outStr = out.count > 0 ? " out=\(out.map { String(format: "%02x", $0) }.joined())" : ""
                    log("\(name) \(fillName) stSize=0x\(String(stSize, radix:16)) kr=0x\(String(k, radix:16)) outSz=\(out.count)\(osStr)\(outStr)")
                }
            }
        }

        log("\(name) type=\(type): probe complete")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        log("=== AGXProbe v40 — AppleJPEGDriver sweep (13 Pro) ===")

        probeService("AppleJPEGDriver", 0)
        probeService("AppleJPEGDriver", 1)

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
