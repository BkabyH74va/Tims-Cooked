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
            Text("AGXProbe v47 — AppleKeyStore deep probe (17 Pro)").font(.headline)
            Text("AppleKeyStore successful selectors with struct I/O").font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v47")
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

    private func tryOpen(_ name: String, _ type: UInt32) -> (kern_return_t, io_connect_t) {
        let matching = IOServiceMatching(name)
        var iter: io_iterator_t = 0
        let kr1 = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iter)
        if kr1 != KERN_SUCCESS { return (kr1, 0) }
        let svc = IOIteratorNext(iter)
        IOObjectRelease(iter)
        if svc == 0 { return (-2, 0) }
        var conn: io_connect_t = 0
        let kr2 = IOServiceOpen(svc, mach_task_self_, type, &conn)
        IOObjectRelease(svc)
        return (kr2, conn)
    }

    private func probeSelStruct(_ name: String, _ type: UInt32, _ sel: UInt32, _ inData: [UInt8], _ outSize: Int) {
        let (kr, conn) = tryOpen(name, type)
        if kr != KERN_SUCCESS {
            log("\(name) type=\(type): kr=0x\(String(UInt32(bitPattern: kr), radix:16))")
            return
        }
        defer { IOServiceClose(conn) }
        log("\(name) type=\(type): OPEN conn=0x\(String(conn, radix:16)) sel=0x\(String(sel, radix:16)) inSz=\(inData.count) outSz=\(outSize)")

        var inScalar: UInt64 = 0
        var outBuff = [UInt8](repeating: 0, count: max(outSize, 1))
        var outSz = outSize
        var k2: kern_return_t = -1
        inData.withUnsafeBytes { raw in
            outBuff.withUnsafeMutableBytes { ob in
                k2 = IOConnectCallMethod(conn, sel, &inScalar, 1, raw.baseAddress, inData.count, nil, nil, ob.baseAddress, &outSz)
            }
        }
        let k2u = UInt32(bitPattern: k2)
        log("  kr=0x\(String(k2u, radix:16)) outSz=\(outSz)")
        if k2u == KERN_SUCCESS && outSz > 0 {
            let hex = outBuff.prefix(min(outSz, 32)).map { String(format: "%02x", $0) }.joined()
            log("  out: \(hex)")
        }
    }

    private func probeSelScalar(_ name: String, _ type: UInt32, _ sel: UInt32, _ scalars: [UInt64]) {
        let (kr, conn) = tryOpen(name, type)
        if kr != KERN_SUCCESS {
            log("\(name) type=\(type): kr=0x\(String(UInt32(bitPattern: kr), radix:16))")
            return
        }
        defer { IOServiceClose(conn) }
        log("\(name) type=\(type): OPEN conn=0x\(String(conn, radix:16)) sel=0x\(String(sel, radix:16)) scalars=\(scalars)")

        var inScalar = [UInt64](repeating: 0, count: 4)
        for i in 0..<scalars.count { inScalar[i] = scalars[i] }
        var outScalar = [UInt64](repeating: 0, count: 8)
        var outScalarCount: UInt32 = 8
        var outBuff = [UInt8](repeating: 0, count: 0x1000)
        var outSz = 0x1000
        var k2: kern_return_t = -1
        outBuff.withUnsafeMutableBytes { ob in
            k2 = IOConnectCallMethod(conn, sel, &inScalar, UInt32(scalars.count), nil, 0, &outScalar, &outScalarCount, ob.baseAddress, &outSz)
        }
        let k2u = UInt32(bitPattern: k2)
        log("  kr=0x\(String(k2u, radix:16)) outSz=\(outSz) outScalarCount=\(outScalarCount)")
        if k2u == KERN_SUCCESS {
            for i in 0..<min(Int(outScalarCount), 8) {
                log("  outScalar[\(i)]=0x\(String(outScalar[i], radix:16))")
            }
        }
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        log("=== AGXProbe v47 — AppleKeyStore deep probe (17 Pro) ===")

        // sel=0x0: empty input, various output sizes
        log("\n--- AppleKeyStore sel=0x0 ---")
        probeSelStruct("AppleKeyStore", 0, 0x0, [], 0x100)
        probeSelStruct("AppleKeyStore", 0, 0x0, [], 0x1000)

        // sel=0x1: empty input
        log("\n--- AppleKeyStore sel=0x1 ---")
        probeSelStruct("AppleKeyStore", 0, 0x1, [], 0x100)

        // sel=0x10: empty input
        log("\n--- AppleKeyStore sel=0x10 ---")
        probeSelStruct("AppleKeyStore", 0, 0x10, [], 0x100)

        // sel=0x11: empty input
        log("\n--- AppleKeyStore sel=0x11 ---")
        probeSelStruct("AppleKeyStore", 0, 0x11, [], 0x100)

        // sel=0x1f: empty input
        log("\n--- AppleKeyStore sel=0x1f ---")
        probeSelStruct("AppleKeyStore", 0, 0x1f, [], 0x100)

        // sel=0x0 with scalar input
        log("\n--- AppleKeyStore sel=0x0 with scalars ---")
        probeSelScalar("AppleKeyStore", 0, 0x0, [0])
        probeSelScalar("AppleKeyStore", 0, 0x0, [1])
        probeSelScalar("AppleKeyStore", 0, 0x0, [0, 0])

        // sel=0x10 with scalar input
        log("\n--- AppleKeyStore sel=0x10 with scalars ---")
        probeSelScalar("AppleKeyStore", 0, 0x10, [0])
        probeSelScalar("AppleKeyStore", 0, 0x10, [1])

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
