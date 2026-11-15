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
            Text("AGXProbe v46 — AppleKeyStore probe (17 Pro)").font(.headline)
            Text("Test AppleKeyStore and AppleSEPKeyStore selectors").font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v46")
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

    private func probeSels(_ name: String, _ type: UInt32, _ sels: [UInt32]) {
        let (kr, conn) = tryOpen(name, type)
        if kr != KERN_SUCCESS {
            log("\(name) type=\(type): kr=0x\(String(UInt32(bitPattern: kr), radix:16))")
            return
        }
        defer { IOServiceClose(conn) }
        log("\(name) type=\(type): OPEN conn=0x\(String(conn, radix:16))")

        for sel in sels {
            var inScalar: UInt64 = 0
            var outBuff = [UInt8](repeating: 0, count: 0x1000)
            var outSz = 0x1000
            outBuff.withUnsafeMutableBytes { ob in
                let k2 = IOConnectCallMethod(conn, sel, &inScalar, 1, nil, 0, nil, nil, ob.baseAddress, &outSz)
                if UInt32(bitPattern: k2) != 0xe00002c7 && UInt32(bitPattern: k2) != 0xe00002bd {
                    log("  sel=0x\(String(sel, radix:16)) kr=0x\(String(UInt32(bitPattern: k2), radix:16)) outSz=\(outSz)")
                }
            }
        }
    }

    private func probeSelsWithData(_ name: String, _ type: UInt32, _ sels: [(UInt32, [UInt8])]) {
        let (kr, conn) = tryOpen(name, type)
        if kr != KERN_SUCCESS {
            log("\(name) type=\(type): kr=0x\(String(UInt32(bitPattern: kr), radix:16))")
            return
        }
        defer { IOServiceClose(conn) }
        log("\(name) type=\(type): OPEN conn=0x\(String(conn, radix:16))")

        for (sel, data) in sels {
            var inScalar: UInt64 = 0
            var outBuff = [UInt8](repeating: 0, count: 0x1000)
            var outSz = 0x1000
            data.withUnsafeBytes { raw in
                outBuff.withUnsafeMutableBytes { ob in
                    let k2 = IOConnectCallMethod(conn, sel, &inScalar, 1, raw.baseAddress, data.count, nil, nil, ob.baseAddress, &outSz)
                    if UInt32(bitPattern: k2) != 0xe00002c7 && UInt32(bitPattern: k2) != 0xe00002bd {
                        log("  sel=0x\(String(sel, radix:16)) kr=0x\(String(UInt32(bitPattern: k2), radix:16)) outSz=\(outSz) inSz=\(data.count)")
                    }
                }
            }
        }
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        log("=== AGXProbe v46 — AppleKeyStore probe (17 Pro) ===")

        // Test AppleKeyStore selectors 0-31
        log("\n--- AppleKeyStore selectors 0-31 ---")
        probeSels("AppleKeyStore", 0, Array(0...31))

        // Test AppleSEPKeyStore selectors 0-31
        log("\n--- AppleSEPKeyStore selectors 0-31 ---")
        probeSels("AppleSEPKeyStore", 0, Array(0...31))

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
