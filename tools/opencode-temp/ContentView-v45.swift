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
            Text("AGXProbe v45 — IOKit service enumerator (17 Pro)").font(.headline)
            Text("Find all openable IOKit services").font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v45")
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

    private func probeService(_ name: String) {
        var results: [String] = []
        for type: UInt32 in [0, 1, 2, 3] {
            let (kr, conn) = tryOpen(name, type)
            if kr == KERN_SUCCESS {
                results.append("type=\(type) conn=0x\(String(conn, radix:16))")
                IOServiceClose(conn)
            } else if kr != -2 && UInt32(bitPattern: kr) != 0xe00002c7 {
                results.append("type=\(type) kr=0x\(String(UInt32(bitPattern: kr), radix:16))")
            }
        }
        if !results.isEmpty {
            log("\(name): \(results.joined(separator: ", "))")
        }
    }

    private func probeSel(_ name: String, _ type: UInt32, _ sel: UInt32) {
        let (kr, conn) = tryOpen(name, type)
        if kr != KERN_SUCCESS {
            log("\(name) type=\(type): kr=0x\(String(kr, radix:16))")
            return
        }
        defer { IOServiceClose(conn) }
        log("\(name) type=\(type): OPEN conn=0x\(String(conn, radix:16))")

        var inScalar: UInt64 = 0
        var outBuff = [UInt8](repeating: 0, count: 0x1000)
        var outSz = 0x1000
        outBuff.withUnsafeMutableBytes { ob in
            IOConnectCallMethod(conn, sel, &inScalar, 1, nil, 0, nil, nil, ob.baseAddress, &outSz)
        }
        log("  sel=\(sel) kr=0x\(String(kr, radix:16)) outSz=\(outSz)")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        log("=== AGXProbe v45 — IOKit service enumerator ===")

        // Services we haven't tested yet
        log("\n--- Untested services ---")
        probeService("AppleKeyStore")
        probeService("AppleSEPKeyStore")
        probeService("AppleSMC")
        probeService("IOPowerManagement")
        probeService("IOPCIeController")
        probeService("IOUSBHostDevice")
        probeService("AppleMultitouchDevice")
        probeService("IOHIDSystem")
        probeService("IODisplayServices")
        probeService("AGXDisplay")
        probeService("AppleM2ScalerCSCDriver")

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
