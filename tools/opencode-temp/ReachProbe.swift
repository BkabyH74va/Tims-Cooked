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
            Text("AGXProbe v14 — IOSurfaceRoot sel 0 scalar probe").font(.headline)
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
                Text(vm.isRunning ? "Probing…" : "Run IOSurface sel 0 scalar probe")
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
    private func strProp(_ s: io_service_t, _ key: String) -> String? {
        guard let v = IORegistryEntryCreateCFProperty(s, key as CFString, kCFAllocatorDefault, 0) else { return nil }
        return (v.takeRetainedValue() as? String)
    }
    private func krName(_ kr: kern_return_t) -> String {
        let v = UInt32(bitPattern: kr)
        switch v {
        case 0: return "OK"
        case 3758097091: return "NotPermitted"
        case 3758097095: return "Unsupported"
        case 3758097090: return "BadArgument"
        case 3758097094: return "ExclusiveAccess"
        case 3758097100: return "NotResponding"
        case 3758097084: return "Error"
        default: return "other"
        }
    }
    private func tryOpen(_ s: io_service_t, _ type: UInt32, cls: String, uc: String) {
        var conn: io_connect_t = 0
        let kr = IOServiceOpen(s, mach_task_self_, type, &conn)
        if kr == 0 {
            log(String(format: "  OPEN  type=%u  %@  [uc=%@]", type, cls as NSString, uc as NSString))
            IOServiceClose(conn)
        } else if UInt32(bitPattern: kr) != 3758097097 {
            log(String(format: "  %-13@ type=%u kr=0x%x %@  [uc=%@]", krName(kr) as NSString, type, UInt32(bitPattern: kr), cls as NSString, uc as NSString))
        }
    }
    func runProbe() async {
        isRunning = true; status = "Sweeping…"; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        log("=== AGXProbe v13 — IOSurfaceRoot sel 0 scalar probe (build 24A446 / t8150)")
        log("SAFETY: IOServiceOpen + IOConnectCallMethod only; no Metal; no writes")
        
        var iter: io_iterator_t = 0
        let mkr = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOSurfaceRoot"), &iter)
        guard mkr == 0 else { log("matching failed 0x\(String(mkr, radix: 16))"); status = "Failed"; isRunning = false; return }
        
        var conn: io_connect_t = 0
        var svc = IOIteratorNext(iter)
        if svc != 0 {
            let kr = IOServiceOpen(svc, mach_task_self_, 0, &conn)
            if kr == 0 {
                log("IOSurfaceRoot OPEN type=0 [uc=?]")
                
                // Test IOSurfaceRoot sel 0 with different scalar input values and struct sizes
                let tests: [(String, [UInt64], Int)] = [
                    ("scalar=0, struct=0", [0], 0),
                    ("scalar=1, struct=0", [1], 0),
                    ("scalar=2, struct=0", [2], 0),
                    ("scalar=0x80000000, struct=0", [0x80000000], 0),
                    ("scalar=0xFFFFFFFF, struct=0", [0xFFFFFFFF], 0),
                    ("scalar=0, struct=88", [0], 88),
                    ("scalar=1, struct=88", [1], 88),
                    ("scalar=2, struct=88", [2], 88),
                    ("scalar=0xFFFFFFFF, struct=88", [0xFFFFFFFF], 88),
                ]
                
                for (name, scalars, structSize) in scalarTests {
                    var inScalar: [UInt64] = [0, 0, 0, 0, 0, 0, 0, 0]
                    for i in 0..<min(scalars.count, 8) {
                        inScalar[i] = scalars[i]
                    }
                    var inScalarCount: UInt32 = UInt32(min(scalars.count, 8))
                    var outScalar: [UInt64] = [0, 0, 0, 0, 0, 0, 0, 0]
                    var outScalarCount: UInt32 = 0
                    var inStruct = [UInt8](repeating: 0, count: structSize)
                    var inStructSize: Int = structSize
                    var outStruct = [UInt8](repeating: 0, count: 512)
                    var outStructSize: Int = 512
                    let cr = IOConnectCallMethod(
                        conn, 0,
                        &inScalar, inScalarCount,
                        &inStruct, inStructSize,
                        &outScalar, &outScalarCount,
                        &outStruct, &outStructSize)
                    log(String(format: "  sel=0 %s kr=0x%x outStruct=%u", name, cr, outStructSize))
                }
                IOServiceClose(conn)
            } else {
                log("IOServiceOpen failed kr=0x\(String(kr, radix: 16))")
            }
        }
        IOObjectRelease(svc)
        IOObjectRelease(iter)
        
        status = "Complete"; isRunning = false
    }
}
