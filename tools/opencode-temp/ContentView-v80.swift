import SwiftUI
import Darwin
import Foundation
import CoreFoundation

@main
struct AGXProbeApp: App {
    var body: some Scene { WindowGroup { ContentView() } }
}

struct ContentView: View {
    @StateObject private var vm = ReachViewModel()
    var body: some View {
        VStack(spacing: 12) {
            Text("AGXProbe v80 - IOKit selector fuzzing").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v80")
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
    var gPort: mach_port_t = 0

    private let logFileURL: URL = {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("reach.log")
    }()

    private func emit(_ m: String) {
        log += m + "\n"; print(m); fflush(stdout)
        try? log.write(to: logFileURL, atomically: true, encoding: .utf8)
    }

    func autoRunIfRequested() async {
        guard !didAutoRun else { return }
        didAutoRun = true
        if ProcessInfo.processInfo.arguments.contains("--autorun") { await runProbe() }
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v80 - IOKit selector fuzzing ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)

        var matchingIter: io_iterator_t = 0
        let krMatch = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOSurfaceRoot"), &matchingIter)
        emit("[1] IOServiceGetMatchingServices kr=0x\(String(krMatch, radix: 16))")
        if krMatch != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        var service: io_object_t = 0
        let svc = IOIteratorNext(matchingIter)
        if svc == 0 {
            emit("[-] no service found")
            IOObjectRelease(matchingIter)
            status = "Complete"; isRunning = false; return
        }
        service = svc
        emit("[2] found service 0x\(String(service, radix: 16))")

        var conn: io_connect_t = 0
        let krOpen = IOServiceOpen(service, mach_task_self(), 0, &conn)
        emit("[3] IOServiceOpen kr=0x\(String(krOpen, radix: 16)) conn=0x\(String(conn, radix: 16))")
        IOObjectRelease(service)
        IOObjectRelease(matchingIter)
        if krOpen != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        var gPortLocal: mach_port_t = 0
        var krPort = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gPortLocal)
        self.gPort = gPortLocal
        emit("[*] port 0x\(String(gPortLocal, radix: 16)) kr=0x\(String(krPort, radix: 16))")
        if krPort != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        emit("\n=== Fuzzing IOConnectCallMethod selectors 0x0-0x20 ===")
        var input: [UInt64] = [UInt64(self.gPort), 1, UInt64(0x1234)]
        var output: UInt64 = 0
        var outputCnt: UInt32 = 1

        var interesting: [UInt32] = []
        for selUInt32: UInt32 in 0...0x20 {
            let kr = IOConnectCallMethod(conn, selUInt32, &input, 3, nil, 0, &output, &outputCnt, nil, nil)
            let krUInt32 = UInt32(bitPattern: kr)
            let krStr = String(kr, radix: 16)
            if krUInt32 != 0 && krUInt32 != 0xe00002c2 {
                emit("[!] sel=0x\(String(selUInt32, radix: 16)) kr=0x\(krStr) output=0x\(String(output, radix: 16)) outputCnt=\(outputCnt)  <-- INTERESTING")
                interesting.append(selUInt32)
            } else if selUInt32 <= 0x10 {
                emit("[*] sel=0x\(String(selUInt32, radix: 16)) kr=0x\(krStr)")
            }
        }
        emit("[*] Interesting selectors: \(interesting.map { String($0, radix: 16) }.joined(separator: ", "))")

        IOObjectRelease(conn)

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}

// External IOKit function declarations
@_silgen_name("IOServiceGetMatchingServices")
func IOServiceGetMatchingServices(_ masterPort: mach_port_t, _ matching: UnsafeMutableRawPointer, _ existing: UnsafeMutablePointer<io_iterator_t>?) -> kern_return_t

@_silgen_name("IOIteratorNext")
func IOIteratorNext(_ iterator: io_iterator_t) -> io_object_t

@_silgen_name("IOServiceOpen")
func IOServiceOpen(_ service: io_object_t, _ owningTask: mach_port_t, _ type: UInt32, _ client: UnsafeMutablePointer<io_connect_t>?) -> kern_return_t

@_silgen_name("IOObjectRelease")
func IOObjectRelease(_ object: io_object_t) -> kern_return_t

@_silgen_name("IOServiceMatching")
func IOServiceMatching(_ name: UnsafePointer<Int8>) -> UnsafeMutableRawPointer?

@_silgen_name("IOConnectCallMethod")
func IOConnectCallMethod(_ connection: io_connect_t, _ selector: UInt32, _ input: UnsafePointer<UInt64>?, _ inputCnt: UInt32, _ inputStruct: UnsafeMutableRawPointer?, _ inputStructCnt: UInt64, _ output: UnsafeMutablePointer<UInt64>?, _ outputCnt: UnsafeMutablePointer<UInt32>?, _ outputStruct: UnsafeMutableRawPointer?, _ outputStructCnt: UnsafeMutablePointer<UInt64>?) -> kern_return_t
