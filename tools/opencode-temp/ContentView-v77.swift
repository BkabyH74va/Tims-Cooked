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
            Text("AGXProbe v77 - IOKit user client direct call").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v77")
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
        emit("=== AGXProbe v77 - IOKit user client direct call ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)

        guard let iokitH = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW) else {
            emit("[-] dlopen IOKit failed"); status = "Complete"; isRunning = false; return
        }
        emit("[*] IOKit framework loaded")

        typealias IOServiceGetMatchingServicesFn = @convention(c) (mach_port_t, UnsafeMutableRawPointer, UnsafeMutablePointer<io_iterator_t>?) -> kern_return_t
        typealias IOIteratorNextFn = @convention(c) (io_iterator_t) -> io_object_t
        typealias IOServiceOpenFn = @convention(c) (io_object_t, mach_port_t, UInt32, UnsafeMutablePointer<io_connect_t>?) -> kern_return_t
        typealias IOObjectReleaseFn = @convention(c) (io_object_t) -> kern_return_t
        typealias IOServiceMatchingFn = @convention(c) (UnsafePointer<Int8>) -> UnsafeMutableRawPointer?
        typealias IOConnectCallMethodFn = @convention(c) (
            io_connect_t, UInt32, UnsafePointer<UInt64>?, UInt32,
            UnsafeMutableRawPointer?, UInt64,
            UnsafeMutablePointer<UInt64>?, UnsafeMutablePointer<UInt32>?,
            UnsafeMutableRawPointer?, UnsafeMutablePointer<UInt64>?
        ) -> kern_return_t

        guard let IOServiceGetMatchingServices = dlsym(iokitH, "IOServiceGetMatchingServices"),
              let IOIteratorNext = dlsym(iokitH, "IOIteratorNext"),
              let IOServiceOpen = dlsym(iokitH, "IOServiceOpen"),
              let IOObjectRelease = dlsym(iokitH, "IOObjectRelease"),
              let IOServiceMatching = dlsym(iokitH, "IOServiceMatching"),
              let IOConnectCallMethod = dlsym(iokitH, "IOConnectCallMethod") else {
            emit("[-] some IOKit symbols missing"); status = "Complete"; isRunning = false; return
        }
        emit("[*] all IOKit symbols resolved")

        var gPortLocal: mach_port_t = 0
        var krPort = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPortLocal)
        self.gPort = gPortLocal
        emit("[*] port 0x\(String(gPortLocal, radix: 16)) kr=0x\(String(krPort, radix: 16))")
        if krPort != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        let ioServiceGetMatchingServices = unsafeBitCast(IOServiceGetMatchingServices, to: IOServiceGetMatchingServicesFn.self)
        let ioIteratorNext = unsafeBitCast(IOIteratorNext, to: IOIteratorNextFn.self)
        let ioServiceOpen = unsafeBitCast(IOServiceOpen, to: IOServiceOpenFn.self)
        let ioObjectRelease = unsafeBitCast(IOObjectRelease, to: IOObjectReleaseFn.self)
        let ioServiceMatching = unsafeBitCast(IOServiceMatching, to: IOServiceMatchingFn.self)
        let ioConnectCallMethod = unsafeBitCast(IOConnectCallMethod, to: IOConnectCallMethodFn.self)

        let matching = ioServiceMatching("IOSurfaceRoot")
        guard let matchingPtr = matching else {
            emit("[-] IOServiceMatching returned nil"); status = "Complete"; isRunning = false; return
        }
        var matchingIter: io_iterator_t = 0
        let krMatch = ioServiceGetMatchingServices(kIOMainPortDefault, matchingPtr, &matchingIter)
        emit("[1] IOServiceGetMatchingServices kr=0x\(String(krMatch, radix: 16))")
        if krMatch != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        var service: io_object_t = 0
        let svc = ioIteratorNext(matchingIter)
        if svc == 0 {
            emit("[-] no service found")
            ioObjectRelease(matchingIter)
            status = "Complete"; isRunning = false; return
        }
        service = svc
        emit("[2] found service 0x\(String(service, radix: 16))")

        var conn: io_connect_t = 0
        let krOpen = ioServiceOpen(service, mach_task_self_, 0, &conn)
        emit("[3] IOServiceOpen kr=0x\(String(krOpen, radix: 16)) conn=0x\(String(conn, radix: 16))")
        ioObjectRelease(service)
        ioObjectRelease(matchingIter)
        if krOpen != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        var input: [UInt64] = [UInt64(gPort), 1, UInt64(0x1234)]
        var output: UInt64 = 0
        var outputCnt: UInt32 = 1

        emit("\n=== Test: IOConnectCallMethod sel=0x11 (set_notify) ===")
        emit("[*] calling with port=0x\(String(gPort, radix: 16)) type=1 surfaceID=0x1234")
        let kr1 = ioConnectCallMethod(conn, 0x11, &input, 3, nil, 0, &output, &outputCnt, nil, nil)
        emit("[*] sel=0x11 inputCnt=3 kr=0x\(String(kr1, radix: 16)) output=0x\(String(output, radix: 16)) outputCnt=\(outputCnt)")

        emit("[*] calling sel=0x11 inputCnt=0")
        let kr2 = ioConnectCallMethod(conn, 0x11, nil, 0, nil, 0, &output, &outputCnt, nil, nil)
        emit("[*] sel=0x11 inputCnt=0 kr=0x\(String(kr2, radix: 16)) output=0x\(String(output, radix: 16)) outputCnt=\(outputCnt)")

        var input2: [UInt64] = [UInt64(0x1234)]
        emit("[*] calling sel=0x12 (remove_notify) surfaceID=0x1234")
        let kr3 = ioConnectCallMethod(conn, 0x12, &input2, 1, nil, 0, &output, &outputCnt, nil, nil)
        emit("[*] sel=0x12 inputCnt=1 kr=0x\(String(kr3, radix: 16)) output=0x\(String(output, radix: 16)) outputCnt=\(outputCnt)")

        var input3: [UInt64] = [UInt64(gPort)]
        emit("[*] calling sel=0x11 inputCnt=1 (port only)")
        let kr4 = ioConnectCallMethod(conn, 0x11, &input3, 1, nil, 0, &output, &outputCnt, nil, nil)
        emit("[*] sel=0x11 inputCnt=1 kr=0x\(String(kr4, radix: 16)) output=0x\(String(output, radix: 16)) outputCnt=\(outputCnt)")

        emit("[*] calling sel=0x13 (unknown)")
        let kr5 = ioConnectCallMethod(conn, 0x13, &input, 3, nil, 0, &output, &outputCnt, nil, nil)
        emit("[*] sel=0x13 inputCnt=3 kr=0x\(String(kr5, radix: 16)) output=0x\(String(output, radix: 16)) outputCnt=\(outputCnt)")

        ioObjectRelease(conn)

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
