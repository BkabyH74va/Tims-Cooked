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
            Text("AGXProbe v89 - IOKit service enumeration").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v89")
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
        emit("=== AGXProbe v89 - IOKit service enumeration ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)

        guard let iokitH = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW) else {
            emit("[-] dlopen IOKit failed"); status = "Complete"; isRunning = false; return
        }
        emit("[*] IOKit framework loaded")

        typealias IOServiceGetMatchingServicesFn = @convention(c) (mach_port_t, UnsafeMutableRawPointer, UnsafeMutablePointer<io_iterator_t>?) -> kern_return_t
        typealias IOIteratorNextFn = @convention(c) (io_iterator_t) -> io_object_t
        typealias IOObjectReleaseFn = @convention(c) (io_object_t) -> kern_return_t
        typealias IOServiceMatchingFn = @convention(c) (UnsafePointer<Int8>) -> UnsafeMutableRawPointer?
        typealias IORegistryEntryGetNameFn = @convention(c) (io_object_t, UnsafeMutablePointer<Int8>) -> kern_return_t

        guard let IOServiceGetMatchingServices = dlsym(iokitH, "IOServiceGetMatchingServices"),
              let IOIteratorNext = dlsym(iokitH, "IOIteratorNext"),
              let IOObjectRelease = dlsym(iokitH, "IOObjectRelease"),
              let IOServiceMatching = dlsym(iokitH, "IOServiceMatching"),
              let IORegistryEntryGetName = dlsym(iokitH, "IORegistryEntryGetName") else {
            emit("[-] some IOKit symbols missing"); status = "Complete"; isRunning = false; return
        }

        let ioServiceGetMatchingServices = unsafeBitCast(IOServiceGetMatchingServices, to: IOServiceGetMatchingServicesFn.self)
        let ioIteratorNext = unsafeBitCast(IOIteratorNext, to: IOIteratorNextFn.self)
        let ioObjectRelease = unsafeBitCast(IOObjectRelease, to: IOObjectReleaseFn.self)
        let ioServiceMatchingFn = unsafeBitCast(IOServiceMatching, to: IOServiceMatchingFn.self)
        let ioRegistryEntryGetName = unsafeBitCast(IORegistryEntryGetName, to: IORegistryEntryGetNameFn.self)

        // Enumerate all IOService objects
        emit("\n=== Enumerating all IOService objects ===")
        let matching = ioServiceMatchingFn("IOService")
        guard let matchingPtr = matching else {
            emit("[-] IOServiceMatching returned nil"); status = "Complete"; isRunning = false; return
        }
        var iter: io_iterator_t = 0
        let krMatch = ioServiceGetMatchingServices(kIOMainPortDefault, matchingPtr, &iter)
        emit("[1] IOServiceGetMatchingServices kr=0x\(String(krMatch, radix: 16))")
        if krMatch != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        var count = 0
        while true {
            let svc = ioIteratorNext(iter)
            if svc == 0 { break }
            count += 1
            var nameBuf = [Int8](repeating: 0, count: 256)
            let krName = ioRegistryEntryGetName(svc, &nameBuf)
            let name = krName == KERN_SUCCESS ? String(cString: nameBuf) : "unknown"
            emit("  [\(count)] service 0x\(String(svc, radix: 16)) name=\(name)")
        }
        emit("[*] Total services: \(count)")
        ioObjectRelease(iter)

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}

// External IOKit function declarations
@_silgen_name("IOServiceGetMatchingServices")
func IOServiceGetMatchingServices(_ masterPort: mach_port_t, _ matching: UnsafeMutableRawPointer, _ existing: UnsafeMutablePointer<io_iterator_t>?) -> kern_return_t

@_silgen_name("IOIteratorNext")
func IOIteratorNext(_ iterator: io_iterator_t) -> io_object_t

@_silgen_name("IOObjectRelease")
func IOObjectRelease(_ object: io_object_t) -> kern_return_t

@_silgen_name("IOServiceMatching")
func IOServiceMatching(_ name: UnsafePointer<Int8>) -> UnsafeMutableRawPointer?

@_silgen_name("IORegistryEntryGetName")
func IORegistryEntryGetName(_ entry: io_object_t, _ name: UnsafeMutablePointer<Int8>) -> kern_return_t

@_silgen_name("mach_task_self")
func mach_task_self() -> mach_port_t
