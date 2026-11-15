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
            Text("AGXProbe v58 - runtime BL scan of notify callees").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v58")
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

    /// exact shape used by IOSurface.framework for the port-aware set call
    typealias SetCallFn = @convention(c) (
        io_connect_t, UInt32, mach_port_t,
        UnsafePointer<UInt64>?, UInt32,
        UnsafeRawPointer?, Int,
        UnsafeMutableRawPointer?, UInt64,
        UnsafeRawPointer?, UnsafeRawPointer?
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
        guard let h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY) else {
            emit("[NO] dlopen"); return false
        }
        defer { dlclose(h) }
        guard let cs = dlsym(h, "IOSurfaceCreate"), let isym = dlsym(h, "IOSurfaceGetID"),
              let ss = dlsym(h, "IOSurfaceClientSetSurfaceNotify") else {
            emit("[NO] symbol"); return false
        }
        gCreate = unsafeBitCast(cs, to: CreateFn.self)
        gGetID = unsafeBitCast(isym, to: GetIDFn.self)
        gSet = unsafeBitCast(ss, to: SetNotifyFn.self)
        emit("  IOSurfaceClientSetSurfaceNotify @ \(UInt(bitPattern: ss))")
        return true
    }

    private func makeSurface() -> UnsafeMutableRawPointer? {
        guard let gCreate else { return nil }
        let p: [String: Any] = ["IOSurfaceWidth": 256, "IOSurfaceHeight": 256,
                                "IOSurfaceBytesPerElement": 4]
        return gCreate(p as CFDictionary)
    }

    private func krstr(_ kr: kern_return_t) -> String {
        let u = UInt32(bitPattern: kr)
        switch u {
        case 0: return "0x0 SUCCESS"
        case 0xe00002c2: return "BadArgument"
        case 0xe00002c9: return "dup"
        case 0xe00002bd: return "0x2bd"
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

    /// runtime scan of BL instructions inside a function
    private func blTargets(_ fn: UnsafeMutableRawPointer, _ len: Int) -> [(Int, UInt64)] {
        var out: [(Int, UInt64)] = []
        let base = UInt64(UInt(bitPattern: fn))
        for off in stride(from: 0, to: len, by: 4) {
            guard let p = UnsafeRawPointer(bitPattern: Int(base + UInt64(off))) else { continue }
            let insn = p.load(as: UInt32.self)
            guard (insn >> 26) == 0b100101 else { continue }
            let imm26 = Int64(insn & 0x03FFFFFF)
            let signed = (imm26 << 38) >> 38
            let target = UInt64(bitPattern: Int64(base + UInt64(off)) + 4 + (signed << 2))
            out.append((off, target))
        }
        return out
    }

    private func probe() {
        // --- find IOConnectCallMethod ------------------------------------------------
        emit("\n=== E0 locate IOConnectCallMethod ===")
        var iocm: UInt64? = nil
        if let p = dlsym(nil, "IOConnectCallMethod") { iocm = UInt64(UInt(bitPattern: p)); emit("  RTLD_DEFAULT -> \(iocm!)") }
        if iocm == nil {
            for path in ["/usr/lib/system/libsystem_kernel.dylib",
                         "/usr/lib/libSystem.B.dylib",
                         "/usr/lib/system/libsystem_platform.dylib"] {
                guard let h = dlopen(path, RTLD_NOW) else { continue }
                if let p = dlsym(h, "IOConnectCallMethod") {
                    iocm = UInt64(UInt(bitPattern: p)); emit("  \(path) -> \(iocm!)"); break
                }
            }
        }
        if iocm == nil { emit("  IOConnectCallMethod symbol not found via dlsym") }

        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setFn = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let rmFn = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify") else {
            emit("  symbol fail"); return
        }

        emit("\n=== E1 runtime BL scan ===")
        let setBLs = blTargets(setFn, 0x200)
        emit("  setNotify fn @ \(UInt(bitPattern: setFn))")
        for (off, t) in setBLs {
            let mark = (iocm != nil && t == iocm!) ? "   <== IOConnectCallMethod" : ""
            emit("    +0x\(String(off, radix: 16)) -> 0x\(String(t, radix: 16))\(mark)")
        }
        let rmBLs = blTargets(rmFn, 0x100)
        emit("  removeNotify fn @ \(UInt(bitPattern: rmFn))")
        for (off, t) in rmBLs {
            let mark = (iocm != nil && t == iocm!) ? "   <== IOConnectCallMethod" : ""
            emit("    +0x\(String(off, radix: 16)) -> 0x\(String(t, radix: 16))\(mark)")
        }

        // --- surface + our own connection -------------------------------------------
        guard let s = makeSurface() else { emit("[NO] create"); return }
        let sid = UInt64(gGetID!(s))
        emit("\n=== E2 setup ===")
        emit("  surface id 0x\(String(sid, radix: 16)) port 0x\(String(gPort, radix: 16))")
        let (okr, conn) = tryOpen("IOSurfaceRoot", 0)
        emit("  open IOSurfaceRoot -> \(krstr(okr)) conn=\(conn)")
        guard okr == KERN_SUCCESS else { return }

        // framework inputs, exactly as the framework builds them
        var inScalars: [UInt64] = [0, 1, sid]        // {0, type, surfaceID}
        var outScalars: [UInt64] = [1, sid, 0]       // {type, surfaceID, 0}

        emit("\n=== E3 try each BL target with the framework's set layout ===")
        var winner: UInt64? = nil
        for (off, t) in setBLs {
            guard let ptr = UnsafeRawPointer(bitPattern: Int(t)) else { continue }
            let fn = unsafeBitCast(ptr, to: SetCallFn.self)
            var kr: kern_return_t = -1
            inScalars.withUnsafeBufferPointer { ib in
                outScalars.withUnsafeMutableBufferPointer { ob in
                    kr = fn(conn, 0x11, gPort,
                            UnsafeRawPointer(ib.baseAddress!).assumingMemoryBound(to: UInt64.self), 3,
                            nil, 0,
                            UnsafeMutableRawPointer(ob.baseAddress!), 0x18,
                            nil, nil)
                }
            }
            emit("  +0x\(String(off, radix: 16)) target 0x\(String(t, radix: 16)) -> \(krstr(kr))")
            if UInt32(bitPattern: kr) == 0 { winner = t; break }
        }

        guard let win = winner else {
            emit("  no candidate returned 0x0")
            IOServiceClose(conn)
            Unmanaged<AnyObject>.fromOpaque(s).release()
            return
        }
        emit("  WINNER = 0x\(String(win, radix: 16))")

        // --- validate ownership: duplicate + remove on our own connection ------------
        guard let ptr = UnsafeRawPointer(bitPattern: Int(win)) else { return }
        let fn = unsafeBitCast(ptr, to: SetCallFn.self)
        var kr: kern_return_t = -1
        inScalars.withUnsafeBufferPointer { ib in
            outScalars.withUnsafeMutableBufferPointer { ob in
                kr = fn(conn, 0x11, gPort,
                        UnsafeRawPointer(ib.baseAddress!).assumingMemoryBound(to: UInt64.self), 3,
                        nil, 0,
                        UnsafeMutableRawPointer(ob.baseAddress!), 0x18,
                        nil, nil)
            }
        }
        emit("  set again (expect dup) -> \(krstr(kr))")

        var rmStruct: [UInt64] = [0, sid, 0]
        kr = -1
        rmStruct.withUnsafeBufferPointer { sb in
            kr = IOConnectCallMethod(conn, 0x12, nil, 0,
                                     UnsafeRawPointer(sb.baseAddress!), 0x18,
                                     nil, nil, nil, nil)
        }
        emit("  plain remove (SDK IOConnectCallMethod) -> \(krstr(kr))")

        emit("\n=== done ===")
        IOServiceClose(conn)
        Unmanaged<AnyObject>.fromOpaque(s).release()
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v58 - runtime BL scan ===")
        guard loadSymbols() else { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        let pkr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("  notify port 0x\(String(gPort, radix: 16))")
        if pkr != KERN_SUCCESS { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        try? await Task.sleep(nanoseconds: 3_500_000_000)
        probe()
        status = "Complete"; isRunning = false
    }
}
