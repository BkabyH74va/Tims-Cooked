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
            Text("AGXProbe v63 - service class hunt").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v63")
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
    typealias ConnectInternalFn = @convention(c) (UInt8) -> io_connect_t
    typealias SetCallFn = @convention(c) (
        io_connect_t, UInt32, mach_port_t,
        UnsafePointer<UInt64>?, UInt32,
        UnsafeRawPointer?, Int,
        UnsafeMutableRawPointer?, UInt64,
        UnsafeRawPointer?, UnsafeRawPointer?
    ) -> kern_return_t

    // MARK: - helpers

    private func krstr(_ kr: kern_return_t) -> String {
        let u = UInt32(bitPattern: kr)
        switch u {
        case 0: return "0x0 SUCCESS"
        case 0xe00002c2: return "BadArgument"
        case 0xe00002c9: return "dup-notify"
        case 0xe00002bd: return "alloc-fail"
        case 0xe00002d8: return "NotAttached"
        case 0xe00002c7: return "Unsupported"
        case 0xe00002e2: return "NotPermitted"
        case 0xe00002be: return "NoResources"
        default: return "0x" + String(u, radix: 16)
        }
    }

    private func hex(_ v: UInt64) -> String { "0x" + String(v, radix: 16) }

    private func blTarget(_ fn: UnsafeMutableRawPointer, _ off: Int) -> UInt64? {
        let fnAddr = Int(UInt(bitPattern: fn))
        guard let p = UnsafeRawPointer(bitPattern: fnAddr + off) else { return nil }
        let insn = p.load(as: UInt32.self)
        guard (insn >> 26) == 0b100101 else { return nil }
        let imm26 = Int64(insn & 0x03FFFFFF)
        let signed = (imm26 << 38) >> 38
        return UInt64(bitPattern: Int64(fnAddr + off) + (signed << 2))
    }

    private func serviceName(_ svc: io_service_t) -> String {
        var name: Unmanaged<CFString>?
        let kr = IORegistryEntryGetName(svc, &name)
        if kr == KERN_SUCCESS, let n = name?.takeRetainedValue() { return n as String }
        return "<unnamed>"
    }

    private func className(_ svc: io_service_t) -> String {
        guard let p = IORegistryEntryCreateCFProperty(svc, "IOService" as CFString, kCFAllocatorDefault, 0) else {
            return "<no class>"
        }
        return (p.takeRetainedValue() as? String) ?? "<class not string>"
    }

    private func enumerate(_ name: String) -> [io_service_t] {
        var out: [io_service_t] = []
        guard let m = IOServiceMatching(name) else { return out }
        var iter: io_iterator_t = 0
        if IOServiceGetMatchingServices(kIOMainPortDefault, m, &iter) != KERN_SUCCESS { return out }
        while true {
            let svc = IOIteratorNext(iter)
            if svc == 0 { break }
            out.append(svc)
        }
        IOObjectRelease(iter)
        return out
    }

    // MARK: - probe

    private func probe() {
        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setFn = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let cs = dlsym(fwH, "IOSurfaceCreate"),
              let isym = dlsym(fwH, "IOSurfaceGetID"),
              let ciSym = dlsym(fwH, "_ioSurfaceConnectInternal") else {
            emit("symbol fail"); return
        }
        let gCreate = unsafeBitCast(cs, to: CreateFn.self)
        let gGetID = unsafeBitCast(isym, to: GetIDFn.self)
        let connectInternal = unsafeBitCast(ciSym, to: ConnectInternalFn.self)
        guard let setCallee = blTarget(setFn, 0x78),
              let setPtr = UnsafeRawPointer(bitPattern: Int(setCallee)) else {
            emit("BL decode failed"); return
        }
        let setCall = unsafeBitCast(setPtr, to: SetCallFn.self)
        emit("set callee @ " + hex(setCallee))

        // framework's cached connection
        let fwConn = connectInternal(0)
        emit("framework conn (via _ioSurfaceConnectInternal) = " + String(fwConn))

        // surface
        let props: [String: Any] = ["IOSurfaceWidth": 256, "IOSurfaceHeight": 256,
                                    "IOSurfaceBytesPerElement": 4]
        guard let surf = gCreate(props as CFDictionary) else { emit("create failed"); return }
        let sid = UInt64(gGetID(surf))
        emit("surface id = " + hex(sid))

        // port
        var port: mach_port_t = 0
        mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port)
        emit("port = " + hex(UInt64(port)))

        func trySet(_ conn: io_connect_t, _ label: String) {
            var inScalars: [UInt64] = [0, 1, sid]
            var structBuf: [UInt64] = [1, sid, 0]
            var kr: kern_return_t = -1
            inScalars.withUnsafeBufferPointer { ib in
                structBuf.withUnsafeMutableBufferPointer { sb in
                    kr = setCall(conn, 0x11, port,
                                 UnsafeRawPointer(ib.baseAddress!).assumingMemoryBound(to: UInt64.self),
                                 3, nil, 0,
                                 UnsafeMutableRawPointer(sb.baseAddress!), 0x18,
                                 nil, nil)
                }
            }
            emit("  set on " + label + " -> " + krstr(kr))
        }

        func tryRemove(_ conn: io_connect_t, _ label: String) {
            var rm: [UInt64] = [0, sid, 0]
            var kr: kern_return_t = -1
            rm.withUnsafeBufferPointer { sb in
                kr = IOConnectCallMethod(conn, 0x12, nil, 0,
                                         UnsafeRawPointer(sb.baseAddress!), 0x18,
                                         nil, nil, nil, nil)
            }
            emit("  remove on " + label + " -> " + krstr(kr))
        }

        emit("\n=== control: framework conn ===")
        trySet(fwConn, "frameworkConn")

        let names = ["IOSurfaceRoot", "IOCoreSurfaceRoot", "IOSurfaceGlobalRoot",
                     "IOSurfaceRemoteClient", "IOSurfaceRootUserClient", "IOSurfaceClient",
                     "IOSurfacePort"]
        for n in names {
            let svcs = enumerate(n)
            emit("\n=== " + n + " : " + String(svcs.count) + " service(s) ===")
            for svc in svcs {
                emit("  service '" + serviceName(svc) + "' class=" + className(svc))
                for t in 0..<3 {
                    var conn: io_connect_t = 0
                    let kr = IOServiceOpen(svc, mach_task_self_, UInt32(t), &conn)
                    if kr != KERN_SUCCESS {
                        emit("  type " + String(t) + " open -> " + krstr(kr))
                        continue
                    }
                    emit("  type " + String(t) + " conn=" + String(conn))
                    trySet(conn, n + "/type" + String(t))
                    tryRemove(conn, n + "/type" + String(t))
                    IOServiceClose(conn)
                }
                IOObjectRelease(svc)
            }
        }

        emit("\n=== done ===")
        Unmanaged<AnyObject>.fromOpaque(surf).release()
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v63 - service class hunt ===")
        try? await Task.sleep(nanoseconds: 3_500_000_000)
        probe()
        status = "Complete"; isRunning = false
    }
}
