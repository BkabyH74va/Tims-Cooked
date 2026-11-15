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
            Text("AGXProbe v48 — IOSurface notify shape").font(.headline)
            Text("sel 0x11/0x12 need stIn=0x18, sIn=0").font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v48")
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

    // MARK: - IOKit helpers

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

    /// Call a selector with ZERO scalar inputs and a fixed-size struct input.
    private func callStruct(_ conn: io_connect_t, _ sel: UInt32, _ bytes: [UInt8]) -> (kr: kern_return_t, outSz: Int) {
        var out = [UInt8](repeating: 0, count: 0x40)
        var outCnt: Int = 0x40
        var kr: kern_return_t = -1
        bytes.withUnsafeBytes { ib in
            out.withUnsafeMutableBytes { ob in
                kr = IOConnectCallMethod(conn, sel,
                                         nil, 0,
                                         ib.baseAddress, Int(bytes.count),
                                         nil, nil,
                                         ob.baseAddress, &outCnt)
            }
        }
        return (kr, outCnt)
    }

    // MARK: - Part A: framework path (dlsym)

    private func frameworkPath() {
        emit("\n=== A · framework notify path (dlsym) ===")
        guard let handle = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY) else {
            emit("[NO] dlopen IOSurface failed: \(String(cString: dlerror()))")
            return
        }
        defer { dlclose(handle) }

        typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
        typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32
        typealias SetNotifyFn = @convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t
        typealias RemoveNotifyFn = @convention(c) (UInt64) -> kern_return_t

        guard let createSym = dlsym(handle, "IOSurfaceCreate"),
              let idSym = dlsym(handle, "IOSurfaceGetID") else {
            emit("[NO] IOSurfaceCreate/GetID missing"); return
        }
        let create = unsafeBitCast(createSym, to: CreateFn.self)
        let getID = unsafeBitCast(idSym, to: GetIDFn.self)

        let setSym = dlsym(handle, "IOSurfaceClientSetSurfaceNotify")
        let remSym = dlsym(handle, "IOSurfaceClientRemoveSurfaceNotify")
        emit("     IOSurfaceClientSetSurfaceNotify    = \(setSym.map { String(UInt(bitPattern: $0), radix: 16) } ?? "NOT FOUND")")
        emit("     IOSurfaceClientRemoveSurfaceNotify = \(remSym.map { String(UInt(bitPattern: $0), radix: 16) } ?? "NOT FOUND")")

        let propsAny: [String: Any] = ["IOSurfaceWidth": 64, "IOSurfaceHeight": 64,
                                       "IOSurfaceBytesPerElement": 4]
        let props = propsAny as CFDictionary
        guard let surface = create(props) else { emit("[NO] IOSurfaceCreate failed"); return }
        let sid = UInt32(getID(surface))
        emit("     surface id = 0x\(String(sid, radix: 16))")

        var port: mach_port_t = 0
        let pkr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port)
        emit("     notify port = 0x\(String(port, radix: 16)) (kr=0x\(String(UInt32(bitPattern: pkr), radix: 16)))")

        guard let setSym, let remSym else { return }
        let setNotify = unsafeBitCast(setSym, to: SetNotifyFn.self)
        let remNotify = unsafeBitCast(remSym, to: RemoveNotifyFn.self)

        let id64 = UInt64(sid)
        let port64 = UInt64(port)

        // order 1: set(port, type, surfaceID)
        var kr = setNotify(port, 1, id64)
        emit("     set(port, type=1, id)   kr=0x\(String(UInt32(bitPattern: kr), radix: 16))")
        kr = setNotify(port, 1, id64)
        emit("     set again               kr=0x\(String(UInt32(bitPattern: kr), radix: 16))")
        kr = remNotify(id64)
        emit("     remove(id)              kr=0x\(String(UInt32(bitPattern: kr), radix: 16))")
        kr = remNotify(id64)
        emit("     remove(id) again        kr=0x\(String(UInt32(bitPattern: kr), radix: 16))")
        kr = setNotify(port, 1, id64)
        emit("     set after remove        kr=0x\(String(UInt32(bitPattern: kr), radix: 16))")
        kr = remNotify(id64)
        emit("     remove(id) final        kr=0x\(String(UInt32(bitPattern: kr), radix: 16))")
    }

    // MARK: - Part B: raw kernel path (no framework)

    private func rawPath() {
        emit("\n=== B · raw IOSurfaceRoot sel 0x11/0x12 (0 scalars, 0x18 struct) ===")
        let (okr, conn) = tryOpen("IOSurfaceRoot", 0)
        if okr != KERN_SUCCESS {
            emit("     open failed kr=0x\(String(UInt32(bitPattern: okr), radix: 16))"); return
        }
        defer { IOServiceClose(conn) }
        emit("     conn=0x\(String(conn, radix: 16))")

        // make a surface so we have a real id
        guard let handle = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY) else { return }
        defer { dlclose(handle) }
        typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
        typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32
        guard let cs = dlsym(handle, "IOSurfaceCreate"), let isym = dlsym(handle, "IOSurfaceGetID") else { return }
        let create = unsafeBitCast(cs, to: CreateFn.self)
        let getID = unsafeBitCast(isym, to: GetIDFn.self)
        let propsAny: [String: Any] = ["IOSurfaceWidth": 64, "IOSurfaceHeight": 64,
                                       "IOSurfaceBytesPerElement": 4]
        let props = propsAny as CFDictionary
        guard let surf = create(props) else { return }
        let sid = UInt64(getID(surf))
        emit("     surface id = 0x\(String(sid, radix: 16))")

        var port: mach_port_t = 0
        _ = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port)
        let port64 = UInt64(port)

        struct Layout { let name: String; let words: [UInt64] }
        let layouts = [
            Layout(name: "{type=1,id,0}",        words: [1, sid, 0]),
            Layout(name: "{0,id,0}",            words: [0, sid, 0]),
            Layout(name: "{port,1,id}",         words: [port64, 1, sid]),
            Layout(name: "{port,id,1}",         words: [port64, sid, 1]),
            Layout(name: "{id,1,0}",            words: [sid, 1, 0]),
            Layout(name: "{1,id,port}",         words: [1, sid, port64]),
            Layout(name: "{port,id,0}",         words: [port64, sid, 0]),
        ]

        for sel in [UInt32(0x11), UInt32(0x12)] {
            emit("     -- selector 0x\(String(sel, radix: 16)) --")
            for l in layouts {
                var bytes = [UInt8](repeating: 0, count: 0x18)
                for (i, w) in l.words.enumerated() {
                    withUnsafeBytes(of: w.littleEndian) { wb in
                        for j in 0..<8 { bytes[i * 8 + j] = wb[j] }
                    }
                }
                let (kr, outSz) = callStruct(conn, sel, bytes)
                let u = UInt32(bitPattern: kr)
                let tag = u == 0xe00002c2 ? "BadArgument" : (u == 0 ? "SUCCESS" : "")
                emit("     \(l.name.padding(toLength: 14, withPad: " ", startingAt: 0)) kr=0x\(String(u, radix: 16)) \(tag) outSz=\(outSz)")
            }
        }
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v48 — IOSurface notify shape ===")
        emit("kernel dispatch: sel 0x11 sIn=0 stIn=0x18 sOut=0 stOut=0")
        emit("kernel dispatch: sel 0x12 sIn=0 stIn=0x18 sOut=0 stOut=0")

        frameworkPath()
        rawPath()

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
