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
            Text("AGXProbe v51 - raw sel 0x11/0x12 with NULL outputs").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v51")
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

    // MARK: - IOSurface handles

    typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
    typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32
    typealias SetNotifyFn = @convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t
    typealias RemoveNotifyFn = @convention(c) (UInt64) -> kern_return_t

    private var gCreate: CreateFn?
    private var gGetID: GetIDFn?
    private var gSet: SetNotifyFn?
    private var gRemove: RemoveNotifyFn?
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
        gRemove = unsafeBitCast(rs, to: RemoveNotifyFn.self)
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
        case 0xe00002c1: return "0xe00002c1 NotPrivileged"
        case 0xe00002c9: return "0xe00002c9 InternalError"
        case 0xe00002d8: return "0xe00002d8 NotAttached"
        case 0xe00002e2: return "0xe00002e2 NotPermitted"
        case 0xe00002bc: return "0xe00002bc Error"
        default: return "0x\(String(u, radix: 16))"
        }
    }

    // MARK: - raw connection

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

    /// Plain IOConnectCallMethod with NULL output params (exactly what the framework does).
    private func callRaw(_ conn: io_connect_t, _ sel: UInt32,
                         _ scalars: [UInt64], _ structBytes: [UInt8]) -> kern_return_t {
        var kr: kern_return_t = -1
        var sbuf = scalars
        sbuf.withUnsafeMutableBufferPointer { sb in
            let sp = sb.baseAddress.map { UnsafeRawPointer($0).assumingMemoryBound(to: UInt64.self) }
            structBytes.withUnsafeBufferPointer { ib in
                kr = IOConnectCallMethod(conn, sel,
                                         sp, UInt32(scalars.count),
                                         ib.baseAddress, Int(structBytes.count),
                                         nil, nil,
                                         nil, nil)
            }
        }
        return kr
    }

    private func words(_ w: [UInt64], _ size: Int) -> [UInt8] {
        var sb = [UInt8](repeating: 0, count: size)
        for i in 0..<min(w.count, size / 8) {
            withUnsafeBytes(of: w[i].littleEndian) { wb in
                for j in 0..<8 { sb[i * 8 + j] = wb[j] }
            }
        }
        return sb
    }

    // MARK: - probe

    private func probe() {
        emit("\n=== service name candidates ===")
        for name in ["IOSurfaceRoot", "IOSurfaceGlobalRoot", "IOSurfaceRemoteClient",
                     "IOSurfaceAccelerator", "IOSurfaceRootUserClient"] {
            let matching = IOServiceMatching(name)
            var iter: io_iterator_t = 0
            let kr = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iter)
            var n = 0
            if kr == KERN_SUCCESS {
                while true {
                    let s = IOIteratorNext(iter)
                    if s == 0 { break }
                    n += 1
                    IOObjectRelease(s)
                }
                IOObjectRelease(iter)
            }
            emit("  \(name): kr=0x\(String(UInt32(bitPattern: kr), radix: 16)) count=\(n)")
        }

        emit("\n=== framework baseline ===")
        guard let s = makeSurface() else { emit("[NO] create failed"); return }
        let sid = UInt64(gGetID!(s))
        emit("  surface id 0x\(String(sid, radix: 16)) port 0x\(String(gPort, radix: 16))")
        emit("  framework set -> \(krstr(gSet!(gPort, 1, sid)))")
        emit("  framework remove -> \(krstr(gRemove!(sid)))")

        let (okr, conn) = tryOpen("IOSurfaceRoot", 0)
        emit("\n=== raw connection ===")
        emit("  open IOSurfaceRoot type=0 -> \(krstr(okr))")
        guard okr == KERN_SUCCESS else { return }
        defer { IOServiceClose(conn) }

        let port = UInt64(gPort)
        let id = sid

        emit("\n=== hand-picked shapes (all outputs NULL) ===")
        struct Shape { let label: String; let sel: UInt32; let sc: [UInt64]; let st: [UInt64]; let stCnt: Int }
        let shapes: [Shape] = [
            Shape(label: "0x11 {port,1,id}", sel: 0x11, sc: [], st: [port, 1, id], stCnt: 0x18),
            Shape(label: "0x11 {port,0,id}", sel: 0x11, sc: [], st: [port, 0, id], stCnt: 0x18),
            Shape(label: "0x11 {port,id,1}", sel: 0x11, sc: [], st: [port, id, 1], stCnt: 0x18),
            Shape(label: "0x11 {port,id,0}", sel: 0x11, sc: [], st: [port, id, 0], stCnt: 0x18),
            Shape(label: "0x11 {1,id,port}", sel: 0x11, sc: [], st: [1, id, port], stCnt: 0x18),
            Shape(label: "0x11 {1,id,0}", sel: 0x11, sc: [], st: [1, id, 0], stCnt: 0x18),
            Shape(label: "0x11 {0,id,0}", sel: 0x11, sc: [], st: [0, id, 0], stCnt: 0x18),
            Shape(label: "0x11 {id,1,0}", sel: 0x11, sc: [], st: [id, 1, 0], stCnt: 0x18),
            Shape(label: "0x11 sc3 {port,1,id}", sel: 0x11, sc: [port, 1, id], st: [], stCnt: 0),
            Shape(label: "0x11 sc3 {1,id,port}", sel: 0x11, sc: [1, id, port], st: [], stCnt: 0),
            Shape(label: "0x11 sc3 {0,1,id}", sel: 0x11, sc: [0, 1, id], st: [], stCnt: 0),
            Shape(label: "0x12 {0,id,0}", sel: 0x12, sc: [], st: [0, id, 0], stCnt: 0x18),
            Shape(label: "0x12 {id,0,0}", sel: 0x12, sc: [], st: [id, 0, 0], stCnt: 0x18),
            Shape(label: "0x12 {0,0,id}", sel: 0x12, sc: [], st: [0, 0, id], stCnt: 0x18),
            Shape(label: "0x12 sc1 {id}", sel: 0x12, sc: [id], st: [], stCnt: 0),
        ]
        var hit = 0
        for sh in shapes {
            let kr = callRaw(conn, sh.sel, sh.sc, words(sh.st, sh.stCnt))
            let u = UInt32(bitPattern: kr)
            if u != 0xe00002c2 { hit += 1 }
            emit("  \(sh.label.padding(toLength: 22, withPad: " ", startingAt: 0)) -> \(krstr(kr))")
        }
        emit("  non-BadArgument: \(hit)")

        Unmanaged<AnyObject>.fromOpaque(s).release()
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v51 - raw sel 0x11/0x12 with NULL outputs ===")

        guard loadSymbols() else { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        let pkr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("  notify port 0x\(String(gPort, radix: 16)) kr=0x\(String(UInt32(bitPattern: pkr), radix: 16))")
        if pkr != KERN_SUCCESS { emit("=== failed ==="); status = "Failed"; isRunning = false; return }

        probe()
        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
