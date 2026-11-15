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
            Text("AGXProbe v55 - stale-entry home + wide sel 0x11 sweep").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v55")
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
        guard let h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY) else {
            emit("[NO] dlopen"); return false
        }
        defer { dlclose(h) }
        guard let cs = dlsym(h, "IOSurfaceCreate"), let isym = dlsym(h, "IOSurfaceGetID"),
              let ss = dlsym(h, "IOSurfaceClientSetSurfaceNotify"),
              let rs = dlsym(h, "IOSurfaceClientRemoveSurfaceNotify") else {
            emit("[NO] symbol"); return false
        }
        gCreate = unsafeBitCast(cs, to: CreateFn.self)
        gGetID = unsafeBitCast(isym, to: GetIDFn.self)
        gSet = unsafeBitCast(ss, to: SetNotifyFn.self)
        gRemove = unsafeBitCast(rs, to: RemoveNotifyFn.self)
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
        case 0xe00002c2: return "0xe00002c2 BadArgument"
        case 0xe00002c9: return "0xe00002c9 dup/InternalError"
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

    private func words(_ w: [UInt64], _ n: Int) -> [UInt8] {
        var sb = [UInt8](repeating: 0, count: n)
        for i in 0..<min(w.count, n / 8) {
            withUnsafeBytes(of: w[i].littleEndian) { wb in
                for j in 0..<8 { sb[i * 8 + j] = wb[j] }
            }
        }
        return sb
    }

    // MARK: - A: where does the stale entry live?

    private func staleHome() {
        emit("\n=== A: stale entry home ===")
        guard let a = makeSurface() else { return }
        let x = UInt64(gGetID!(a))
        emit("  A id=0x\(String(x, radix: 16)) set -> \(krstr(gSet!(gPort, 1, x)))")
        release(a)
        emit("  A released")

        guard let b = makeSurface() else { return }
        let y = UInt64(gGetID!(b))
        emit("  B id=0x\(String(y, radix: 16)) set -> \(krstr(gSet!(gPort, 1, y)))")
        emit("  set(old X=0x\(String(x, radix: 16))) -> \(krstr(gSet!(gPort, 1, x)))")
        emit("  remove(X) -> \(krstr(gRemove!(x)))")
        emit("  remove(Y) -> \(krstr(gRemove!(y)))")
        emit("  set(Y) after -> \(krstr(gSet!(gPort, 1, y)))")
        emit("  remove(Y) again -> \(krstr(gRemove!(y)))")
        release(b)
    }

    private func release(_ s: UnsafeMutableRawPointer) {
        Unmanaged<AnyObject>.fromOpaque(s).release()
    }

    // MARK: - B: wide sel 0x11 sweep on our own user client

    private func sweep() {
        emit("\n=== B: wide raw sel 0x11 sweep on our own user client ===")
        let (okr, conn) = tryOpen("IOSurfaceRoot", 0)
        emit("  open -> \(krstr(okr)) conn=\(conn)")
        guard okr == KERN_SUCCESS else { return }
        defer { IOServiceClose(conn) }

        let port = UInt64(gPort)
        let baseId: UInt64 = 0x100000

        var scalarPool: [[UInt64]] = [
            [],
            [port], [baseId], [1], [baseId, 1],
            [port, baseId], [baseId, port], [1, baseId], [baseId, 1], [port, 1], [1, port],
            [port, 1, baseId], [1, baseId, port], [0, 1, baseId], [port, baseId, 1],
            [port, baseId, 0], [1, baseId, 0], [0, baseId, 0], [baseId, 0, 0],
            [0, 0, baseId], [baseId, baseId, baseId],
            [port, 1, baseId, 0], [0, port, 1, baseId]
        ]
        var structPool: [[UInt64]] = [
            [0, baseId, 0],
            [port, 1, baseId],
            [port, baseId, 0],
            [1, baseId, 0],
            [baseId, 0, 0],
            [0, 0, baseId],
            [0, 1, baseId],
            [baseId, baseId, baseId]
        ]

        let counts = [0, 1, 2, 3, 4, 6, 8, 12, 16, 24]
        let sizes = [0, 8, 0x10, 0x18, 0x20, 0x28]

        var calls = 0
        var hits = 0
        for sc in counts {
            for stc in sizes {
                for (si, sv) in scalarPool.enumerated() {
                    // scalar count is in bytes in the SDK API; try the raw count and byte count
                    for byteMode in [false, true] {
                        guard sv.count <= max(sc, 1) || sc == 0 else { continue }
                        if sc != 0 && sv.count == 0 { continue }
                        let useCnt = byteMode ? sc : sv.count
                        if byteMode && sc == 0 { continue }
                        for (ti, tv) in structPool.enumerated() {
                            let sb = words(tv, stc)
                            var kr: kern_return_t = -1
                            sv.withUnsafeBufferPointer { ib in
                                sb.withUnsafeBufferPointer { jb in
                                    kr = IOConnectCallMethod(conn, 0x11,
                                                             ib.baseAddress.map {
                                                                UnsafeRawPointer($0).assumingMemoryBound(to: UInt64.self)
                                                             }, UInt32(useCnt),
                                                             jb.baseAddress, Int(stc),
                                                             nil, nil, nil, nil)
                                }
                            }
                            calls += 1
                            let u = UInt32(bitPattern: kr)
                            if u != 0xe00002c2 {
                                hits += 1
                                emit("  HIT sc=\(sc) scBytes=\(useCnt) st=\(stc) sIdx=\(si) tIdx=\(ti) -> \(krstr(kr))")
                                if hits > 40 { emit("  ...too many hits, stopping"); return }
                            }
                        }
                    }
                }
            }
        }
        emit("  calls=\(calls) hits=\(hits)")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v55 ===")
        guard loadSymbols() else { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        let pkr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("  notify port 0x\(String(gPort, radix: 16))")
        if pkr != KERN_SUCCESS { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        staleHome()
        sweep()
        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
