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
            Text("AGXProbe v56 - sel 0x11 shape matrix").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v56")
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

    private var gCreate: CreateFn?
    private var gGetID: GetIDFn?
    private var gPort: mach_port_t = 0

    private func loadSymbols() -> Bool {
        guard let h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY) else {
            emit("[NO] dlopen"); return false
        }
        defer { dlclose(h) }
        guard let cs = dlsym(h, "IOSurfaceCreate"), let isym = dlsym(h, "IOSurfaceGetID") else {
            emit("[NO] symbol"); return false
        }
        gCreate = unsafeBitCast(cs, to: CreateFn.self)
        gGetID = unsafeBitCast(isym, to: GetIDFn.self)
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
        case 0: return "0x0 OK"
        case 0xe00002c2: return "BadArg"
        case 0xe00002c9: return "dup"
        case 0xe00002bd: return "0x2bd"
        case 0xe00002d8: return "NotAttach"
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

    private func rawSet(_ conn: io_connect_t,
                        _ ip: UnsafePointer<UInt64>?, _ ic: UInt32,
                        _ sp: UnsafeRawPointer?, _ sc: Int,
                        _ op: UnsafeMutablePointer<UInt64>?, _ oc: UInt32?) -> kern_return_t {
        var ocv = oc ?? 0
        if let _ = oc {
            return IOConnectCallMethod(conn, 0x11, ip, ic, sp, sc, op, &ocv, nil, nil)
        }
        return IOConnectCallMethod(conn, 0x11, ip, ic, sp, sc, op, nil, nil, nil)
    }

    private func probe() {
        emit("\n=== sel 0x11 shape matrix (own user client) ===")
        let (okr, conn) = tryOpen("IOSurfaceRoot", 0)
        emit("  open -> \(krstr(okr)) conn=\(conn)")
        guard okr == KERN_SUCCESS else { return }
        defer { IOServiceClose(conn) }

        guard let s = makeSurface() else { return }
        let sid = UInt64(gGetID!(s))
        let port = UInt64(gPort)
        emit("  surface id 0x\(String(sid, radix: 16)) port 0x\(String(port, radix: 16))")

        let inCnts = [0, 8, 16, 24, 32]
        let stCnts = [0, 8, 0x10, 0x18, 0x20]
        let outModes = 3

        var scalars: [UInt64] = [port, 1, sid]
        var outs: [UInt64] = [1, sid, 0]
        var stv: [UInt64] = [0, sid, 0]

        emit("  inCnt | stCnt | outMode -> kr")
        for ic in inCnts {
            for sc in stCnts {
                for om in 0..<outModes {
                    let sb = words(stv, sc)
                    var kr: kern_return_t = -1
                    scalars.withUnsafeBufferPointer { ib in
                        outs.withUnsafeMutableBufferPointer { ob in
                            sb.withUnsafeBufferPointer { jb in
                                let ip = ib.baseAddress.map {
                                    UnsafeRawPointer($0).assumingMemoryBound(to: UInt64.self)
                                }
                                let op = (om == 0) ? nil : ob.baseAddress
                                kr = rawSet(conn, ip, UInt32(ic), jb.baseAddress, Int(sc), op,
                                            (om == 0) ? nil : (om == 1 ? 24 : 3))
                            }
                        }
                    }
                    let u = UInt32(bitPattern: kr)
                    let flag = (u == 0 || u == 0xe00002c9) ? "  <<<<<<" : ""
                    emit("  \(String(ic).padding(toLength: 5, withPad: " ", startingAt: 0)) | \(String(sc).padding(toLength: 5, withPad: " ", startingAt: 0)) | \(om) -> \(krstr(kr))\(flag)")
                }
            }
        }
        Unmanaged<AnyObject>.fromOpaque(s).release()
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v56 ===")
        guard loadSymbols() else { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        let pkr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("  notify port 0x\(String(gPort, radix: 16))")
        if pkr != KERN_SUCCESS { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        probe()
        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
