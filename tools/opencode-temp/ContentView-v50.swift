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
            Text("AGXProbe v50 - raw sel 0x11/0x12 shape sweep").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v50")
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

    private var gCreate: CreateFn?
    private var gGetID: GetIDFn?
    private var gPort: mach_port_t = 0

    private func loadSymbols() -> Bool {
        guard let handle = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY) else {
            emit("[NO] dlopen failed"); return false
        }
        defer { dlclose(handle) }
        guard let cs = dlsym(handle, "IOSurfaceCreate"),
              let isym = dlsym(handle, "IOSurfaceGetID") else {
            emit("[NO] symbol missing"); return false
        }
        gCreate = unsafeBitCast(cs, to: CreateFn.self)
        gGetID = unsafeBitCast(isym, to: GetIDFn.self)
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

    private func callRaw(_ conn: io_connect_t, _ sel: UInt32,
                         _ scalars: [UInt64], _ structBytes: [UInt8]) -> (kr: kern_return_t, outCnt: Int) {
        var out = [UInt8](repeating: 0, count: 0x40)
        var outCnt: Int = 0x40
        var kr: kern_return_t = -1
        var sbuf = scalars
        let sc = scalars.count
        sbuf.withUnsafeMutableBufferPointer { sb in
            let sp = sb.baseAddress.map { UnsafeRawPointer($0).assumingMemoryBound(to: UInt64.self) }
            structBytes.withUnsafeBufferPointer { ib in
                out.withUnsafeMutableBytes { ob in
                    kr = IOConnectCallMethod(conn, sel,
                                             sp, UInt32(sc),
                                             ib.baseAddress, Int(structBytes.count),
                                             nil, nil,
                                             ob.baseAddress, &outCnt)
                }
            }
        }
        return (kr, outCnt)
    }

    // MARK: - sweep

    private func sweep() {
        emit("\n=== raw shape sweep on IOSurfaceRoot ===")
        for (svcName, svcType) in [("IOSurfaceRoot", UInt32(0)), ("IOSurfaceRoot", UInt32(1))] {
            let (okr, conn) = tryOpen(svcName, svcType)
            emit("  open \(svcName) type=\(svcType) -> \(krstr(okr))")
            guard okr == KERN_SUCCESS else { continue }
            defer { IOServiceClose(conn) }

            guard let surf = makeSurface() else { continue }
            let sid = UInt64(gGetID!(surf))
            let port = UInt64(gPort)
            emit("  surface id 0x\(String(sid, radix: 16)) port 0x\(String(port, radix: 16))")

            var scalarSets: [[UInt64]] = [[]]
            scalarSets.append([port])
            scalarSets.append([sid])
            scalarSets.append([1])
            scalarSets.append([port, sid])
            scalarSets.append([sid, port])
            scalarSets.append([1, sid])
            scalarSets.append([sid, 1])
            scalarSets.append([port, 1, sid])
            scalarSets.append([1, sid, port])
            scalarSets.append([0, 1, sid])
            scalarSets.append([1, sid, 0])

            var structSets: [[UInt64]] = [[0, 0, 0]]
            structSets.append([1, sid, 0])
            structSets.append([0, sid, 0])
            structSets.append([port, 1, sid])
            structSets.append([port, sid, 1])
            structSets.append([sid, 1, 0])
            structSets.append([1, sid, port])
            structSets.append([sid, 0, 0])

            var hits = 0
            for sel in [UInt32(0x11), UInt32(0x12)] {
                for sc in 0...3 {
                    for stCnt in [0, 8, 0x18, 0x20] {
                        for (si, scv) in scalarSets.enumerated() {
                            if scv.count != sc { continue }
                            for (ti, stv) in structSets.enumerated() {
                                var sb = [UInt8](repeating: 0, count: stCnt)
                                if stCnt >= 8 {
                                    withUnsafeBytes(of: stv[0].littleEndian) { wb in
                                        for j in 0..<min(8, stCnt) { sb[j] = wb[j] }
                                    }
                                }
                                if stCnt >= 16 {
                                    withUnsafeBytes(of: stv[1].littleEndian) { wb in
                                        for j in 0..<min(8, stCnt - 8) { sb[8 + j] = wb[j] }
                                    }
                                }
                                if stCnt >= 24 {
                                    withUnsafeBytes(of: stv[2].littleEndian) { wb in
                                        for j in 0..<min(8, stCnt - 16) { sb[16 + j] = wb[j] }
                                    }
                                }
                                let (kr, _) = callRaw(conn, sel, scv, sb)
                                let u = UInt32(bitPattern: kr)
                                if u != 0xe00002c2 {
                                    hits += 1
                                    emit("  HIT sel=0x\(String(sel, radix: 16)) sc=\(sc) stCnt=\(stCnt) sIdx=\(si) stIdx=\(ti) -> \(krstr(kr))")
                                }
                            }
                        }
                    }
                }
            }
            emit("  non-BadArgument results: \(hits)")
            Unmanaged<AnyObject>.fromOpaque(surf).release()
        }
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v50 - raw sel 0x11/0x12 shape sweep ===")

        guard loadSymbols() else { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        let pkr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("  notify port 0x\(String(gPort, radix: 16)) kr=0x\(String(UInt32(bitPattern: pkr), radix: 16))")

        sweep()
        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
