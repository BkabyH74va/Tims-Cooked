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
            Text("AGXProbe v69 - verify global + IOCoreSurfaceRoot census").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v69")
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

    typealias ConnectInternalFn = @convention(c) (UInt8) -> io_connect_t

    private func hex(_ v: UInt64) -> String { "0x" + String(v, radix: 16) }

    // MARK: - mach-o segment map

    private func mappedRanges() -> [(UInt64, UInt64)] {
        var out: [(UInt64, UInt64)] = []
        let n = _dyld_image_count()
        for i in 0..<n {
            guard let h = _dyld_get_image_header(i) else { continue }
            let hdr = UnsafeRawPointer(h)
            let magic = hdr.load(as: UInt32.self)
            guard magic == 0xfeedfacf else { continue }
            let ncmds = hdr.load(fromByteOffset: 16, as: UInt32.self)
            guard ncmds > 0, ncmds < 4096 else { continue }
            var off = 32
            var textVm: UInt64 = 0
            var segs: [(UInt64, UInt64)] = []
            for _ in 0..<ncmds {
                guard off + 8 <= 0x100000 else { break }
                let cmd = hdr.load(fromByteOffset: off, as: UInt32.self)
                let cmdsize = Int(hdr.load(fromByteOffset: off + 4, as: UInt32.self))
                if cmdsize < 8 { break }
                if cmd == 0x19 {
                    let name = String(cString: (hdr + off + 8).assumingMemoryBound(to: CChar.self))
                    let vmaddr = (hdr + off + 24).load(as: UInt64.self)
                    let vmsize = (hdr + off + 32).load(as: UInt64.self)
                    if name == "__TEXT" { textVm = vmaddr }
                    if vmsize > 0 { segs.append((vmaddr, vmsize)) }
                }
                off += cmdsize
            }
            let base = UInt64(UInt(bitPattern: h))
            let slide = base &- textVm
            for (va, vs) in segs {
                out.append((slide &+ va, vs))
            }
        }
        return out
    }

    private func isMapped(_ a: UInt64, _ ranges: [(UInt64, UInt64)]) -> Bool {
        for (s, n) in ranges where a >= s && a < s &+ n { return true }
        return false
    }

    private func safe_rd64(_ a: UInt64, _ ranges: [(UInt64, UInt64)]) -> UInt64? {
        guard isMapped(a, ranges), isMapped(a + 7, ranges),
              let p = UnsafeRawPointer(bitPattern: Int(a)) else { return nil }
        return p.load(as: UInt64.self)
    }

    private func safe_rd32(_ a: UInt64, _ ranges: [(UInt64, UInt64)]) -> UInt32? {
        guard isMapped(a, ranges), isMapped(a + 3, ranges),
              let p = UnsafeRawPointer(bitPattern: Int(a)) else { return nil }
        return p.load(as: UInt32.self)
    }

    // MARK: - probe

    private func probe() {
        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let ciSym = dlsym(fwH, "_ioSurfaceConnectInternal") else {
            emit("symbol fail"); return
        }
        let connectInternal = unsafeBitCast(ciSym, to: ConnectInternalFn.self)

        let ranges = mappedRanges()
        emit("mapped ranges: " + String(ranges.count))

        // Find __DATA_DIRTY base for IOSurface
        var dataDirtyBase: UInt64 = 0
        var textVm: UInt64 = 0
        for img in 0..<_dyld_image_count() {
            guard let h = _dyld_get_image_header(img) else { continue }
            let hdr = UnsafeRawPointer(h)
            let magic = hdr.load(as: UInt32.self)
            guard magic == 0xfeedfacf else { continue }
            let path = String(cString: _dyld_get_image_name(img))
            guard path.contains("IOSurface") else { continue }
            let ncmds = hdr.load(fromByteOffset: 16, as: UInt32.self)
            var off = 32
            for _ in 0..<ncmds {
                guard off + 8 <= 0x100000 else { break }
                let cmd = hdr.load(fromByteOffset: off, as: UInt32.self)
                let cmdsize = Int(hdr.load(fromByteOffset: off + 4, as: UInt32.self))
                if cmdsize < 8 { break }
                if cmd == 0x19 {
                    let name = String(cString: (hdr + off + 8).assumingMemoryBound(to: CChar.self))
                    let vmaddr = (hdr + off + 24).load(as: UInt64.self)
                    let vmsize = (hdr + off + 32).load(as: UInt64.self)
                    if name == "__TEXT" { textVm = vmaddr }
                    if name == "__DATA_DIRTY" {
                        dataDirtyBase = UInt64(UInt(bitPattern: h)) &- textVm &+ vmaddr
                        emit("IOSurface __DATA_DIRTY @ " + hex(dataDirtyBase) + " size=" + hex(vmsize))
                    }
                }
                off += cmdsize
            }
        }

        // === verify global stability ===
        emit("\n=== verify connection global stability ===")
        let connAddr = dataDirtyBase + 360
        emit("connection global addr: " + hex(connAddr))

        let conn1 = connectInternal(0)
        emit("call 1: conn = " + String(conn1) + " (" + hex(UInt64(conn1)) + ")")

        if let stored1 = safe_rd64(connAddr, ranges) {
            emit("global after call 1: " + hex(stored1) + " match=" + String(stored1 == UInt64(conn1)))
        }

        let conn2 = connectInternal(0)
        emit("call 2: conn = " + String(conn2) + " (" + hex(UInt64(conn2)) + ")")

        if let stored2 = safe_rd64(connAddr, ranges) {
            emit("global after call 2: " + hex(stored2) + " match=" + String(stored2 == UInt64(conn2)))
        }

        if let stored1 = safe_rd64(connAddr, ranges) {
            emit("global re-read: " + hex(stored1))
        }

        // === IOCoreSurfaceRoot census ===
        emit("\n=== IOCoreSurfaceRoot service census ===")
        let names = ["IOCoreSurfaceRoot", "IOSurfaceRoot", "IOSurfaceRootUserClient"]
        for n in names {
            guard let m = IOServiceMatching(n) else { emit("  " + n + ": matching failed"); continue }
            var iter: io_iterator_t = 0
            let kr = IOServiceGetMatchingServices(kIOMainPortDefault, m, &iter)
            if kr != KERN_SUCCESS { emit("  " + n + ": getMatchingServices -> " + String(kr)); continue }
            var count = 0
            var firstConn: io_connect_t = 0
            var firstOpen: kern_return_t = -1
            while true {
                let svc = IOIteratorNext(iter)
                if svc == 0 { break }
                count += 1
                var buf = [CChar](repeating: 0, count: 128)
                let nkr = buf.withUnsafeMutableBufferPointer { bp in
                    IORegistryEntryGetName(svc, bp.baseAddress!)
                }
                let nm = (nkr == KERN_SUCCESS) ? String(cString: buf) : "<noname>"
                var conn: io_connect_t = 0
                let okr = IOServiceOpen(svc, mach_task_self_, 0, &conn)
                if count == 1 { firstConn = conn; firstOpen = okr }
                emit("  " + n + " [" + String(count) + "] name='" + nm + "' open->" + String(UInt32(bitPattern: okr)) + " conn=" + String(conn))
                if conn != 0 { IOServiceClose(conn) }
                IOObjectRelease(svc)
            }
            IOObjectRelease(iter)
            emit("  " + n + ": count=" + String(count) + " firstOpen=" + String(UInt32(bitPattern: firstOpen)))
        }

        emit("\n=== done ===")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v69 ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        probe()
        status = "Complete"; isRunning = false
    }
}
