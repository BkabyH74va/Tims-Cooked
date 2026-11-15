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
            Text("AGXProbe v68 - data section scan").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v68")
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
                if cmd == 0x19 { // LC_SEGMENT_64
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

        let fwConn = connectInternal(0)
        emit("_ioSurfaceConnectInternal(0) -> conn " + String(fwConn) + " (" + hex(UInt64(fwConn)) + ")")

        let ciAddr = UInt64(UInt(bitPattern: ciSym))
        emit("_ioSurfaceConnectInternal @ " + hex(ciAddr))

        emit("\n=== scanning all IOSurface segments for conn value ===")
        var foundCount = 0
        for img in 0..<_dyld_image_count() {
            guard let h = _dyld_get_image_header(img) else { continue }
            let hdr = UnsafeRawPointer(h)
            let magic = hdr.load(as: UInt32.self)
            guard magic == 0xfeedfacf else { continue }
            let path = String(cString: _dyld_get_image_name(img))
            guard path.contains("IOSurface") else { continue }

            let ncmds = hdr.load(fromByteOffset: 16, as: UInt32.self)
            var off = 32
            var textVm: UInt64 = 0
            var segs: [(name: String, va: UInt64, vs: UInt64)] = []
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
                    segs.append((name, vmaddr, vmsize))
                }
                off += cmdsize
            }
            let slide = UInt64(UInt(bitPattern: h)) &- textVm

            for seg in segs {
                let va = slide &+ seg.va
                emit("  " + seg.name + " @ " + hex(va) + " size=" + hex(seg.vs))
                var o: UInt64 = 0
                while o < seg.vs {
                    if let v = safe_rd64(va + o, ranges), v == UInt64(fwConn) {
                        emit("  <== FOUND conn at " + seg.name + "+" + String(format: "%03x", o) + " = " + hex(va + o))
                        foundCount += 1
                    }
                    o += 8
                }
            }
        }
        emit("  total conn matches: " + String(foundCount))

        emit("\n=== done ===")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v68 ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        probe()
        status = "Complete"; isRunning = false
    }
}
