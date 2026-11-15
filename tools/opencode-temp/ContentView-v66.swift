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
            Text("AGXProbe v66 - cached-conn hunt + service census").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v66")
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

    // MARK: - mach-o segment map (for safe reads)

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

    private func rd32(_ a: UInt64, _ ranges: [(UInt64, UInt64)]) -> UInt32? {
        guard isMapped(a, ranges), let p = UnsafeRawPointer(bitPattern: Int(a)) else { return nil }
        return p.load(as: UInt32.self)
    }

    private func rd64(_ a: UInt64, _ ranges: [(UInt64, UInt64)]) -> UInt64? {
        guard isMapped(a, ranges), let p = UnsafeRawPointer(bitPattern: Int(a)) else { return nil }
        return p.load(as: UInt64.self)
    }

    // MARK: - adrp resolution

    private func adrpPage(_ insn: UInt32, pc: UInt64) -> UInt64? {
        guard (insn & 0x9F000000) == 0x90000000 else { return nil }
        let immlo = UInt64((insn >> 29) & 3)
        let immhi = UInt64((insn >> 5) & 0x7FFFF)
        var v = Int64((immhi << 2) | immlo)
        if v & 0x100000 != 0 { v -= 0x200000 }
        return (pc & ~0xFFF) &+ UInt64(bitPattern: v << 12)
    }

    // MARK: - probe

    private func probe() {
        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let ciSym = dlsym(fwH, "_ioSurfaceConnectInternal"),
              let cs = dlsym(fwH, "IOSurfaceCreate"),
              let isym = dlsym(fwH, "IOSurfaceGetID") else {
            emit("symbol fail"); return
        }
        typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
        typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32
        let gCreate = unsafeBitCast(cs, to: CreateFn.self)
        let gGetID = unsafeBitCast(isym, to: GetIDFn.self)
        let connectInternal = unsafeBitCast(ciSym, to: ConnectInternalFn.self)

        let ranges = mappedRanges()
        emit("mapped ranges: " + String(ranges.count))

        let fwConn = connectInternal(0)
        emit("_ioSurfaceConnectInternal(0) -> conn " + String(fwConn) + " (" + hex(UInt64(fwConn)) + ")")

        let ciAddr = UInt64(UInt(bitPattern: ciSym))
        emit("_ioSurfaceConnectInternal @ " + hex(ciAddr))

        emit("\n=== adrp+ldr candidates in _ioSurfaceConnectInternal ===")
        var candidates: [UInt64] = []
        var i = 0
        while i < 0x100 {
            guard let p = UnsafeRawPointer(bitPattern: Int(ciAddr) + i) else { break }
            let insn = p.load(as: UInt32.self)
            let pc = ciAddr + UInt64(i)
            if let page = adrpPage(insn, pc: pc) {
                let rd = (insn & 0x1F) // Rd of adrp
                let insn2 = p.load(fromByteOffset: 4, as: UInt32.self)
                // LDR (unsigned offset) 64-bit: 1111 1001 01 imm12 Rn Rt
                let isLdr64 = (insn2 & 0xFFC00000) == 0xF9400000
                let isLdr32 = (insn2 & 0xFFC00000) == 0xB9400000
                let rn = (insn2 >> 5) & 0x1F
                if (isLdr64 || isLdr32) && rn == rd {
                    let imm12 = UInt64((insn2 >> 10) & 0xFFF) << (isLdr64 ? 3 : 2)
                    let target = page &+ imm12
                    var note = ""
                    if let v64 = rd64(target, ranges) {
                        if v64 == UInt64(fwConn) { note = "  <== MATCHES conn (64)" }
                        if isLdr64 {
                            if let v32 = rd32(v64, ranges), v32 == fwConn {
                                note = "  <== POINTER to conn (64->32)"
                            }
                        }
                    }
                    if let v32 = rd32(target, ranges), v32 == fwConn {
                        note = "  <== MATCHES conn (32)"
                    }
                    emit("  +" + String(format: "%03x", i) + " adrp -> " + hex(page) + " ldr " + (isLdr64 ? "x" : "w") + " #" + hex(imm12) + " = target " + hex(target) + note)
                    if !note.isEmpty { candidates.append(target) }
                }
            }
            i += 4
        }
        if candidates.isEmpty { emit("  (no candidate matched)") }

        // --- service census (correct name reading) ---
        emit("\n=== service census ===")
        let names = ["IOSurfaceRoot", "IOCoreSurfaceRoot", "IOSurfaceGlobalRoot",
                     "IOSurfaceRootUserClient", "IOSurfaceClient", "IOSurfaceRemoteClient",
                     "IOSurfaceAccelerator"]
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

        // --- surface sanity ---
        let props: [String: Any] = ["IOSurfaceWidth": 64, "IOSurfaceHeight": 64, "IOSurfaceBytesPerElement": 4]
        if let surf = gCreate(props as CFDictionary) {
            emit("\nsurface id = " + hex(UInt64(gGetID(surf))))
            Unmanaged<AnyObject>.fromOpaque(surf).release()
        } else {
            emit("\nsurface create failed")
        }

        emit("\n=== done ===")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v66 ===")
        try? await Task.sleep(nanoseconds: 3_500_000_000)
        probe()
        status = "Complete"; isRunning = false
    }
}
