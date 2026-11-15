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
            Text("AGXProbe v67 - swap-the-global test").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v67")
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

    private func safe_rd32(_ a: UInt64, _ ranges: [(UInt64, UInt64)]) -> UInt32? {
        guard isMapped(a, ranges), let p = UnsafeRawPointer(bitPattern: Int(a)) else { return nil }
        return p.load(as: UInt32.self)
    }

    private func safe_rd64(_ a: UInt64, _ ranges: [(UInt64, UInt64)]) -> UInt64? {
        guard isMapped(a, ranges), let p = UnsafeRawPointer(bitPattern: Int(a)) else { return nil }
        return p.load(as: UInt64.self)
    }

    private func safe_rd_insn(_ a: UInt64, _ ranges: [(UInt64, UInt64)]) -> UInt32? {
        // Instruction fetch: must be 4-byte aligned and mapped
        guard a % 4 == 0, isMapped(a, ranges), isMapped(a + 3, ranges),
              let p = UnsafeRawPointer(bitPattern: Int(a)) else { return nil }
        return p.load(as: UInt32.self)
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

        emit("\n=== adrp+ldr scan (first 0x1000 bytes) ===")
        var candidates: [(target: UInt64, note: String)] = []
        var i: UInt64 = 0
        while i < 0x1000 {
            guard let insn = safe_rd_insn(ciAddr + i, ranges) else { i += 4; continue }
            let pc = ciAddr + i
            if let page = adrpPage(insn, pc: pc) {
                let rd = (insn & 0x1F)
                guard let insn2 = safe_rd_insn(ciAddr + i + 4, ranges) else { i += 4; continue }
                let isLdr64 = (insn2 & 0xFFC00000) == 0xF9400000
                let isLdr32 = (insn2 & 0xFFC00000) == 0xB9400000
                let rn = (insn2 >> 5) & 0x1F
                if (isLdr64 || isLdr32) && rn == rd {
                    let imm12 = UInt64((insn2 >> 10) & 0xFFF) << (isLdr64 ? 3 : 2)
                    let target = page &+ imm12
                    var note = ""
                    if let v64 = safe_rd64(target, ranges), v64 == UInt64(fwConn) {
                        note = "  <== MATCHES conn (64)"
                    }
                    if isLdr64 {
                        if let v64 = safe_rd64(target, ranges),
                           let v32 = safe_rd32(v64, ranges), v32 == UInt32(bitPattern: fwConn) {
                            note = "  <== POINTER to conn (64->32)"
                        }
                    }
                    if let v32 = safe_rd32(target, ranges), v32 == UInt32(bitPattern: fwConn) {
                        note = "  <== MATCHES conn (32)"
                    }
                    emit("  +" + String(format: "%03x", i) + " adrp -> " + hex(page) + " ldr " + (isLdr64 ? "x" : "w") + " #" + hex(imm12) + " = " + hex(target) + note)
                    if !note.isEmpty { candidates.append((target, note)) }
                }
            }
            i += 4
        }
        if candidates.isEmpty { emit("  (no candidate matched conn)") }

        emit("\n=== scanning data section for conn value ===")
        // Scan __DATA segment of IOSurface.framework for the conn pointer value
        for img in 0..<_dyld_image_count() {
            guard let h = _dyld_get_image_header(img) else { continue }
            let hdr = UnsafeRawPointer(h)
            let magic = hdr.load(as: UInt32.self)
            guard magic == 0xfeedfacf else { continue }
            let path = String(cString: _dyld_get_image_name(img))
            guard path.contains("IOSurface") else { continue }
            let ncmds = hdr.load(fromByteOffset: 16, as: UInt32.self)
            var off = 32
            var base: UInt64 = 0
            var textVm: UInt64 = 0
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
                    if name == "__DATA" { base = vmaddr }
                }
                off += cmdsize
            }
            let slide = UInt64(UInt(bitPattern: h)) &- textVm
            let dataBase = slide &+ base
            emit("  IOSurface __DATA base: " + hex(dataBase))
            // Scan first 4096 bytes of __DATA for conn value
            var dataOff: UInt64 = 0
            while dataOff < 0x1000 {
                if let v = safe_rd64(dataBase + dataOff, ranges), v == UInt64(fwConn) {
                    emit("  <== FOUND conn at DATA+" + String(format: "%03x", dataOff) + " = " + hex(dataBase + dataOff))
                }
                dataOff += 8
            }
        }

        emit("\n=== done ===")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v67 ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        probe()
        status = "Complete"; isRunning = false
    }
}
