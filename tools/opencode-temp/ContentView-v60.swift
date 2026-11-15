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
            Text("AGXProbe v59 - runtime image/export-trie resolver").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v59")
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

    // MARK: - dyld image iteration

    @_silgen_name("_dyld_image_count")
    private func dyld_image_count() -> UInt32

    @_silgen_name("_dyld_get_image_header")
    private func dyld_get_image_header(_ index: UInt32) -> UnsafeRawPointer?

    @_silgen_name("_dyld_get_image_name")
    private func dyld_get_image_name(_ index: UInt32) -> UnsafePointer<CChar>?

    // MARK: - helpers

    private func readULEB(_ p: UnsafeRawPointer, _ i: inout Int) -> UInt64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while true {
            let b = p.load(fromByteOffset: i, as: UInt8.self); i += 1
            result |= UInt64(b & 0x7f) << shift
            if (b & 0x80) == 0 { break }
            shift += 7
            if shift > 63 { break }
        }
        return result
    }

    private func cString(_ p: UnsafeRawPointer) -> String {
        var bytes: [UInt8] = []
        var i = 0
        while i < 512 {
            let b = p.load(fromByteOffset: i, as: UInt8.self)
            if b == 0 { break }
            bytes.append(b); i += 1
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// parse the export trie of one image; returns [(name, runtimeAddr)]
    private func exports(_ header: UnsafeRawPointer) -> [(String, UInt64)] {
        var out: [(String, UInt64)] = []
        let magic = header.load(as: UInt32.self)
        guard magic == 0xfeedfacf else { return out }
        let ncmds = header.load(fromByteOffset: 16, as: UInt32.self)
        guard ncmds > 0, ncmds < 4096 else { return out }
        var off = 32
        var expOff = 0, expSize = 0
        for _ in 0..<ncmds {
            guard off + 8 <= 0x100000 else { break }
            let cmd = header.load(fromByteOffset: off, as: UInt32.self)
            let cmdsize = Int(header.load(fromByteOffset: off + 4, as: UInt32.self))
            if cmdsize < 8 { break }
            if cmd == 0x80000033 { // LC_DYLD_EXPORTS_TRIE
                expOff = Int(header.load(fromByteOffset: off + 8, as: UInt32.self))
                expSize = Int(header.load(fromByteOffset: off + 12, as: UInt32.self))
            } else if cmd == 0x80000022 { // LC_DYLD_INFO_ONLY: export_off at +40
                let e = Int(header.load(fromByteOffset: off + 40, as: UInt32.self))
                let s = Int(header.load(fromByteOffset: off + 44, as: UInt32.self))
                if e != 0 && s > 0 { expOff = e; expSize = s }
            }
            off += cmdsize
        }
        guard expSize > 0, expOff > 0 else { return out }
        let trie = header.advanced(by: expOff)
        let trieEnd = expSize
        let base = UInt64(UInt(bitPattern: header))
        var total = 0

        // node layout: uleb terminalSize; [terminal data of terminalSize bytes];
        //               uleb childCount; childCount * (cstring name, uleb childOffset)
        func walk(_ nodeOff: Int, _ prefix: String, _ depth: Int) {
            if depth > 32 || total > 200_000 { return }
            guard nodeOff >= 0, nodeOff < trieEnd else { return }
            let node = trie.advanced(by: nodeOff)
            var i = 0
            let termSize = Int(readULEB(node, &i))
            var childStart = i
            if termSize > 0 {
                guard i + termSize <= trieEnd else { return }
                var j = i
                _ = readULEB(node, &j)              // flags
                let symOff = readULEB(node, &j)      // offset from image base
                let name = cString(node.advanced(by: j))
                out.append((prefix + name, base + symOff))
                total += 1
                childStart = i + termSize
            }
            var k = childStart
            let childCount = Int(readULEB(node, &k))
            guard childCount >= 0, childCount < 4096 else { return }
            var cursor = k
            for _ in 0..<childCount {
                guard cursor < trieEnd else { return }
                let childName = cString(trie.advanced(by: cursor))
                cursor += childName.utf8.count + 1
                var ci = cursor
                let childOff = Int(readULEB(trie, &ci))
                cursor = ci
                walk(childOff, prefix + childName, depth + 1)
            }
        }
        walk(0, "", 0)
        return out
    }

    /// build a sorted symbol table for the images that matter
    private func allSymbols() -> [(UInt64, String)] {
        var all: [(UInt64, String)] = []
        let wanted = ["IOKit.framework", "libsystem_kernel", "IOSurface.framework",
                      "libsystem_platform", "libsystem_c.dylib", "libsystem_trace"]
        let count = dyld_image_count()
        for i in 0..<count {
            guard let h = dyld_get_image_header(i) else { continue }
            let name = String(cString: dyld_get_image_name(i)!)
            var hit = false
            for w in wanted where name.contains(w) { hit = true }
            if !hit { continue }
            let ex = exports(h)
            emit("  [" + String(i) + "] " + name + ": " + String(ex.count) + " exports @ " + String(UInt(bitPattern: h)))
            all.append(contentsOf: ex.map { ($0.1, name + ":" + $0.0) })
        }
        all.sort { $0.0 < $1.0 }
        return all
    }

    private func resolve(_ syms: [(UInt64, String)], _ addr: UInt64) -> String {
        // find nearest symbol <= addr in the same image (image prefix before ':')
        let target = syms.first { $0.0 == addr }
        if let t = target { return t.1 }
        var lo = 0, hi = syms.count - 1, best = -1
        while lo <= hi {
            let mid = (lo + hi) / 2
            if syms[mid].0 <= addr { best = mid; lo = mid + 1 } else { hi = mid - 1 }
        }
        guard best >= 0 else { return "?" }
        let cand = syms[best]
        let img = String(cString: cand.1.split(separator: ":").first.map(String.init) ?? "?")
        return "\(cand.1) +0x\(String(addr - cand.0, radix: 16)) [img \(img)]"
    }

    private func blTargets(_ fn: UnsafeMutableRawPointer, _ len: Int) -> [(Int, UInt64)] {
        var out: [(Int, UInt64)] = []
        let base = UInt64(UInt(bitPattern: fn))
        for off in stride(from: 0, to: len, by: 4) {
            guard let p = UnsafeRawPointer(bitPattern: Int(base + UInt64(off))) else { continue }
            let insn = p.load(as: UInt32.self)
            guard (insn >> 26) == 0b100101 else { continue }
            let imm26 = Int64(insn & 0x03FFFFFF)
            let signed = (imm26 << 38) >> 38
            let target = UInt64(bitPattern: Int64(base + UInt64(off)) + 4 + (signed << 2))
            out.append((off, target))
        }
        return out
    }

    private func hexDump(_ addr: UInt64, _ n: Int, _ tag: String) {
        guard let p = UnsafeRawPointer(bitPattern: Int(addr)) else { return }
        var line = ""
        for i in 0..<n {
            line += String(format: "%02x", p.load(fromByteOffset: i, as: UInt8.self))
            if i % 16 == 15 {
                emit("  \(tag)+\(String(format: "%03x", i - 15)): \(line)")
                line = ""
            }
        }
        if !line.isEmpty { emit("  \(tag): \(line)") }
    }

    // MARK: - probe

    private func probe() {
        emit("=== images ===")
        let count = dyld_image_count()
        for i in 0..<count {
            guard let h = dyld_get_image_header(i) else { continue }
            let name = String(cString: dyld_get_image_name(i)!)
            if name.contains("IOSurface") || name.contains("IOKit") || name.contains("libsystem") {
                emit("  [\(i)] \(name) @ \(UInt(bitPattern: h))")
            }
        }

        emit("\n=== symbol table ===")
        let syms = allSymbols()
        emit("  symbols: \(syms.count)")

        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setFn = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let rmFn = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify") else {
            emit("  symbol fail"); return
        }
        let setAddr = UInt64(UInt(bitPattern: setFn))
        let rmAddr = UInt64(UInt(bitPattern: rmFn))
        emit("  IOSurfaceClientSetSurfaceNotify    @ 0x\(String(setAddr, radix: 16))  -> \(resolve(syms, setAddr))")
        emit("  IOSurfaceClientRemoveSurfaceNotify @ 0x\(String(rmAddr, radix: 16))  -> \(resolve(syms, rmAddr))")

        emit("\n=== BL targets in set notify ===")
        for (off, t) in blTargets(setFn, 0x300) {
            emit("  +0x\(String(off, radix: 16)) -> 0x\(String(t, radix: 16))   \(resolve(syms, t))")
        }
        emit("\n=== BL targets in remove notify ===")
        for (off, t) in blTargets(rmFn, 0x180) {
            emit("  +0x\(String(off, radix: 16)) -> 0x\(String(t, radix: 16))   \(resolve(syms, t))")
        }

        emit("\n=== runtime bytes: set notify (0x180) ===")
        hexDump(setAddr, 0x180, "set")
        emit("\n=== runtime bytes: remove notify (0x100) ===")
        hexDump(rmAddr, 0x100, "rm")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v59 - runtime resolver ===")
        try? await Task.sleep(nanoseconds: 3_500_000_000)
        probe()
        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
