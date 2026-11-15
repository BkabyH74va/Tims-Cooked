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
            Text("AGXProbe v61 - runtime BL scan + dladdr resolver").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v61")
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

    // MARK: - helpers

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

    /// resolve an address to the nearest exported symbol using dladdr
    private func describe(_ addr: UInt64) -> String {
        guard let p = UnsafeRawPointer(bitPattern: Int(addr)) else { return "bad-addr" }
        var info = Dl_info()
        guard dladdr(p, &info) != 0 else { return "dladdr-fail" }
        let img = info.dli_fname.map { String(cString: $0) } ?? "?"
        let sname = info.dli_sname.map { String(cString: $0) } ?? "<no-symbol>"
        let saddr = info.dli_saddr.map { UInt64(UInt(bitPattern: $0)) } ?? 0
        return sname + "  [" + img + (saddr != 0 ? " +0x" + String(addr &- saddr, radix: 16) : "") + "]"
    }

    private func hexDump(_ addr: UInt64, _ n: Int, _ tag: String) {
        guard let p = UnsafeRawPointer(bitPattern: Int(addr)) else { return }
        var line = ""
        for i in 0..<n {
            line += String(format: "%02x", p.load(fromByteOffset: i, as: UInt8.self))
            if i % 16 == 15 {
                emit("  " + tag + "+" + String(format: "%03x", i - 15) + ": " + line)
                line = ""
            }
        }
        if !line.isEmpty { emit("  " + tag + ": " + line) }
    }

    // MARK: - probe

    private func probe() {
        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setFn = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let rmFn = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify") else {
            emit("symbol fail"); return
        }
        let setAddr = UInt64(UInt(bitPattern: setFn))
        let rmAddr = UInt64(UInt(bitPattern: rmFn))
        emit("set    IOSurfaceClientSetSurfaceNotify    @ 0x" + String(setAddr, radix: 16))
        emit("remove IOSurfaceClientRemoveSurfaceNotify @ 0x" + String(rmAddr, radix: 16))

        emit("\n=== BL targets in set notify ===")
        for (off, t) in blTargets(setFn, 0x300) {
            emit("  +0x" + String(off, radix: 16) + " -> 0x" + String(t, radix: 16) + "   " + describe(t))
        }
        emit("\n=== BL targets in remove notify ===")
        for (off, t) in blTargets(rmFn, 0x180) {
            emit("  +0x" + String(off, radix: 16) + " -> 0x" + String(t, radix: 16) + "   " + describe(t))
        }

        emit("\n=== runtime bytes: set notify (0x1c0) ===")
        hexDump(setAddr, 0x1c0, "set")
        emit("\n=== runtime bytes: remove notify (0x100) ===")
        hexDump(rmAddr, 0x100, "rm")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v61 - BL scan + dladdr ===")
        try? await Task.sleep(nanoseconds: 3_500_000_000)
        probe()
        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
