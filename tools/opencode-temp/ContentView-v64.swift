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
            Text("AGXProbe v64 - dump raw callees").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v64")
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

    private func hex(_ v: UInt64) -> String { "0x" + String(v, radix: 16) }

    private func blTarget(_ fn: UnsafeMutableRawPointer, _ off: Int) -> UInt64? {
        let fnAddr = Int(UInt(bitPattern: fn))
        guard let p = UnsafeRawPointer(bitPattern: fnAddr + off) else { return nil }
        let insn = p.load(as: UInt32.self)
        guard (insn >> 26) == 0b100101 else { return nil }
        let imm26 = Int64(insn & 0x03FFFFFF)
        let signed = (imm26 << 38) >> 38
        return UInt64(bitPattern: Int64(fnAddr + off) + (signed << 2))
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

    private func probe() {
        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setFn = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let rmFn = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify") else {
            emit("symbol fail"); return
        }
        guard let setCallee = blTarget(setFn, 0x78),
              let rmCallee = blTarget(rmFn, 0x50) else {
            emit("BL fail"); return
        }
        emit("set    fn @ " + hex(UInt64(UInt(bitPattern: setFn))) + "  callee @ " + hex(setCallee))
        emit("remove fn @ " + hex(UInt64(UInt(bitPattern: rmFn))) + "  callee @ " + hex(rmCallee))

        emit("\n=== bytes: set callee (0x240) ===")
        hexDump(setCallee, 0x240, "setc")
        emit("\n=== bytes: remove callee (0x100) ===")
        hexDump(rmCallee, 0x100, "rmc")
        emit("\n=== done ===")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v64 - dump callees ===")
        try? await Task.sleep(nanoseconds: 3_500_000_000)
        probe()
        status = "Complete"; isRunning = false
    }
}
