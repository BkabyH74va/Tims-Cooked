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
            Text("AGXProbe v65 - resolve stub -> real function").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v65")
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

    /// resolve a lazy-binding stub: adrp x16, page ; add x16, x16, #imm ; br x16
    private func stubTarget(_ stub: UInt64) -> UInt64? {
        guard let p = UnsafeRawPointer(bitPattern: Int(stub)) else { return nil }
        let i0 = p.load(as: UInt32.self)
        let i1 = p.load(fromByteOffset: 4, as: UInt32.self)
        // ADRP: 1 immlo(2) 10000 immhi(19) Rd(5)
        guard (i0 & 0x9F000000) == 0x90000000 else { return nil }
        let immlo = (i0 >> 29) & 3
        let immhi = (i0 >> 5) & 0x7FFFF
        var v = Int64((immhi << 2) | immlo)
        if v & 0x100000 != 0 { v -= 0x200000 }   // sign-extend 21-bit page offset
        let imm = v << 12
        let page = (Int64(stub) & ~0xFFF) + imm
        // ADD (immediate): 1001 0001 0 0 0 sh imm12 Rn Rd
        guard (i1 & 0xFFC00000) == 0x91000000 else { return nil }
        let imm12 = Int64((i1 >> 10) & 0xFFF)
        let sh = (i1 >> 22) & 3
        let add = imm12 << (sh == 1 ? 12 : 0)
        return UInt64(bitPattern: page + add)
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
        guard let setStub = blTarget(setFn, 0x78),
              let rmStub = blTarget(rmFn, 0x50) else {
            emit("BL fail"); return
        }
        emit("set stub    @ " + hex(setStub))
        emit("remove stub @ " + hex(rmStub))
        guard let setReal = stubTarget(setStub) else { emit("set stub resolve failed"); return }
        guard let rmReal = stubTarget(rmStub) else { emit("rm stub resolve failed"); return }
        emit("set real    @ " + hex(setReal))
        emit("remove real @ " + hex(rmReal))

        emit("\n=== bytes: set real (0x400) ===")
        hexDump(setReal, 0x400, "setr")
        emit("\n=== bytes: remove real (0x180) ===")
        hexDump(rmReal, 0x180, "rmr")
        emit("\n=== done ===")
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v65 - stub resolution ===")
        try? await Task.sleep(nanoseconds: 3_500_000_000)
        probe()
        status = "Complete"; isRunning = false
    }
}
