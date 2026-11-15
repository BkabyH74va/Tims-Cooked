#!/usr/bin/env python3
"""
AGXProbe - Argument shape probing for AGXAcceleratorG18P.
Tests different (scalarInputCount, structInputSize) combinations
to find which ones bypass the argument-shape gate.
"""

import swift
import Foundation
import IOKit

@main
struct AGXProbeApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @StateObject private var vm = ProbeViewModel()

    var body: some View {
        VStack(spacing: 16) {
            Text("AGXProbe - Arg Shape Probe")
                .font(.title)
                .fontWeight(.bold)
            Text("iPhone18,1 / V53AP / t8150 / iOS 27.0.1 (24A446)")
                .font(.subheadline).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding().background(Color.black.opacity(0.05)).cornerRadius(8)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing…" : "Run Arg Shape Probe")
                    .font(.headline).foregroundColor(.white)
                    .frame(maxWidth: .infinity).padding()
                    .background(vm.isRunning ? Color.gray : Color.blue)
                    .cornerRadius(8)
            }.disabled(vm.isRunning).padding(.top)
            Text("Status: \(vm.status)").font(.caption).foregroundColor(.secondary)
            Spacer()
        }.padding()
    }
}

@MainActor
class ProbeViewModel: ObservableObject {
    @Published var log = ""
    @Published var status = "Ready"
    @Published var isRunning = false

    private func log(_ m: String) {
        let ts = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        self.log += "[\(ts)] \(m)\n"
    }

    func runProbe() async {
        isRunning = true
        status = "Opening AGXAcceleratorG18P…"
        log("=== AGXProbe Arg Shape Probe ===")

        let matching = IOServiceMatching("AGXAcceleratorG18P")
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        if service == IO_OBJECT_NULL {
            log("FAILED: IOServiceGetMatchingService returned NULL")
            isRunning = false; status = "Service not found"; return
        }
        log("Service found: AGXAcceleratorG18P")

        var connect: io_connect_t = 0
        let openKr = IOServiceOpen(service, mach_task_self(), 1, &connect)
        IOObjectRelease(service)
        if openKr != KERN_SUCCESS {
            log("FAILED: IOServiceOpen(type=1) failed: \(openKr) (0x\(String(openKr, radix: 16)))")
            isRunning = false; status = "IOServiceOpen failed"; return
        }
        log("IOServiceOpen(type=1) ok, connect=0x\(String(connect, radix: 16))")

        // Test selectors and argument shapes
        let selectors: [UInt32] = [0x100, 0x101, 0x102, 0x105, 0x110]
        let structSizes: [Int] = [0, 4, 8, 12, 16, 20, 24, 28, 32, 48, 64, 128]
        let scalarCounts: [UInt32] = [0, 1, 2, 3, 4]

        var found: [(UInt32, Int, UInt32, kern_return_t)] = []
        var tested = 0

        for sel in selectors {
            for ssize in structSizes {
                for scount in scalarCounts {
                    tested += 1

                    // Build struct input
                    var sdata: [UInt8] = Array(repeating: 0, count: ssize)
                    if ssize >= 1 { sdata[0] = 0x01 }  // put something in first byte
                    if ssize >= 8 { sdata[8] = 0x02 }

                    var sdataOut: [UInt64] = Array(repeating: 0, count: 16)
                    var sdataOutCount: UInt32 = UInt32(sdataOut.count)

                    let result = IOConnectCallMethod(
                        connect, sel,
                        nil, 0,                                  // no scalar input
                        ssize > 0 ? &sdata : nil, ssize,         // struct input
                        &sdataOut, &sdataOutCount,               // scalar output
                        nil, nil                                 // no struct output
                    )

                    if result != KERN_SUCCESS {
                        if result != 0xe00002c2 {  // not kIOReturnBadArgument
                            found.append((sel, ssize, scount, result))
                            log("  sel=0x\(String(sel, radix:16)) ssize=\(ssize) scount=\(scount) kr=\(result) (0x\(String(result, radix:16))) OUT=\(sdataOutCount)")
                        }
                    } else {
                        found.append((sel, ssize, scount, result))
                        log("  sel=0x\(String(sel, radix:16)) ssize=\(ssize) scount=\(scount) kr=KERN_SUCCESS OUT=\(sdataOutCount)")
                    }
                }
            }
        }

        IOConnectClose(connect)
        log("\n=== Probe Complete ===")
        log("Tested \(tested) combinations, \(found.count) non-KERN_SUCCESS results")
        for (sel, ssize, scount, kr) in found {
            log("  sel=0x\(String(sel, radix:16)) ssize=\(ssize) scount=\(scount) kr=\(kr) (0x\(String(kr, radix:16)))")
        }
        status = "Complete — \(found.count) non-KS results out of \(tested)"
        isRunning = false
    }
}