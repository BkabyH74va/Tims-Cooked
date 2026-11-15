//
//  ContentView.swift
//  AGXProbe — geometry v3: property retention + allocation adjacency
//
//  v2 established (t8150 / 27.0.1):
//    * unknown keys are ignored (parser is lenient)
//    * 1-plane trees are accepted
//    * hdrPerSlice=0x40000000 with sliceCount=4 and alloc=0x10000 is ACCEPTED
//    * planeSize > allocSize is REJECTED
//
//  v3 asks the follow-up questions, still read-only:
//    1. Are the oversized per-slice values actually STORED on the object
//       (visible via IOSurfaceCopyValue), or silently dropped?
//    2. Where do these allocations land relative to each other? (adjacency)
//    3. Is there any upper bound at all on the per-slice fields?
//
//  SAFETY: no Metal, no GPU submission, no writes to any surface, no
//  cross-object attempt. Creation + property readback only.
//

import SwiftUI
import Darwin

@main
struct AGXProbeApp: App {
    var body: some Scene { WindowGroup { ContentView() } }
}

struct ContentView: View {
    @StateObject private var vm = GeomViewModel()
    var body: some View {
        VStack(spacing: 12) {
            Text("AGXProbe — geometry v3").font(.headline)
            Text("iPhone18,1 / t8150 / iOS 27.0.1 (24A446)")
                .font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing…" : "Run geometry probe v3")
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
final class GeomViewModel: ObservableObject {
    @Published var log = ""
    @Published var status = "Ready"
    @Published var isRunning = false

    private var didAutoRun = false
    private let PF_BGRA: UInt32 = 0x42475241

    private var logFileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("geom3.log")
    }

    private func log(_ m: String) {
        log += m + "\n"; print(m); fflush(stdout)
        try? log.write(to: logFileURL, atomically: true, encoding: .utf8)
    }

    func autoRunIfRequested() async {
        guard !didAutoRun else { return }
        didAutoRun = true
        guard ProcessInfo.processInfo.arguments.contains("--autorun") else { return }
        await runProbe()
    }

    // ------------------------------------------------------------------

    private let keysToRead = [
        "IOSurfaceSliceCount",
        "IOSurfacePlaneHeaderRegionBytesPerSlice",
        "IOSurfacePlaneDataRegionBytesPerSlice",
        "IOSurfacePlaneBytesPerRowOfTileData",
        "IOSurfacePlaneBytesPerTileData",
        "IOSurfacePlaneSize",
        "IOSurfacePlaneOffset",
        "IOSurfaceAllocSize",
        "IOSurfaceBytesPerRow",
    ]

    private func dump(_ s: IOSurfaceRef, _ tag: String) {
        let alloc = IOSurfaceGetAllocSize(s)
        let base = IOSurfaceGetBaseAddress(s)
        let id = IOSurfaceGetID(s)
        let baseStr = String(format: "0x%llx", UInt64(UInt(bitPattern: base)))
        log(String(format: "%@ id=%u base=%@ alloc=0x%lx planes=%lu",
                   tag, id, baseStr, alloc, IOSurfaceGetPlaneCount(s)))
        for k in keysToRead {
            if let v = IOSurfaceCopyValue(s, k as CFString) {
                if let n = v as? NSNumber {
                    log(String(format: "    %@ = 0x%llx", k, n.uint64Value))
                } else {
                    log("    \(k) = \(v)")
                }
            } else {
                log("    \(k) = <absent>")
            }
        }
    }

    private func make(_ d: [String: Any], _ tag: String) {
        guard let s = IOSurfaceCreate(d as CFDictionary) else {
            log("\(tag): REJECTED"); return
        }
        dump(s, tag)
    }

    private func dict(w: Int, h: Int, bpr: Int, alloc: Int,
                      planes: [[String: Any]]? = nil,
                      extra: [String: Any] = [:]) -> [String: Any] {
        var d: [String: Any] = [
            "IOSurfaceWidth": w, "IOSurfaceHeight": h,
            "IOSurfaceBytesPerElement": 4, "IOSurfaceBytesPerRow": bpr,
            "IOSurfaceAllocSize": alloc, "IOSurfacePixelFormat": PF_BGRA,
        ]
        if let p = planes { d["IOSurfacePlaneInfo"] = p }
        for (k, v) in extra { d[k] = v }
        return d
    }

    private let plane64: [String: Any] = [
        "IOSurfacePlaneWidth": 64,
        "IOSurfacePlaneHeight": 64,
        "IOSurfacePlaneBytesPerRow": 256,
        "IOSurfacePlaneBytesPerElement": 4,
        "IOSurfacePlaneOffset": 0,
        "IOSurfacePlaneSize": 0x4000,
    ]

    // ------------------------------------------------------------------

    func runProbe() async {
        isRunning = true; status = "Running…"; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)

        log("=== AGXProbe geometry v3 === build 24A446 / t8150")
        log("SAFETY: read-only; no Metal, no writes, no cross-object attempt")

        // --- F. retention: are oversized values stored? ---------------
        log("\n--- F. property retention ---")
        make(dict(w: 64, h: 64, bpr: 256, alloc: 0x4000, planes: [plane64]),
             "F1 control: 1 plane, no slice keys")
        make(dict(w: 64, h: 64, bpr: 256, alloc: 0x10000, planes: [plane64],
                  extra: ["IOSurfaceSliceCount": 4,
                          "IOSurfacePlaneHeaderRegionBytesPerSlice": NSNumber(value: UInt64(0x4000))]),
             "F2 modest: hdr=0x4000 sc=4")
        make(dict(w: 64, h: 64, bpr: 256, alloc: 0x10000, planes: [plane64],
                  extra: ["IOSurfaceSliceCount": 4,
                          "IOSurfacePlaneHeaderRegionBytesPerSlice": NSNumber(value: UInt64(0x40000000))]),
             "F3 oversized: hdr=0x40000000 sc=4, alloc=0x10000")
        make(dict(w: 64, h: 64, bpr: 256, alloc: 0x10000, planes: [plane64],
                  extra: ["IOSurfaceSliceCount": 4,
                          "IOSurfacePlaneDataRegionBytesPerSlice": NSNumber(value: UInt64(0x40000000))]),
             "F4 oversized: data=0x40000000 sc=4, alloc=0x10000")
        make(dict(w: 64, h: 64, bpr: 256, alloc: 0x10000, planes: [plane64],
                  extra: ["IOSurfaceSliceCount": 4,
                          "IOSurfacePlaneHeaderRegionBytesPerSlice": NSNumber(value: UInt64(0x40000000)),
                          "IOSurfacePlaneDataRegionBytesPerSlice": NSNumber(value: UInt64(0x40000000))]),
             "F5 oversized: hdr+data=0x40000000 each, sc=4")

        // --- G. upper bound hunt --------------------------------------
        log("\n--- G. upper bound on headerPerSlice (sc=1, alloc=0x4000) ---")
        for hv in [UInt64(0x7fffffff), UInt64(0x80000000), UInt64(0xfffffffe), UInt64(0xffffffff)] {
            make(dict(w: 64, h: 64, bpr: 256, alloc: 0x4000, planes: [plane64],
                      extra: ["IOSurfaceSliceCount": 1,
                              "IOSurfacePlaneHeaderRegionBytesPerSlice": NSNumber(value: hv)]),
                 String(format: "G hdr=0x%llx sc=1", hv))
        }

        // --- H. adjacency: where do two surfaces land? ----------------
        log("\n--- H. allocation adjacency (no writes) ---")
        var surfs: [IOSurfaceRef] = []
        for i in 0..<4 {
            let d = dict(w: 64, h: 64, bpr: 256, alloc: 0x10000, planes: [plane64],
                         extra: ["IOSurfaceSliceCount": 4,
                                 "IOSurfacePlaneHeaderRegionBytesPerSlice": NSNumber(value: UInt64(0x40000000))])
            if let s = IOSurfaceCreate(d as CFDictionary) {
                let b = IOSurfaceGetBaseAddress(s)
                log(String(format: "H%d oversized alloc=0x10000 base=0x%llx id=%u",
                           i, UInt64(UInt(bitPattern: b)), IOSurfaceGetID(s)))
                surfs.append(s)
            } else {
                log("H\(i) oversized: REJECTED")
            }
        }
        if surfs.count >= 2 {
            // Report pairwise deltas — pure arithmetic, no memory access.
            for i in 1..<surfs.count {
                let a = UInt64(UInt(bitPattern: IOSurfaceGetBaseAddress(surfs[i-1])))
                let b = UInt64(UInt(bitPattern: IOSurfaceGetBaseAddress(surfs[i])))
                log(String(format: "    delta H%d-H%d = %lld (0x%llx)",
                           i, i-1, Int64(bitPattern: b &- a), b &- a))
            }
        }
        surfs.removeAll()

        // --- I. does SliceCount alone change anything? ----------------
        log("\n--- I. SliceCount without per-slice bytes ---")
        for sc in [1, 2, 4, 16] {
            make(dict(w: 64, h: 64, bpr: 256, alloc: 0x4000, planes: [plane64],
                      extra: ["IOSurfaceSliceCount": sc]),
                 "I sc=\(sc) alloc=0x4000")
        }

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
