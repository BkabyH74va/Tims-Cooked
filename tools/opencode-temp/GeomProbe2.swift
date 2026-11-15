//
//  ContentView.swift
//  AGXProbe — IOSurface geometry probe v2 (read-only)
//
//  v1 result (2026-11-08):
//    plain surfaces            -> ACCEPTED
//    ANY dict with PlaneInfo   -> REJECTED (including a benign 1-plane dict)
//    ANY dict with SliceCount  -> REJECTED
//  => v1 could not distinguish "malformed dictionary" from "geometry refused".
//
//  v2 therefore first establishes a *known-valid* baseline and measures how
//  strict the parser is, before sweeping the F1 knobs on top of a valid tree.
//
//  SAFETY: read-only. No Metal, no GPU submission, no writes to any surface,
//  no cross-object attempt. Surfaces are created, inspected, released.
//

import SwiftUI
import Darwin

@main
struct AGXProbeApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

struct ContentView: View {
    @StateObject private var vm = GeomViewModel()

    var body: some View {
        VStack(spacing: 12) {
            Text("AGXProbe — geometry v2").font(.headline)
            Text("iPhone18,1 / t8150 / iOS 27.0.1 (24A446)")
                .font(.caption2).foregroundColor(.secondary)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                    .background(Color.black.opacity(0.85))
                    .cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing…" : "Run geometry probe v2")
                    .font(.headline).foregroundColor(.white)
                    .frame(maxWidth: .infinity).padding(10)
                    .background(vm.isRunning ? Color.gray : Color.blue)
                    .cornerRadius(8)
            }
            .disabled(vm.isRunning)
            Text("Status: \(vm.status)").font(.caption2).foregroundColor(.secondary)
            Spacer(minLength: 0)
        }
        .padding()
        .task { await vm.autoRunIfRequested() }
    }
}

@MainActor
final class GeomViewModel: ObservableObject {
    @Published var log = ""
    @Published var status = "Ready"
    @Published var isRunning = false

    private var didAutoRun = false
    private let PF_BGRA: UInt32 = 0x42475241  // 'BGRA'

    private var logFileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("geom2.log")
    }

    private func log(_ m: String) {
        log += m + "\n"
        print(m); fflush(stdout)
        try? log.write(to: logFileURL, atomically: true, encoding: .utf8)
    }

    func autoRunIfRequested() async {
        guard !didAutoRun else { return }
        didAutoRun = true
        guard ProcessInfo.processInfo.arguments.contains("--autorun") else { return }
        await runProbe()
    }

    // ------------------------------------------------------------------
    // Core attempt helper — the ONLY place a surface is created.
    // ------------------------------------------------------------------

    private func attempt(_ tag: String, _ d: [String: Any], verbose: Bool = true) {
        guard let s = IOSurfaceCreate(d as CFDictionary) else {
            log("\(tag): REJECTED")
            return
        }
        let base = IOSurfaceGetBaseAddress(s)
        let alloc = IOSurfaceGetAllocSize(s)
        let bpr = IOSurfaceGetBytesPerRow(s)
        let h = IOSurfaceGetHeight(s)
        let w = IOSurfaceGetWidth(s)
        let pf = IOSurfaceGetPixelFormat(s)
        let planes = IOSurfaceGetPlaneCount(s)
        let baseStr = String(format: "0x%llx", UInt64(UInt(bitPattern: base)))
        log(String(format: "%@: OK base=%@ alloc=0x%lx bpr=%lu %lux%lu pf=0x%08x planes=%lu",
                   tag, baseStr, alloc, bpr, w, h, pf, planes))
        if verbose && planes > 0 {
            for i in 0..<planes {
                let pw = IOSurfaceGetWidthOfPlane(s, i)
                let ph = IOSurfaceGetHeightOfPlane(s, i)
                let pbpr = IOSurfaceGetBytesPerRowOfPlane(s, i)
                let pbpe = IOSurfaceGetBytesPerElementOfPlane(s, i)
                let pbase = IOSurfaceGetBaseAddressOfPlane(s, i)
                let pbs = String(format: "0x%llx", UInt64(UInt(bitPattern: pbase)))
                log(String(format: "    plane[%lu] base=%@ %lux%lu bpr=%lu bpe=%lu",
                           i, pbs, pw, ph, pbpr, pbpe))
            }
        }
        if verbose { readBack(s, "IOSurfaceSliceCount", "    sliceCount") }
    }

    private func readBack(_ s: IOSurfaceRef, _ key: String, _ label: String) {
        if let v = IOSurfaceCopyValue(s, key as CFString) {
            if let n = v as? NSNumber {
                log(String(format: "%@ = 0x%llx (%llu)", label, n.uint64Value, n.uint64Value))
            } else {
                log("\(label) = \(v)")
            }
        }
    }

    private func dict(w: Int, h: Int, bpr: Int, alloc: Int,
                      planes: [[String: Any]]? = nil,
                      extra: [String: Any] = [:]) -> [String: Any] {
        var d: [String: Any] = [
            "IOSurfaceWidth": w,
            "IOSurfaceHeight": h,
            "IOSurfaceBytesPerElement": 4,
            "IOSurfaceBytesPerRow": bpr,
            "IOSurfaceAllocSize": alloc,
            "IOSurfacePixelFormat": PF_BGRA,
        ]
        if let p = planes { d["IOSurfacePlaneInfo"] = p }
        for (k, v) in extra { d[k] = v }
        return d
    }

    private func plane(w: Int, h: Int, bpr: Int, offset: Int, size: Int) -> [String: Any] {
        [
            "IOSurfacePlaneWidth": w,
            "IOSurfacePlaneHeight": h,
            "IOSurfacePlaneBytesPerRow": bpr,
            "IOSurfacePlaneBytesPerElement": 4,
            "IOSurfacePlaneOffset": offset,
            "IOSurfacePlaneSize": size,
        ]
    }

    // ------------------------------------------------------------------
    // Probe
    // ------------------------------------------------------------------

    func runProbe() async {
        isRunning = true; status = "Running…"; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)

        log("=== AGXProbe geometry v2 === build 24A446 / t8150")
        log("SAFETY: read-only; no Metal, no writes, no cross-object attempt")

        // --- A. parser strictness -------------------------------------
        log("\n--- A. parser strictness ---")
        attempt("A1 plain 64x64", dict(w: 64, h: 64, bpr: 256, alloc: 0x4000))
        attempt("A2 plain + unknown key", dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                                              extra: ["IOSurfaceTotallyUnknownKey": 1]))
        attempt("A3 plain + SliceCount=1", dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                                                extra: ["IOSurfaceSliceCount": 1]))
        attempt("A4 plain + SliceCount=4", dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                                                extra: ["IOSurfaceSliceCount": 4]))
        attempt("A5 plain + junk string key", dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                                                   extra: ["IOSurfaceBogus": "hello"]))

        // --- B. minimal valid plane trees ------------------------------
        log("\n--- B. minimal plane trees ---")
        // B1: canonical single plane, offset 0, size == bpr*h, alloc == size.
        attempt("B1 1 plane 64x64 off=0 size=0x4000",
                dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000)]))
        // B2: omit PlaneOffset/PlaneSize — let the kernel derive them.
        var p2 = plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000)
        p2.removeValue(forKey: "IOSurfacePlaneOffset")
        p2.removeValue(forKey: "IOSurfacePlaneSize")
        attempt("B2 1 plane, offset/size omitted",
                dict(w: 64, h: 64, bpr: 256, alloc: 0x4000, planes: [p2]))
        // B3: two planes back to back.
        attempt("B3 2 planes 64x64 @0/0x4000",
                dict(w: 128, h: 64, bpr: 256, alloc: 0x8000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000),
                              plane(w: 64, h: 64, bpr: 256, offset: 0x4000, size: 0x4000)]))
        // B4: single plane + SliceCount=1 (consistent).
        attempt("B4 1 plane + SliceCount=1",
                dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000)],
                     extra: ["IOSurfaceSliceCount": 1]))
        // B5: single plane + SliceCount=4, alloc == 4*planeSize.
        attempt("B5 1 plane + SliceCount=4 alloc=0x10000",
                dict(w: 64, h: 64, bpr: 256, alloc: 0x10000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000)],
                     extra: ["IOSurfaceSliceCount": 4]))

        // --- C. F1 knobs on the smallest accepted tree -----------------
        log("\n--- C. per-slice region keys on a 1-plane tree ---")
        let basePlane = [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000)]
        let hdrVals: [UInt64] = [0, 0x1000, 0x4000, 0x10000, 0x100000, 0x1000000]
        for hv in hdrVals {
            attempt(String(format: "C hdr=0x%llx sc=1 alloc=0x%llx", hv, 0x4000 + hv),
                    dict(w: 64, h: 64, bpr: 256,
                         alloc: Int(0x4000 + hv),
                         planes: basePlane,
                         extra: ["IOSurfaceSliceCount": 1,
                                 "IOSurfacePlaneHeaderRegionBytesPerSlice": NSNumber(value: hv)]),
                    verbose: false)
        }
        for hv in hdrVals {
            attempt(String(format: "C hdr=0x%llx sc=4 alloc=4*(0x4000+hdr)", hv),
                    dict(w: 64, h: 64, bpr: 256,
                         alloc: Int(4 * (0x4000 + hv)),
                         planes: basePlane,
                         extra: ["IOSurfaceSliceCount": 4,
                                 "IOSurfacePlaneHeaderRegionBytesPerSlice": NSNumber(value: hv)]),
                    verbose: false)
        }
        // dataPerSlice on its own.
        for dv in [0x1000, 0x4000, 0x10000] as [UInt64] {
            attempt(String(format: "C data=0x%llx sc=4", dv),
                    dict(w: 64, h: 64, bpr: 256,
                         alloc: Int(4 * (0x4000 + dv)),
                         planes: basePlane,
                         extra: ["IOSurfaceSliceCount": 4,
                                 "IOSurfacePlaneDataRegionBytesPerSlice": NSNumber(value: dv)]),
                    verbose: false)
        }
        // tile fields on valid tree.
        for tr in [0x100, 0x200, 0x400] {
            attempt(String(format: "C tileRow=0x%x", tr),
                    dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                         planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000)],
                         extra: ["IOSurfacePlaneBytesPerRowOfTileData": tr]),
                    verbose: false)
        }
        for td in [0x400, 0x800, 0x1000] {
            attempt(String(format: "C tileData=0x%x", td),
                    dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                         planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000)],
                         extra: ["IOSurfacePlaneBytesPerTileData": td]),
                    verbose: false)
        }

        // --- D. arithmetic-consistency questions ----------------------
        // These ask the kernel a pure question: is the per-slice product
        // validated, or is each field validated in isolation? Nothing is
        // written to any surface; if the kernel accepts a small allocation
        // for a huge declared region, that fact is recorded and the surface
        // is released immediately.
        log("\n--- D. arithmetic consistency (no writes) ---")
        for (hv, sc) in [(UInt64(0x40000000), 4), (UInt64(0x40000000), 2), (UInt64(0x7fffffff), 4)] {
            attempt(String(format: "D hdr=0x%llx sc=%d alloc=0x10000 (deliberately short)", hv, sc),
                    dict(w: 64, h: 64, bpr: 256, alloc: 0x10000,
                         planes: basePlane,
                         extra: ["IOSurfaceSliceCount": sc,
                                 "IOSurfacePlaneHeaderRegionBytesPerSlice": NSNumber(value: hv)]),
                    verbose: false)
        }
        for (dv, sc) in [(UInt64(0x40000000), 4), (UInt64(0x7fffffff), 2)] {
            attempt(String(format: "D data=0x%llx sc=%d alloc=0x10000 (deliberately short)", dv, sc),
                    dict(w: 64, h: 64, bpr: 256, alloc: 0x10000,
                         planes: basePlane,
                         extra: ["IOSurfaceSliceCount": sc,
                                 "IOSurfacePlaneDataRegionBytesPerSlice": NSNumber(value: dv)]),
                    verbose: false)
        }
        // A plane whose declared size exceeds the allocation.
        attempt("D plane size 0x100000 vs alloc 0x4000",
                dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x100000)]))
        // A plane offset that leaves no room.
        attempt("D plane off=0x8000 size=0x4000 vs alloc 0x4000",
                dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0x8000, size: 0x4000)]))

        // --- E. address / superbuffer keys ----------------------------
        log("\n--- E. address / superbuffer keys ---")
        attempt("E AddressFormat+Offset+Ranges",
                dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                     extra: ["IOSurfaceAddressFormat": 0,
                             "IOSurfaceAddressOffset": 0,
                             "IOSurfaceAddressRanges": [0, 0x4000]]))
        attempt("E Superbuffer=0",
                dict(w: 64, h: 64, bpr: 256, alloc: 0x4000,
                     extra: ["IOSurfaceSuperbuffer": 0]))

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
