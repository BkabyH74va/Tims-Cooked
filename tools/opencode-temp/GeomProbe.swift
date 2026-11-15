//
//  ContentView.swift
//  AGXProbe â€” IOSurface geometry probe (read-only)
//
//  Target: iPhone18,1 / V53AP / t8150 / iOS 27.0.1 (24A446)
//
//  PURPOSE
//  -------
//  Answer one question, statically raised in analysis/f1/IOSURFACE-F1-KEYS.md:
//  on t8150 / 27.0.1, which caller-supplied IOSurface tile/slice geometry does
//  the kernel ACCEPT, and what does the resulting surface look like?
//
//  SAFETY
//  ------
//  This probe is deliberately inert:
//    * no Metal, no GPU work, no cross-object write attempt
//    * no writes to any other allocation
//    * only IOSurfaceCreate / IOSurfaceGet* / IOSurfaceCopyValue / release
//  A rejected geometry simply returns NULL. Accepted geometries are allocated
//  and immediately released.
//
//  The iOS SDK has no Swift module for IOSurface, so the C API is exposed
//  through AGXProbe-Bridging-Header.h.
//

import SwiftUI
import Darwin

@main
struct AGXProbeApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @StateObject private var vm = GeomViewModel()

    var body: some View {
        VStack(spacing: 12) {
            Text("AGXProbe â€” IOSurface geometry")
                .font(.headline)
            Text("iPhone18,1 / t8150 / iOS 27.0.1 (24A446)")
                .font(.caption2)
                .foregroundColor(.secondary)
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
                Text(vm.isRunning ? "Probingâ€¦" : "Run geometry probe")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(10)
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

    private var logFileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("geom.log")
    }

    private func log(_ m: String) {
        let line = "[\(Date().timeIntervalSince1970)] \(m)"
        self.log += line + "\n"
        print(line)
        fflush(stdout)
        try? self.log.write(to: logFileURL, atomically: true, encoding: .utf8)
    }

    func autoRunIfRequested() async {
        guard !didAutoRun else { return }
        didAutoRun = true
        guard ProcessInfo.processInfo.arguments.contains("--autorun") else { return }
        await runProbe()
    }

    // ------------------------------------------------------------------
    // Surface construction
    // ------------------------------------------------------------------

    /// Build one surface from explicit geometry. All values are the exact
    /// property-key strings the 27.0.1 kernel reads (verified in
    /// analysis/f1/IOSURFACE-F1-KEYS.md section 2).
    private func createSurface(
        _ tag: String,
        width: Int, height: Int, bytesPerRow: Int, allocSize: Int,
        pixelFormat: UInt32,
        sliceCount: Int? = nil,
        plane: [String: Any]? = nil
    ) {
        var d: [String: Any] = [:]
        d["IOSurfaceWidth"] = width
        d["IOSurfaceHeight"] = height
        d["IOSurfaceBytesPerElement"] = 4
        d["IOSurfaceBytesPerRow"] = bytesPerRow
        d["IOSurfaceAllocSize"] = allocSize
        d["IOSurfacePixelFormat"] = pixelFormat
        if let sc = sliceCount { d["IOSurfaceSliceCount"] = sc }
        if let p = plane { d["IOSurfacePlaneInfo"] = [p] }

        let ref = IOSurfaceCreate(d as CFDictionary)
        guard let s = ref else {
            log("\(tag): REJECTED (IOSurfaceCreate returned NULL)")
            return
        }
        // IOSurfaceRef is ARC-managed in Swift; no explicit release needed.

        let base = IOSurfaceGetBaseAddress(s)
        let alloc = IOSurfaceGetAllocSize(s)
        let bpr = IOSurfaceGetBytesPerRow(s)
        let h = IOSurfaceGetHeight(s)
        let w = IOSurfaceGetWidth(s)
        let pf = IOSurfaceGetPixelFormat(s)

        let baseStr = String(format: "0x%llx", UInt64(UInt(bitPattern: base)))
        log(String(
            format: "%@: OK base=%@ alloc=0x%lx bpr=%lu h=%lu w=%lu pf=0x%08x",
            tag, baseStr, alloc, bpr, h, w, pf
        ))

        // Read back the per-slice geometry the kernel actually stored.
        readBack(s, "IOSurfacePlaneHeaderRegionBytesPerSlice", "  hdrPerSlice")
        readBack(s, "IOSurfacePlaneDataRegionBytesPerSlice", "  dataPerSlice")
        readBack(s, "IOSurfacePlaneBytesPerRowOfTileData", "  tileRow")
        readBack(s, "IOSurfacePlaneBytesPerTileData", "  tileData")
        readBack(s, "IOSurfacePlaneOffset", "  planeOff")
        readBack(s, "IOSurfaceSliceCount", "  sliceCount")
        readBack(s, "IOSurfacePlaneSize", "  planeSize")
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

    /// A plain 2D surface with no tile geometry â€” the control.
    private func plain(_ tag: String, w: Int, h: Int) {
        createSurface(tag, width: w, height: h, bytesPerRow: w * 4,
                      allocSize: w * 4 * h, pixelFormat: 0x42475241 /* 'BGRA' */)
    }

    // ------------------------------------------------------------------
    // Probe
    // ------------------------------------------------------------------

    func runProbe() async {
        isRunning = true
        status = "Runningâ€¦"
        log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)

        log("=== AGXProbe IOSurface geometry probe ===")
        log("build 24A446 / t8150")
        log("SAFETY: read-only; no Metal, no writes, no cross-object attempt")

        // --- 0. controls -------------------------------------------------
        log("\n--- 0. control surfaces (no tile geometry) ---")
        plain("plain 64x64", w: 64, h: 64)
        plain("plain 512x64", w: 512, h: 64)

        // --- 1. does a plane dict with tile fields get accepted at all? ---
        log("\n--- 1. plane dict + tile fields, F1-shaped baseline ---")
        let f1Baseline: [String: Any] = [
            "IOSurfacePlaneWidth": 512,
            "IOSurfacePlaneHeight": 64,
            "IOSurfacePlaneBytesPerRow": 512,
            "IOSurfacePlaneBytesPerElement": 4,
            "IOSurfacePlaneOffset": 0x88,
            "IOSurfacePlaneSize": 0x4000,
            "IOSurfacePlaneBytesPerTileData": 0x1000,
            "IOSurfacePlaneBytesPerRowOfTileData": 0x200,
            "IOSurfacePlaneDataRegionBytesPerSlice": 0x4000,
            "IOSurfacePlaneHeaderRegionBytesPerSlice": 0x4000,
        ]
        createSurface("f1base hdr=0x4000", width: 512, height: 64,
                      bytesPerRow: 512, allocSize: 0x10000,
                      pixelFormat: 0x42475241, sliceCount: 4, plane: f1Baseline)

        // --- 2. headerPerSlice sweep (the F1 knob) ------------------------
        log("\n--- 2. headerPerSlice sweep (sliceCount=4) ---")
        let hdrValues: [UInt64] = [
            0, 1, 0x100, 0x1000, 0x4000, 0x10000, 0x100000,
            0x1000000, 0x10000000, 0x20000000, 0x40000000,
            0x7fffffff, 0x80000000, 0xffffffff,
        ]
        for hv in hdrValues {
            var p = f1Baseline
            p["IOSurfacePlaneHeaderRegionBytesPerSlice"] = NSNumber(value: hv)
            createSurface(String(format: "hdrPerSlice=0x%llx", hv),
                          width: 512, height: 64, bytesPerRow: 512,
                          allocSize: 0x10000, pixelFormat: 0x42475241,
                          sliceCount: 4, plane: p)
        }

        // --- 3. same sweep without the plane dict ------------------------
        // Distinguishes "the value is rejected" from "the key is only read
        // from a plane dictionary".
        log("\n--- 3. headerPerSlice as a top-level key (no plane info) ---")
        for hv in [0x4000, 0x100000, 0x40000000] {
            var d: [String: Any] = [:]
            d["IOSurfaceWidth"] = 512
            d["IOSurfaceHeight"] = 64
            d["IOSurfaceBytesPerElement"] = 4
            d["IOSurfaceBytesPerRow"] = 512
            d["IOSurfaceAllocSize"] = 0x10000
            d["IOSurfacePixelFormat"] = 0x42475241
            d["IOSurfaceSliceCount"] = 4
            d["IOSurfacePlaneHeaderRegionBytesPerSlice"] = hv
            let r = IOSurfaceCreate(d as CFDictionary)
            if r == nil {
                log(String(format: "top-level hdrPerSlice=0x%llx: REJECTED", hv))
            } else {
                log(String(format: "top-level hdrPerSlice=0x%llx: OK (ignored?)", hv))
            }
        }

        // --- 4. dataPerSlice / tile fields -------------------------------
        log("\n--- 4. dataPerSlice and tile field sweeps ---")
        for dv in [0x1000, 0x4000, 0x10000, 0x100000, 0x40000000] {
            var p = f1Baseline
            p["IOSurfacePlaneDataRegionBytesPerSlice"] = NSNumber(value: dv)
            p["IOSurfacePlaneHeaderRegionBytesPerSlice"] = 0x4000
            createSurface(String(format: "dataPerSlice=0x%llx", dv),
                          width: 512, height: 64, bytesPerRow: 512,
                          allocSize: 0x10000, pixelFormat: 0x42475241,
                          sliceCount: 4, plane: p)
        }
        for tr in [0x200, 0x400, 0x1000, 0x10000] {
            var p = f1Baseline
            p["IOSurfacePlaneBytesPerRowOfTileData"] = tr
            createSurface(String(format: "tileRow=0x%x", tr),
                          width: 512, height: 64, bytesPerRow: 512,
                          allocSize: 0x10000, pixelFormat: 0x42475241,
                          sliceCount: 4, plane: p)
        }
        for td in [0x1000, 0x2000, 0x4000, 0x10000] {
            var p = f1Baseline
            p["IOSurfacePlaneBytesPerTileData"] = td
            createSurface(String(format: "tileData=0x%x", td),
                          width: 512, height: 64, bytesPerRow: 512,
                          allocSize: 0x10000, pixelFormat: 0x42475241,
                          sliceCount: 4, plane: p)
        }

        // --- 5. sliceCount sweep -----------------------------------------
        log("\n--- 5. sliceCount sweep (hdr=0x4000, data=0x4000) ---")
        for sc in [1, 2, 3, 4, 8, 16] {
            createSurface("sliceCount=\(sc)", width: 512, height: 64,
                          bytesPerRow: 512, allocSize: 0x10000,
                          pixelFormat: 0x42475241, sliceCount: sc,
                          plane: f1Baseline)
        }

        // --- 6. adjacent primitives (do they exist / are they gated?) ----
        log("\n--- 6. adjacent primitives ---")
        probeAddressProps()
        probeSuperbuffer()

        log("\n=== done ===")
        status = "Complete"
        isRunning = false
    }

    /// IOSurfaceAddressRanges / AddressOffset / AddressFormat: the
    /// "map this surface over caller-supplied addresses" shape.
    private func probeAddressProps() {
        var d: [String: Any] = [:]
        d["IOSurfaceWidth"] = 512
        d["IOSurfaceHeight"] = 64
        d["IOSurfaceBytesPerElement"] = 4
        d["IOSurfaceBytesPerRow"] = 512
        d["IOSurfaceAllocSize"] = 0x10000
        d["IOSurfacePixelFormat"] = 0x42475241
        d["IOSurfaceAddressFormat"] = 0
        d["IOSurfaceAddressOffset"] = 0
        // A single range that does NOT cover the allocation, then one that
        // would. Both should be rejected or ignored; we only record which.
        d["IOSurfaceAddressRanges"] = [0, 0x10000]
        if let r = IOSurfaceCreate(d as CFDictionary) {
            log("address-props surface: OK (address keys ignored/rejected silently)")
            _ = r
        } else {
            log("address-props surface: REJECTED (NULL)")
        }
    }

    private func probeSuperbuffer() {
        // Pure probe: does the key exist in this kernel's parser? Supplying
        // a bogus superbuffer should fail, but how it fails is informative.
        var d: [String: Any] = [:]
        d["IOSurfaceWidth"] = 512
        d["IOSurfaceHeight"] = 64
        d["IOSurfaceBytesPerElement"] = 4
        d["IOSurfaceBytesPerRow"] = 512
        d["IOSurfaceAllocSize"] = 0x10000
        d["IOSurfacePixelFormat"] = 0x42475241
        d["IOSurfaceSuperbuffer"] = 0
        if let r = IOSurfaceCreate(d as CFDictionary) {
            log("superbuffer surface: OK (key ignored)")
            _ = r
        } else {
            log("superbuffer surface: REJECTED (NULL)")
        }
    }
}
