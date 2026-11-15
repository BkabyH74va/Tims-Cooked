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
            Text("AGXProbe v62 - raw notify registration on our OWN connection").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v62")
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

    // MARK: - types

    typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
    typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32

    /// the framework's port-aware callee:
    /// (conn, selector, port, inputScalars, inputCnt, inputStruct, inputStructCnt,
    ///  outStruct, outStructSize, ?, ?)
    typealias SetCallFn = @convention(c) (
        io_connect_t, UInt32, mach_port_t,
        UnsafePointer<UInt64>?, UInt32,
        UnsafeRawPointer?, Int,
        UnsafeMutableRawPointer?, UInt64,
        UnsafeRawPointer?, UnsafeRawPointer?
    ) -> kern_return_t

    private var gCreate: CreateFn?
    private var gGetID: GetIDFn?

    // MARK: - helpers

    private func krstr(_ kr: kern_return_t) -> String {
        let u = UInt32(bitPattern: kr)
        switch u {
        case 0: return "0x0 SUCCESS"
        case 0xe00002c2: return "BadArgument"
        case 0xe00002c9: return "dup-notify"
        case 0xe00002bd: return "0x2bd"
        case 0xe00002d8: return "NotAttached"
        default: return "0x" + String(u, radix: 16)
        }
    }

    private func hex(_ v: UInt64) -> String { "0x" + String(v, radix: 16) }

    /// decode a BL at fn+off. ARM64 branch target = PC + signext(imm26<<2)  (NO +4)
    private func blTarget(_ fn: UnsafeMutableRawPointer, _ off: Int) -> UInt64? {
        let fnAddr = Int(UInt(bitPattern: fn))
        guard let p = UnsafeRawPointer(bitPattern: fnAddr + off) else { return nil }
        let insn = p.load(as: UInt32.self)
        guard (insn >> 26) == 0b100101 else { return nil }
        let imm26 = Int64(insn & 0x03FFFFFF)
        let signed = (imm26 << 38) >> 38
        let pc = UInt64(fnAddr + off)
        return UInt64(bitPattern: Int64(pc) + (signed << 2))
    }

    private func makeSurface() -> UnsafeMutableRawPointer? {
        guard let gCreate else { return nil }
        let p: [String: Any] = ["IOSurfaceWidth": 256, "IOSurfaceHeight": 256,
                                "IOSurfaceBytesPerElement": 4]
        return gCreate(p as CFDictionary)
    }

    private func tryOpen(_ name: String, _ type: UInt32) -> (kern_return_t, io_connect_t) {
        let matching = IOServiceMatching(name)
        var iter: io_iterator_t = 0
        let kr1 = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iter)
        if kr1 != KERN_SUCCESS { return (kr1, 0) }
        let svc = IOIteratorNext(iter)
        IOObjectRelease(iter)
        if svc == 0 { return (-2, 0) }
        var conn: io_connect_t = 0
        let kr2 = IOServiceOpen(svc, mach_task_self_, type, &conn)
        IOObjectRelease(svc)
        return (kr2, conn)
    }

    // MARK: - probe

    private func probe() {
        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setFn = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let rmFn = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify"),
              let cs = dlsym(fwH, "IOSurfaceCreate"),
              let isym = dlsym(fwH, "IOSurfaceGetID") else {
            emit("symbol fail"); return
        }
        gCreate = unsafeBitCast(cs, to: CreateFn.self)
        gGetID = unsafeBitCast(isym, to: GetIDFn.self)

        // the framework's BL sites: set @ +0x78, remove @ +0x50
        guard let setCallee = blTarget(setFn, 0x78),
              let rmCallee = blTarget(rmFn, 0x50) else {
            emit("BL decode failed"); return
        }
        emit("set    fn      @ " + hex(UInt64(UInt(bitPattern: setFn))))
        emit("set    callee  @ " + hex(setCallee))
        emit("remove fn      @ " + hex(UInt64(UInt(bitPattern: rmFn))))
        emit("remove callee  @ " + hex(rmCallee))

        guard let setPtr = UnsafeRawPointer(bitPattern: Int(setCallee)) else { return }
        let setFnPtr = unsafeBitCast(setPtr, to: SetCallFn.self)

        // --- our own surface -------------------------------------------------------
        guard let surf = makeSurface() else { emit("surface create failed"); return }
        let sid = UInt64(gGetID!(surf))
        emit("\nsurface id = " + hex(sid))

        // --- our own connection to IOSurfaceRoot ----------------------------------
        let (okr, conn) = tryOpen("IOSurfaceRoot", 0)
        emit("IOServiceOpen(IOSurfaceRoot) -> " + krstr(okr) + " conn=" + String(conn))
        guard okr == KERN_SUCCESS else {
            Unmanaged<AnyObject>.fromOpaque(surf).release(); return
        }

        // --- our own notify port ---------------------------------------------------
        var port: mach_port_t = 0
        let pkr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port)
        emit("mach_port_allocate -> " + krstr(pkr) + " port=" + hex(UInt64(port)))
        guard pkr == KERN_SUCCESS else { IOServiceClose(conn); return }

        // --- exactly the framework's wire shape ------------------------------------
        var inScalars: [UInt64] = [0, 1, sid]      // {0, type, surfaceID}
        var structBuf: [UInt64] = [1, sid, 0]     // {type, surfaceID, 0}
        let surfaceID = sid

        func doSet() -> kern_return_t {
            var kr: kern_return_t = -1
            inScalars.withUnsafeBufferPointer { ib in
                structBuf.withUnsafeMutableBufferPointer { sb in
                    kr = setFnPtr(conn, 0x11, port,
                                  UnsafeRawPointer(ib.baseAddress!).assumingMemoryBound(to: UInt64.self),
                                  3, nil, 0,
                                  UnsafeMutableRawPointer(sb.baseAddress!), 0x18,
                                  nil, nil)
                }
            }
            return kr
        }

        emit("\n=== raw set on OUR connection ===")
        let kr1 = doSet()
        emit("set(P, 1, " + hex(surfaceID) + ") -> " + krstr(kr1))
        let kr2 = doSet()
        emit("set again (expect dup)     -> " + krstr(kr2))

        // --- raw remove on our connection (plain IOConnectCallMethod) --------------
        var rmStruct: [UInt64] = [0, surfaceID, 0]
        var kr3: kern_return_t = -1
        rmStruct.withUnsafeBufferPointer { sb in
            kr3 = IOConnectCallMethod(conn, 0x12, nil, 0,
                                     UnsafeRawPointer(sb.baseAddress!), 0x18,
                                     nil, nil, nil, nil)
        }
        emit("remove via SDK IOConnectCallMethod -> " + krstr(kr3))

        // --- remove again (expect BadArgument) ------------------------------------
        var kr4: kern_return_t = -1
        rmStruct.withUnsafeBufferPointer { sb in
            kr4 = IOConnectCallMethod(conn, 0x12, nil, 0,
                                      UnsafeRawPointer(sb.baseAddress!), 0x18,
                                      nil, nil, nil, nil)
        }
        emit("remove again (expect BadArgument)  -> " + krstr(kr4))

        // --- also try the framework's remove callee directly -----------------------
        if let rmPtr = UnsafeRawPointer(bitPattern: Int(rmCallee)) {
            typealias PlainFn = @convention(c) (
                io_connect_t, UInt32,
                UnsafePointer<UInt64>?, UInt32,
                UnsafeRawPointer?, Int,
                UnsafeMutablePointer<UInt64>?, UnsafeMutablePointer<UInt32>?,
                UnsafeMutableRawPointer?, UnsafeMutablePointer<Int>?
            ) -> kern_return_t
            let plain = unsafeBitCast(rmPtr, to: PlainFn.self)
            var kr5: kern_return_t = -1
            rmStruct.withUnsafeBufferPointer { sb in
                kr5 = plain(conn, 0x12, nil, 0,
                            UnsafeRawPointer(sb.baseAddress!), 0x18,
                            nil, nil, nil, nil)
            }
            emit("remove via framework callee       -> " + krstr(kr5))
        }

        emit("\n=== done ===")
        IOServiceClose(conn)
        Unmanaged<AnyObject>.fromOpaque(surf).release()
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v62 - raw notify on our own conn ===")
        try? await Task.sleep(nanoseconds: 3_500_000_000)
        probe()
        status = "Complete"; isRunning = false
    }
}
