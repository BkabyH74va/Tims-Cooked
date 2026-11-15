import Darwin
import Foundation

// Swift-visible mach_msg (SDK header order):
//   mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout, notify_name)

func sendTo(_ remote: mach_port_name_t, _ local: mach_port_name_t, bits: UInt32) -> mach_msg_return_t {
    var h = mach_msg_header_t()
    h.msgh_bits = bits
    h.msgh_remote_port = remote
    h.msgh_local_port = local
    h.msgh_id = 0xBEEF
    h.msgh_size = UInt32(MemoryLayout<mach_msg_header_t>.size)
    return withUnsafeMutablePointer(to: &h) { hp in
        mach_msg(hp, MACH_SEND_MSG, 0, 0, 0, 0, 0)
    }
}

func recvFrom(_ port: mach_port_name_t, size: UInt32, timeoutMs: UInt32) -> (mach_msg_return_t, mach_msg_id_t, UInt32, UInt32) {
    var h = mach_msg_header_t()
    let r = withUnsafeMutablePointer(to: &h) { hp in
        mach_msg(hp, MACH_RCV_MSG, 0, size, port, timeoutMs, 0)
    }
    return (r, h.msgh_id, h.msgh_size, h.msgh_bits)
}

var p: mach_port_t = 0
let ka = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE | MACH_PORT_RIGHT_SEND, &p)
print("alloc recv|send kr=\(ka) port=\(p)")

let bitCandidates: [UInt32] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                               0x10, 0x20, 0x30, 0x40, 0x50, 0x60]
var sent = false
for bits in bitCandidates {
    let r = sendTo(p, p, bits: bits)
    print("send bits=0x\(String(bits, radix: 16)) -> kr=\(r) (0x\(String(UInt32(bitPattern: r), radix: 16)))")
    if r == 0 {
        let (rr, mid, msize, mbits) = recvFrom(p, size: 64, timeoutMs: 500)
        print("   recv -> kr=\(rr) id=0x\(String(mid, radix: 16)) size=\(msize) bits=0x\(String(mbits, radix: 16))")
        sent = true
        break
    }
}
print("sent=\(sent)")

// kernel-sourced message: request a DEAD_NAME notification on a dead port
var dead: mach_port_t = 0
let kd = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &dead)
print("alloc dead kr=\(kd) port=\(dead)")
let kdd = mach_port_deallocate(mach_task_self_, dead)
print("deallocate dead kr=\(kdd)")

var notify: mach_port_t = 0
let kn = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &notify)
print("alloc notify kr=\(kn) port=\(notify)")
let krn = mach_port_request_notification(mach_task_self_, dead, MACH_NOTIFY_DEAD_NAME, 0, notify)
print("request_notification -> \(krn)")
if krn == 0 {
    let (rr, mid, msize, mbits) = recvFrom(notify, size: 64, timeoutMs: 2000)
    print("   recv -> kr=\(rr) id=0x\(String(mid, radix: 16)) size=\(msize) bits=0x\(String(mbits, radix: 16))")
}
print("done")
