import Darwin
import Foundation

@_silgen_name("mach_task_self")
func mts() -> mach_port_t

func test() {
    var p: mach_port_t = 0
    let kr1 = mach_port_allocate(mts(), MACH_PORT_RIGHT_RECEIVE, &p)
    print("alloc", kr1, p)

    var q: mach_port_t = 0
    let kr2 = mach_port_allocate(mts(), MACH_PORT_RIGHT_SEND, &q)
    print("alloc2", kr2, q)

    // send a simple message to p using the send right q
    var hdr = mach_msg_header_t()
    hdr.msgh_bits = UInt32(MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0))
    hdr.msgh_remote_port = p
    hdr.msgh_local_port = q
    hdr.msgh_size = UInt32(MemoryLayout<mach_msg_header_t>.size)
    hdr.msgh_id = 0x1234

    let snd = withUnsafeMutablePointer(to: &hdr) { hp in
        hp.withMemoryRebound(to: Int32.self, capacity: 4) { ip in
            mach_msg(ip, MACH_SEND_MSG, 0, 0, 0, 0, 0, 0)
        }
    }
    print("send", snd)

    var rh = mach_msg_header_t()
    let rcv = withUnsafeMutablePointer(to: &rh) { hp in
        hp.withMemoryRebound(to: Int32.self, capacity: 4) { ip in
            mach_msg(ip, MACH_RCV_MSG, 0, 1000, p, 0, 0, 0)
        }
    }
    print("recv", rcv, rh.msgh_id, rh.msgh_size)
}
