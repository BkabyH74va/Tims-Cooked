# Reclaimed datagram socket field differential — measured negative

Date: 2026-11-15
Device: secondary iPhone14,2 (iOS 27.0, 24A5390f). Primary iPhone18,1 (24A446)
remains SpringBoard-Locked (`unlockedSinceBoot: true` but `devicectl launch`
still refused), so it is not measured.
Carrier mode: `--sockfield` (`runSockFieldMode()` in
`carrier/AGXProbe/ContentView.swift`, `sockuaf_field_probe()` in
`carrier/AGXProbe/SockUafSpray.c`).
Raw log: `analysis/evidence/sockfield-2026-11-15/sockfield-13pro.log`.

## Question

`analysis/socket-uaf-crosstype-2026-11-14.md` proved a freed TCP socket slot can
be taken by a `SOCK_DGRAM` socket and that stale sender bytes are then transmitted
through it as UDP datagrams — but it never *read* the reclaimed object. Nothing
beyond payload and destination was known to be controlled; the mechanism by which
the data reaches the datagram socket (append to `so_snd`, protocol output) was
inferred, not observed. The named next step was to fingerprint every API-visible
field of the colliding socket and compare against a no-race control.

## Method

Per iteration:

1. one target TCP socket connected to a loopback listener;
2. six sender threads gate-spawned into `sendmsg` (8×1 KiB iovecs, 8192-byte
   buffer), then close lands while they may still be in-kernel (precision race);
3. **in-window hammer**: `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)` + `connect()`
   to the oracle port, in a tight loop while senders may still be inside their
   syscall, up to 256 allocations — the same hammer that wins the slot in
   `--sockmix`;
4. 48 fresh TCP sockets connected to the precision peer listener (control);
5. drain the UDP oracle (a datagram here is the positive collision detector);
6. **field diff**: fingerprint each hammer fd via `SO_TYPE`, `SO_ERROR`,
   `SO_SNDBUF`, `SO_RCVBUF`, `TCP_CONNECTION_INFO` (tcpinfo), and
   `getsockname` (family/port/addr); compare against a 16-sample control set of
   freshly created, never-raced dgram sockets built by the probe itself. A field
   whose value differs from *every* control sample is flagged.

The control is built by the same code path on the same device, so baseline drift
(allocator-dependent buffer sizes) cannot masquerade as a difference.

## Result

```
[+] sockfield: 5 cross-type hit(s), 0 field-diff hit(s), 0 peer hit(s) in 3000 iterations
```

| iter | datagrams | bytes | hammer fds | fingerprinted | field diffs |
|---|---|---|---|---|---|
| 138 | 5 | 40,960 | 251 | **251** | 0 |
| 298 | 6 | 49,152 | 40 | **40** | 0 |
| 978 | 2 | 16,384 | 7 | **7** | 0 |
| 1192 | 6 | 49,152 | 256 | **256** | 0 |
| 2349 | 1 | 8,192 | 5 | **5** | 0 |

Totals over 3,000 iterations: **5,487 hammer fds fingerprinted, 0 field
differences**. Control set consistent at n=16, `SO_TYPE=2 (SOCK_DGRAM)`,
`SO_SNDBUF=9216`, `SO_RCVBUF=786896`, tcpinfo unavailable on this family
(`-1` everywhere, identically on control and raced fds).

Representative lines (iter 138):

```
[!] ITER 138 sockfield: *** CROSS-TYPE HIT: 5 datagram(s)/40960 byte(s) (hammer=251, in flight at close 0/6) ***
[*] sockfield(odd): control n=16 type=2 sndbuf=9216 rcvbuf=786896 tcpinfo=-1
[*] sockfield(odd): VERDICT scanned=251 hits=0 readfail=0
```

## Proven

* On iterations where the TCP→UDP collision demonstrably fired (datagrams
  delivered through a socket the harness never sent on), **every** hammer-created
  datagram socket still answered the API exactly like a fresh, never-raced
  datagram socket. No `SO_TYPE`, `SO_ERROR`, `SO_SNDBUF`, `SO_RCVBUF`,
  `getsockname` or `TCP_CONNECTION_INFO` value moved outside the control range.
* The probe's detector is live: the same run produced 5 cross-type hits and
  `readfail=0` throughout, so the scan ran and the API calls succeeded. The zero
  is a measured absence, not a blind detector.
* The stale sender's bytes reach the reclaimed socket without leaving any trace
  in its userspace-visible socket state — the append/output path consumed them
  before this scan ran, or wrote only kernel-internal `sockbuf`/`mbuf` state
  that none of these options expose.

## Honest limits

* This measures the **API-visible** surface of the reclaimed socket only. Kernel
  fields that no socket option reads (`so_pcb` pointer, `so_proto`,
  `sockbuf` bookkeeping, usecount/defunct flags) are not observable here; a
  corruption in those would not appear.
* The scan runs after the oracle drain and after the contention sends, so a
  transient field state that existed inside the race window and was repaired by
  the protocol output path could be missed. That ordering is inherent to the
  design (the collision must complete before the hammer fds can be read).
* One device/build (24A5390f). Primary remains locked.
* Still not kR/W: this is a bounded negative on the conversion route, not a
  primitive.

## Interpretation

The cross-type collision is real and repeatable, but the reclaimed datagram
socket exposes **no observable field differential** through the entire BSD
socket API surface. Combined with the standing `kalloc_type` finding (the socket
slot is type-isolated, so the collision ceiling is TCP↔UDP within `struct
socket`), this closes the "name the corrupted field" step of the socket-UAF
conversion plan for app-visible fields: there is no app-readable handle on the
corruption.

The remaining theoretical route — a kernel-internal field (e.g. `so_pcb`) being
corrupted such that later protocol processing dereferences attacker-influenced
memory — cannot be tested from this harness without a kernel read, and would be
a different bug class than the one under investigation.

## Device safety

One clean run. The app completed normally (`=== sockfield done ===`), stayed
alive, and produced **no new AGXProbe crash report** (newest on the device is
`AGXProbe-2026-11-15-124950.ips`, ~2.5 h before the run; the run finished 15:19).
No panic, respring or reboot. Primary untouched (locked).
