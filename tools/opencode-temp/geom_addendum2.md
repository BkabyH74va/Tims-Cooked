
### 11.5 The GPU half: what reproduces and what does not (2026-11-12, later)

The Metal toolchain component was installed (`xcodebuild -downloadComponent MetalToolchain`,
838.9 MB) and `probe.metal` (two kernels: `readU32`/`writeU32` on a device pointer at a
**byte** offset) is now compiled by Xcode into the app's `default.metallib`.

Note: a hand-built metallib (`xcrun -sdk iphoneos metal ... -target air64-apple-ios14.0`)
is rejected by the device with `MTLLibraryErrorDomain Code=1 "Invalid library file"`,
and so is the SDK-default build. **Xcode's own** metallib loads fine
(`device.makeDefaultLibrary()`), so the library must come from the app bundle.

What works on the 13 Pro (iOS 27.0, A15 GPU):

```
library loaded
F1 surface created id=16 kbase=0x102a6c000 alloc=0x10000
F1 buffer wrap ok gpuAddress=0x1500000000 len=65536
CTRL buffer gpuAddress=0x1500018000
READ idx=0x0 -> 0x0
READ idx=0x8000 (out of the 0x10000 buffer) -> 0x0
delta = 0x18000
WRITE at +0x18000 status=completed
CPU view of the control buffer: hit=-1 word0=0x0
GPU view of the control buffer: word0=0x0 word1=0x0
no marker in the control buffer (GPU view)
```

* `makeBuffer(bytesNoCopy: <kernel backing pointer>)` **works** - the driver accepts a
  kernel VA as the buffer's backing and gives it a GPU VA.
* A compute-kernel write **past** the 64 KiB buffer **executes** (`status=completed`).
* But it has **no effect**: the control buffer (GPU readback, not the CPU view) is
  unchanged. The A15 GPU masks the write to the buffer's own allocation.

Re-reading `F1-PRIMITIVE-EVIDENCE.md` §4.5 with this in mind: the transcript's
`*** CROSS-OBJECT HIT ctrl off=0x0 ***` is the tool's **own arithmetic** ("we aimed at
`ctrlga`, so by construction we hit it") - the transcript contains **no independent
readback** of the control buffer after the F1 write (the `[CTRLBUF] READ` lines all
read the control buffer *through the control buffer*, before the F1 write). So the F1
cross-object claim is weaker than it reads, and on our device the mechanism does not
reproduce: the write is silently dropped.

### 11.6 Why: the descriptor on 27.0/27.0.1 does not carry the per-slice values

The F1 transcript's descriptor dump (27.3 beta) has the header size at `+0x68`:

```
0060: 04 00 01 01 00 00 00 00   00 00 00 04 00 00 00 00
      -> +0x60 = 0x01010004       +0x68 = 0x40000000   <- headerPerSlice
```

Our descriptor (27.0 / 24A5390f and 27.0.1 / 24A446) for the *same* payload:

```
desc[0x40..0xc8]
40:0000000000000000 48:0000000042475241 50:0000000000010000 58:0000000000000001
60:0000000001010004 68:0000000000000000 70:0000000000000000 78:000000000001ccb3
80:0000000000000000 88:0000000000000040 90:0000000000000040 98:0000000000000000
a0:0000000000000000 a8:0000000000000200 b0:0000000000010000 b8:0000000001010004
descriptor occurrences of the per-slice values: [0x20=0x10000] [0x50=0x10000] [0xb0=0x10000]
```

**`0x40000000` and `0x4000` are absent** - only the real allocation size survives.
(The layouts are also shifted by 8 bytes between the two builds.) The kernel *parsed*
and *validated* the per-slice values - cases B and E are rejected, which is only
possible if the parser ran - but the values are not propagated into the descriptor
that the driver reads. So on 27.0/27.0.1 the GPU is never told about the bogus
geometry, and there is nothing for it to size an oversized mapping from.

**Consequence.** The F1 route (steer the surface's GPU mapping to alias another
allocation) depends on the per-slice values reaching the driver, and that does not
happen on these builds. What remains open is the *kernel-side* consumer: any path in
`com.apple.iokit.IOSurface` that trusts the stored `headerPerSlice`
(`plane+0x38`) / `dataPerSlice` (`plane+0x34`) when it copies or maps plane data
would be a kernel out-of-bounds access, which is the primitive a jailbreak needs.
That is a static hunt over the kext: find every read of the plane struct's
`+0x34`/`+0x38` after `0xa32cd18`/`0xa32cd94` store them.
