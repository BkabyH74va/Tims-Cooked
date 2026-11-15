
### 11.7 Verdict on the per-slice overflow (2026-11-12, final)

The consumer hunt for the stored per-slice values came back **empty**:

* Every instruction in `com.apple.iokit.IOSurface` that reads a `+0x34` / `+0x38`
  word other than the parser (`0xa32b7b4`) belongs to a **doubly-linked-list node
  helper** (the `next`/`prev` idiom at `+0x38`/`+0x40` with the
  `cmp`/`brk #0xbffd` back-pointer checks) - not to the plane structure.
* The only reads of the plane's `dataPerSlice` (`plane+0x34`) and `headerPerSlice`
  (`plane+0x38`) are the parser's own validation (`0xa32cd18` stores the data
  value, `0xa32cd94` stores the header value, `0xa32cd98` reads the data value
  back for the coverage check).
* The values never reach the driver: the 0xc68 descriptor on 27.0 / 27.0.1 does
  not contain them (§11.6), and `newTextureWithDescriptor:iosurface:plane:`
  **fails** for a surface created through the raw user-client path (it is not a
  shared/importable IOSurface), so the GPU never maps it either.
* The user-mapping path is closed: `IOSurfaceLock` returns false even for a
  self-consistent surface.

**So the overflow is a real validation bug with no exploitable consequence on
these two builds.** It is worth reporting as a finding (the parser's
`(data + header) * sliceCount` is computed in 32 bits, so a surface can claim a
1 GiB per-slice header region against a 64 KiB allocation, and the parser accepts
it) - but on 27.0 / 27.0.1 there is no consumer for the stored values, so it
cannot be escalated here.

### 11.8 The F1 transcript's GPU addresses are 32-bit-truncated

The F1 transcript prints `figa=0x15000000` and `ctrlga=0x15000e8000` - a
32-bit-looking address space. On our devices the same buffer reports
`gpuAddress=0x1500000000` (64-bit). The F1 tool therefore computed
`delta = ctrlga - figa = 0xe8000` on **truncated** addresses, and its
`*** CROSS-OBJECT HIT ***` is that arithmetic, not an independent readback
(the transcript has no read of the control buffer after the F1 write; the
`[CTRLBUF] READ` lines all read the control buffer *through the control buffer*,
before the write). Re-running the recipe here: the out-of-bounds compute write
executes (`status=completed`) but changes nothing - the A15 GPU masks it to the
buffer's own allocation.

Combined with §11.6/§11.7, the F1 lead is **not** a path to a jailbreak on
iOS 27.0 / 27.0.1.
