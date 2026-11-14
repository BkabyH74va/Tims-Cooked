# `vm_object_iopl_request`: the DART/SID validator is NOT a 27.2 addition (2026-11-14)

Status: **static only, no device run, no vulnerability claim.**
Scope: corrects a central claim in
`analysis/krw-leads/upl-iopl-cluster-diff-2026-11-14.md` §3, which said the
24A446 → 24B119 diff *adds* a DART/APF/SID validation call inside
`vm_object_iopl_request`. **That is wrong: 27.0.1 already contains it.**

## 1. The correction, with the instruction that proves it

`vm_object_iopl_request`, 24A446 @ `0xfffffe000acd1e18`, size `0x20f0`.

```
0xfffffe000acd3c5c  csel  w8, wzr, w8, ne
0xfffffe000acd3c60  ldrb  w1, [x19, #0xa6]      ; byte tag on vm_object
0xfffffe000acd3c64  cmp   w1, #2
0xfffffe000acd3c74  b.eq  0xfffffe000acd3740    ; skip
0xfffffe000acd3c78  cmp   w1, #0x22
0xfffffe000acd3c7c  b.eq  0xfffffe000acd3740    ; skip
0xfffffe000acd3c80  cmp   w1, #0x80
0xfffffe000acd3c84  b.eq  0xfffffe000acd3740    ; skip
0xfffffe000acd3c88  stur  x25, [x29, #-0x70]
0xfffffe000acd3c8c  ldr   w8, [sp, #0x38]
0xfffffe000acd3c90  stp   w8, wzr, [x29, #-0x68]
0xfffffe000acd3c94  sturb wzr, [x29, #-0x60]
0xfffffe000acd3c98  sturb wzr, [x29, #-0x5f]
0xfffffe000acd3c9c  sturb wzr, [x29, #-0x5c]
0xfffffe000acd3ca0  sub   x0, x29, #0x70
0xfffffe000acd3ca4  mov   w2, #1
0xfffffe000acd3ca8  bl    0xfffffe000ad3ff9c    ; sz=0x1a88  <-- DART/SID/APF validator
0xfffffe000acd3cac  ldr   w8, [x19, #0xa8]
0xfffffe000acd3cb0  orr   w8, w8, #0x80
0xfffffe000acd3cb4  str   w8, [x19, #0xa8]
```

Its diagnostics (`annot.py`): `Mis-aligned APF register base`,
`Potential double unmap or memory stomper? pmap=%p ttep=%p`,
`dart %p (%s): pa %#llx len %#lx out of range`.

The 27.2 counterpart is `bl 0xfffffe000ad92f44` at `0xfffffe000ad25484`
(`vm_object_iopl_request` @ `0xfffffe000ad23b5c`, size `0x1cb8`), with the
**identical** `[x19+0xa6]` tag gate (skip on `2`, `0x22`, `0x80`) and the
**identical** `orr w8,#0x80 -> [x19+0xa8]`. Both validator bodies are
`0x1a88` bytes. The only differences between the two call sites are stack
offsets and register allocation.

So this block was **moved/re-encoded**, not introduced. The prior document's
"141-instruction block added in 27.2" was a mis-attribution produced by
comparing the annotated streams at different sizes without matching the
`[obj+0xa6]` tag-gate shape.

## 2. Call-graph fingerprints are equivalent

Direct `BL` count inside the function: **109 in 24A446, 100 in 24B119**.
Distinct callees: 44 vs 44. Both call the `0x1a88` validator exactly once.
Only two 27.2-only callee entries exist (`0xfffffe000ad2586c` sz `0x3b8`,
`0xfffffe000ad37930` sz `0x37c`), and 27.0.1 compensates elsewhere
(e.g. 13 calls to the `0x80`-byte helper `0xad12ab8` in 27.2 vs 10 to its
`0xacc1138` counterpart). This is a re-layout, not a new dependency.

## 3. Which `vm_object` fields are touched — identical set

Counted every `[x19, #imm]` access in each function body:

| offset | 24A446 | 24B119 |
|---|---|---|
| `+0x18` | 1 | 1 |
| `+0x2c` | 1 | 1 |
| `+0x38` | 2 | 2 |
| `+0x48` | 1 | 1 |
| `+0x50` | 1 | 1 |
| `+0x58` | 2 | 2 |
| `+0x60` | 3 | 3 |
| `+0x6c` | 11 | 11 |
| `+0x70` | 8 | 8 |
| **`+0x74`** | **19** | **11** |
| `+0x75` | 1 | 2 |
| `+0x76` | 1 | 1 |
| `+0xa6` | 1 | 1 |
| `+0xa8` | 8 | 7 |
| `+0xa9` | 3 | 3 |
| `+0xab` | 1 | 1 |
| `+0xb8` | 2 | 2 |
| `+0xe8` | 8 | 8 |

**18 distinct offsets in both builds, the same set.** The only meaningful count
difference is `+0x74` (19 → 11) and the corresponding `+0xa8` write count
(8 → 7), consistent with removal of one gated accounting site — not with any
new validation being bolted on.

## 4. What actually changed

1. **`iopl_valid_data` lost one gate** (already recorded correctly in
   `upl-iopl-cluster-diff-2026-11-14.md` §2): 27.0.1 tests
   `tbnz w8, #0xc` on `[vm_object+0x74]` before the pager/ledger accounting
   call; 27.2 does not. Bit 12 is inferred to be `internal`.
2. **A 196-instruction `vm_page_grab` statistics block was deleted**
   (`A[1534:1730]` collapses to `B[1450:1452]`) — the bulk of the size delta
   (`0x20f0` → `0x1cb8`).
3. **Two new helper calls appear in 27.2** (`0xad2586c` sz `0x3b8`,
   `0xad37930` sz `0x37c`); their 27.0.1 equivalents were not identified in
   this pass and remain open.
4. `0xacd5224` (page-list builder) and `0xacd64fc` / `0xacd8e50` still show
   the same structural changes previously recorded.

## 5. `iopl_valid_data` caller identity — RESOLVED

Previous state: "its caller `0xfffffe000b347a08` has no direct BL/B to it and
no plain pointer slot, so reachability is unresolved."

Now measured:

* `iopl_valid_data` (`0xacd4d34`) has **exactly one direct branch**:
  `BL 0xfffffe000acd4d34` at `0xfffffe000b347c20`, inside function
  `0xfffffe000b347a08` (size `0x418`).
* `0xb347a08` is in **`IOMemoryDescriptor.cpp`**: its callees include
  `0xb347e20` (`IOMemoryDescriptor.cpp`), `0xacd60f0` (`vm_pageout.c`),
  `0xad00da4` (`pages available? kr=%d`), and it references
  `"complete() while dma active @%s:%d"` at `0xb347e18`. Its own 7
  `iopl_valid_data:` panic strings resolve into the callee as expected.
* `0xb347a08` itself has **zero direct branches** and **zero chained-fixup
  pointer slots** (`kz_chainfind.py chainrefs` → 0 indirect slots), so it is
  entered through a runtime pointer (jump/vtable) rather than a static call.
  That is where the chain stops today; it does not change the verdict below.

## 6. Verdict

* **The UPL/DART lead is not a new-fix signal.** The single most-cited
  "27.2 added SID validation on the IOPL path" claim is refuted; both builds
  validate. Re-do not reopen this as a patch-diff lead without a fresh
  semantic delta.
* **Ceiling unchanged: DoS.** `iopl_valid_data`'s failure modes are all
  `panic()`, so even a fully reachable trigger yields a kernel panic, not
  read/write. No device run is justified on this basis.
* The one real behavioural delta left standing is the removal of the
  `internal`-bit gate around a ledger-accounting call in `iopl_valid_data`
  (`upl-iopl-cluster-diff-2026-11-14.md` §2). It reads as refactor/hardening;
  it is not demonstrated to be a memory-safety fix and no device probe is
  warranted yet.
* **Next static step** if this cluster is ever reopened: name the two
  27.2-only helpers (`0xad2586c`, `0xad37930`) and their 27.0.1 counterparts,
  and identify how `0xb347a08` is dispatched (runtime pointer source).
