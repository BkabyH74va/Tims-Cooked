# `iopl_valid_data` dispatch resolved: IOMemoryDescriptor-family vtable slot 28

Date: 2026-11-16
Builds: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target),
`firmware/24B119/kernelcache.release.macho` (iOS 27.2)
Tooling: new `tools/kz-static-diff/kz_vtable.py` (numpy-free, capstone +
`tools/opencode-temp/kc_fstarts.py`). Raw output:
`analysis/evidence/iopl-vtable-2026-11-16/`.
No device run. No vulnerability claim.

## 1. Why this pass happened

`analysis/krw-leads/upl-dart-not-a-272-addition-2026-11-14.md` §5 left one open
question: the sole caller of `iopl_valid_data`, `0xfffffe000b347a08`, has **zero
direct branch sites and zero chained-fixup pointer slots**, so its entry mechanism
was unknown. This pass settles it.

## 2. The decoding rule that was missing

Arm64e *auth* pointer tables (vtables, jump tables) in these kernelcaches store
each entry as a full 64-bit value:

```
entry = PAC/diversity (bits 32..63) | (target_va - 0xfffffe0007004000) (bits 0..31)
```

They are **not** part of the `LC_DYLD_CHAINED_FIXUPS` blob, so
`kz_chainfind.py chainrefs` reports `0 indirect slot(s)` for their targets — a
false negative that reads as "unreachable". Measured base:
`0xfffffe0007004000` (the `__TEXT` *segment* starts at `0xfffffe000700c000`;
the rebase base is `0x8000` lower, matching `kz_chainfind.TEXT_VMADDR_DEFAULT`).

Verified examples (24A446): entry `0x8011928504343a08` → low32 `0x04343a08` →
`0xfffffe0007004000 + 0x04343a08 = 0xfffffe000b347a08`.

## 3. Result: `iopl_valid_data` is vtable slot 28

| build | `iopl_valid_data` | size | sole direct caller | caller's vtable slot |
|---|---|---:|---|---|
| 24A446 | `0xfffffe000acd4d34` | `0x4f0` | `0xfffffe000b347a08` (`BL` @ `0xb347c20`) | index 28 (`+0xe0`) of table `0xfffffe0007ebd5e0` |
| 24B119 | `0xfffffe000ad269f8` | `0x4e8` | `0xfffffe000b39de14` (`BL` @ `0xb39e02c`) | index 28 of table `0xfffffe0007ecd688` |

The table at `0xfffffe0007ebd5e0` is an **IOMemoryDescriptor-family class
vtable**:

* slot 18 (`0xb34967c`) references `IOMemoryDescriptor.cpp` and asserts
  `_dmaReferences overflow`;
* slot 32 (`0xb347928`) references `IOMemoryDescriptor.cpp`;
* slot 27's callee `0xb3486a4` contains `IOMemoryDescriptor 0x%zx prepared read
  only`;
* the slot-28 body references `"complete() while dma active @%s:%d"`
  (string `0xfffffe00070c4103`, code ref at `0xfffffe000b347e18`, inside the
  slot-28 function boundaries), so it is a **`complete()`-family method**.

Additional copies of the same slot exist in sibling vtables at
`0xfffffe0007ebd7b8`, `0xfffffe0007ef50a8`, `0xfffffe0007ef52b0` (and their
24B119 counterparts) — same target function, same index, confirming these are
parallel class vtables rather than a one-off table.

Slot-28 behaviour recorded from the disassembly (24A446):

* gate: `(this->flags & kIOMemoryTypeMask /*0xf0*/) == kIOMemoryTypePhysical
  (0x20)`, else return `0xe00002d8`; bit 18 of `this->flags` returns
  `0xe00002d9`;
* CAS-locks `this+0xa8`;
* walks a stride-`0x28` list and calls `iopl_valid_data(entry, ...)` per element;
* dispatches virtual slot 17 (`+0x88`) with selector `0x32`/`0x33`.

So the previously "unresolved runtime pointer source" is a plain C++ virtual
dispatch through an IOMemoryDescriptor-family object. Because IOMemoryDescriptor
objects are created by many user clients from app-supplied buffers and file
mappings, this is **structurally app-adjacent**, not yet proven reachable from a
specific selector.

## 4. Cross-build vtable comparison — bounded negative

`kz_vtable.py diff 24A446 0xfffffe0007ebd5e0 24B119 0xfffffe0007ecd688 38`
(`analysis/evidence/iopl-vtable-2026-11-16/vtdiff.txt`):

* all 38 entries resolve to function starts in both builds;
* every entry's high 32 bits match across builds (same PAC/diversity);
* deltas cluster at `+0x56104` .. `+0x5646c` — pure code-layout shift, **no entry
  changed identity**.

No vtable-level fix signal between 27.0.1 and 27.2 on this surface.

## 5. The one real behavioural delta found: slot 27's new argument guard

Slot 27 (`0xfffffe000b348450` sz `0x254` ↔ `0xfffffe000b39e868` sz `0x270`)
grew by exactly one 8-instruction prologue in 27.2:

```asm
; 24B119 @ 0xfffffe000b39e868
bti   c
mov   w8, #0x2d8
movk  w8, #0xe000, lsl #16     ; 0xe00002d8
mov   w9, #0xc0
bic   w9, w9, w1               ; bits set in w1 are cleared
cbnz  w9, 0xfffffe000b39e888   ; any of bits 6/7 clear -> normal body
sub   w0, w8, #0x16            ; 0xe00002d8 - 0x16 = 0xe00002c2
ret                            ; kIOReturnBadArgument
```

24A446's slot 27 has no such check: the same call falls straight into the normal
body. Everything else in the two bodies is semantically identical (verified with
`annot.py` + `kz_side.py`; the only other differences are three global-variable
addresses in the page-accounting block and re-indexing caused by the insertion).

The guard lives in the **shared method implementation**, not one class: all four
sibling vtables found by `kz_vtable.py find` (bases `0xfffffe0007ebd5e0`,
`0xfffffe0007ebd7b8`, `0xfffffe0007ef4fc8`, `0xfffffe0007ef51d0`; 24B119
counterparts `0x7ecd688`, `0x7ecd860`, `0x7f050c0`, `0x7f052c8`) map slot 27 to
the same pair `0xb348450` / `0xb39e868` and slot 28 to `0xb347a08` /
`0xb39de14`. So every class that dispatches these slots inherits the new check.
Raw output: `vtdiff-siblings.txt`.

`0xc0` matches `kIODirectionCompleteWithError (0x40) |
kIODirectionCompleteWithDataValid (0x80)` from the IOKit `IODirection` enum
(`MacKernelSDK/Headers/IOKit/IOMemoryDescriptor.h`, `IOTypes.h` on iOS). Those
flags are documented "valid for the complete() method only", and slot 27 is
immediately before the `complete()`-family slot 28 in the same vtable.

**What is proven:** 27.2 rejects `(arg & 0xc0) == 0xc0` with
`kIOReturnBadArgument` in this method; 27.0.1 accepts it and runs the normal
prepare/deposit path.

**Method mapping (strong inference; target-matched headers are unavailable):** The public LP64 `IOMemoryDescriptor` declaration has 12 new virtual methods before `prepare`, and `prepare` is immediately followed by `complete`. Counting the inherited `OSMetaClassBase`/`OSObject` virtual entries (including the two ABI destructor entries, conditional `Dispatch`, and `OSObject::init/free`) places them at indices 27 and 28 if the target uses this ABI layout. Target behavior independently fits: slot 18 maps to `dmaCommandOperation` and contains the `_dmaReferences` overflow assertion; slot 27's callee reports an `IOMemoryDescriptor ... prepared read only` condition; slot 28 contains the `complete() while dma active` diagnostic and calls `iopl_valid_data`. This makes slot 27 = `prepare(IODirection)` highly likely, but the public header is a 2019 MacKernelSDK reference, not the exact iOS 27 header, and no symbol/RTTI confirms the target class.

**What remains inferred, not proven:**

* the exact dynamic class owning this vtable;
* that an app can cause a user-client method to call this method with the completion-only bits set;
* that accepting them in 27.0.1 produces anything worse than different bookkeeping. No exploit primitive, no DoS and no reachability is established.

## 6. Verdict and next steps

* The open question "how is `iopl_valid_data`'s caller entered?" is **closed**: it
  is an arm64e auth-pointer vtable dispatch, slot 28 of an
  IOMemoryDescriptor-family vtable. The technique (`kz_vtable.py`) generalizes to
  any "zero BL/B, zero chainrefs" function.
* The UPL/DART fix-site hypothesis stays **refuted** (both builds validate SID);
  this pass found no new evidence for it.
* The slot-27 guard is a **genuine 27.2 behavioural delta on a plausible
  app-adjacent IOKit method**, currently bounded reconnaissance.

Next falsifiable steps, cheapest first:

1. Name the vtable's class and the method at index 27 by reconstructing the
   declaration order from the public `IOMemoryDescriptor.h` (base-class virtuals
   first) and checking at least two independently identified slots.
2. Find an app-openable user client whose external method calls this vtable slot
   on a descriptor created from app memory (`IOBufferMemoryDescriptor`,
   `IOMemoryDescriptor::withAddressRange`); only then decide whether a device
   probe is justified.
3. If (2) finds a caller, test whether 24A446 accepts `(arg & 0xc0) == 0xc0` and
   whether the resulting path differs from the non-flag case — bounded, secondary
   unit first, with crash-log pull before/after.
