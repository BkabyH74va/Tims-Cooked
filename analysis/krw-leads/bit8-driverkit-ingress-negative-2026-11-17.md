# The `0x7ed74f0` / bit-8 cluster sits inside DriverKit user-client creation — ingress negative

Date: 2026-11-17
Builds: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target),
`firmware/24B119/kernelcache.release.macho` (iOS 27.2)
Tooling added: `tools/kz-static-diff/kz_nzrange.py`, `kz_refs_func.py`.
Raw output: `analysis/evidence/bit8-driverkit-2026-11-17/`.
No device run. No vulnerability claim.

## 1. Why this pass happened

The previous checkpoint (`analysis/krw-leads/osusermetaclass-dispatch-owner-2026-11-17.md`)
named the slot-12 owner as `OSUserMetaClass` and left one bounded step open:
*identify the parent object behind the `__DATA_CONST` descriptor slot
`0xfffffe0007f00d00` and walk up to the first MIG / syscall / user-client entry*,
with an explicit exit criterion — if neither table resolves to an app-visible
message path, close the cluster as reconnaissance-only.

This pass executes that step. It does not reach a user-client entry; it reaches
an entitlement-gated DriverKit user-client creation path instead.

## 2. What the descriptor region is

`0xfffffe0007f00d00` holds one arm64e auth pointer (`-> 0xfffffe000b3ea86c`, the
function that allocates an `OSUserMetaClass`). It is not a vtable slot. The
surrounding `__DATA_CONST` bytes are a **method-descriptor table**, not a plain
C++ vtable:

* entries mix function pointers with small integers and type-encoding strings;
* the strings are block/method signatures, e.g.
  `0xfffffe00070ce8f6` = `"B16@?0^{OSObject=^^?i}8"`,
  `0xfffffe00070c8c82` = `"B16@?0^{OSArray=^^?iIIIII^^{OSMetaClassBase}}8"`,
  `0xfffffe00070cdf75` = `"i8@?0"`;
* repeated groups carry `{ptr, ptr, type-string}` plus integer fields `0x28`,
  `0x30`, `0x38`, `0x20`.

Observed window: `descriptor-window-24B119.txt`. Notably, **no code site
references the exact address `0xfffffe0007f00d00`**; the table is consumed by
offset, not through the slot itself (`kz_rawslot.py 24B119 com.apple.kernel
0xfffffe0007f00d00` returns 0 slots while a control target returns its slot).

## 3. Who consumes it: one contiguous kernel-core block

An ADRP+ADD/LDR scan of every `__TEXT*` segment for references into
`0xfffffe0007f00d00 .. 0xfffffe0007f01200` finds **122 sites in 31 distinct
functions**, all inside one contiguous range of `com.apple.kernel`:

```
0xfffffe000b35288c .. 0xfffffe000b401738   (the outlier at b35288c is sz 0xc0)
```

Raw: `adrp-refs-24B119.txt`, `refs-to-functions-24B119.txt`.

So the table has no consumer outside this runtime block. It is not referenced by
any kext member, and there is no MIG routine or syscall glue among the callers.

## 4. The block contains the DriverKit user-client creation entitlement gate

`0xfffffe000b3fc5cc` (sz `0x928`) is one of the 31 consumers, and it is the
entitlement check for creating a DriverKit user client. Annotated excerpt
(`gate-24B119-b3fc5cc.s`):

```
0xfffffe000b3fc618  STR "root"
0xfffffe000b3fc620  bl   0xfffffe000b3cf820        ; 'consolesession'/'secureprocess'/'foreground'
0xfffffe000b3fc624  cbnz w0, skip
0xfffffe000b3fc630  ldr  x16,[x19]; autda; add x16,x16,#0x100; ldr x8,[x16]
0xfffffe000b3fc650  STR "com.apple.developer.driverkit.administrator"
0xfffffe000b3fc654  mov  x0, x19
0xfffffe000b3fc65c  blraa x8, x16                  ; <- entitlement probe
...
0xfffffe000b3fc6ac  STR "IOUserClientCreator"     ; fallback name
0xfffffe000b3fc6bc  blraa x8, x16
```

Its 12 references into the descriptor region are listed in
`cross-build-gate.txt`; the function reads `0xfffffe0007f00d68` nine times and
`0xfffffe0007f01058` three times.

**Cross-build.** The target build carries the identical function at
`0xfffffe000b3a5fd0` (same size `0x928`, same instruction stream) with the same
two names and the same gate shape; see `cross-build-gate.txt` and
`gate-24A446-b3a5fd0.s`. The entitlement string exists exactly once per build
(`0xfffffe00070c7dd5` in 24A446, `0xfffffe00070c8a09` in 24B119) and each has
exactly one code reference, inside this gate.

The 24A446 side of the class itself was already verified in the previous
checkpoint: registration `0xfffffe000b39a564` (name literal `0x70c709c`),
instance vtable base `0x7ec73b8`, slot-12 override `0xfffffe000b392a34`.
(The 24A446 counterpart of the instantiation function `0xb3ea86c` was **not**
located this pass.)

## 5. Verdict

**Bounded negative — close the bit-8 / `OSUserMetaClass` cluster as
reconnaissance-only.**

* Proven: the fix-site-bearing slot-12 override belongs to `OSUserMetaClass`;
  the descriptor table that drives its instantiation is consumed only from one
  contiguous kernel-core runtime block; that block's identifiable consumer is a
  DriverKit user-client creation path gated on
  `com.apple.developer.driverkit.administrator`; the same gate exists in the
  target build.
* Proven earlier and still standing: the changed instructions are four
  `and #~0x100` clears on a private/reserved flag bit, and bit 8 is a common flag
  bit (304 sites in `com.apple.kernel`), so the change is hardening-shaped.
* Not established: that the entitlement gate is the *only* route to the handler,
  or that some non-DriverKit user client reuses `OSUserMetaClass`. No such route
  was found in a full-image caller/data-reference scan.
* No MIG / syscall / user-client entry, no attacker-controlled argument, no
  memory-safety effect, no device measurement.

Per the previous checkpoint's exit criterion, effort returns to the VM/VFS and
external-object leads.

### Secondary negatives recorded

* **No symbol table.** Neither build's fileset members carry an `LC_SYMTAB`
  (0 members / 0 symbols). `__LINKINFO` is a string blob only, so address→name
  resolution must go through the OSMetaClass constructor recipe, not `nlist`.
* **Mixed descriptor table.** Windows of `__DATA_CONST` in this area must be
  interpreted entry-by-entry; stride-`0x28` grouping silently merges a
  method-descriptor array with neighbouring arrays, and any single-slot census
  mislabels a vtable as present/absent.
