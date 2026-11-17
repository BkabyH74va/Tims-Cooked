# The `0x7ed74f0` slot-12 table belongs to `OSUserMetaClass`

Date: 2026-11-17
Builds: `firmware/24B119/kernelcache.release.macho` (iOS 27.2),
`firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target)
Tooling added: `tools/kz-static-diff/kz_tblwin.py`, `kz_adrp_range_np.py`,
`kz_rawslot.py`.
Raw output: `analysis/evidence/osusermetaclass-2026-11-17/`
(`register-and-vtable-24B119.txt`, `instantiation-site-24B119.txt`,
`verify-24A446.txt`).
No device run. No vulnerability claim.

## 1. Why this pass happened

The previous checkpoint named slot 12 as `IOUserClient::Dispatch(const IORPC)`
and left one bounded static step open: *name the owner of the*
`0xfffffe0007ed74f0` *table and characterise the* `0x7e8c980` *array*, so that
"invoked via data table" becomes either an ingress path or a hard negative.
This pass closes the first half and records the naming method, which is
reusable for every other stripped arm64e class in this image.

## 2. Result: the table is the instance vtable of `OSUserMetaClass`

`0xfffffe0007ed7490` (24B119) is an instance vtable with a two-entry C++ header
at `0x7ed7480`/`0x7ed7488`, so the stored vptr is `0x7ed7490`; the slot-12 entry
is therefore `0x7ed7490 + 0x60 = 0x7ed74f0` (`0xfffffe000b3e8ea0`), matching the
previous run's pointer-slot finding.

Slot 7 is `getMetaClass` and returns a global OSMetaClass; slot 2–6 and 8–11 are
the shared `OSObject` virtual bodies that also appear in `IOUserClient`'s base
vtable. That makes the owner a small `OSObject` subclass, not an
`IOUserClient` subclass (an earlier inference from slot-body reuse is corrected
here — see §4).

The owner is named from the generated metaclass constructor, which follows one
fixed shape (`this`, `#className`, `super::gMetaClass`, `sizeof(class)`, then
`OSMetaClass::OSMetaClass` and a vptr store):

```
0xfffffe000b3f09c8  pacibsp
0xfffffe000b3f09d8  adrp x0, #0xfffffe000b80a000 ; add x0,x0,#0x790   ; this = &gMetaClass
0xfffffe000b3f09e0  adrp x1, #0xfffffe00070c7000 ; add x1,x1,#0xcd0   ; "OSUserMetaClass"
0xfffffe000b3f09e8  adrp x19,#0xfffffe000b80a000 ; add x19,x19,#0xeb8 ; super::gMetaClass
0xfffffe000b3f09f4  mov  w3, #0x58                                          ; instanceSize
0xfffffe000b3f09f8  bl   #0xfffffe000b2bb604                               ; OSMetaClass::OSMetaClass
0xfffffe000b3f09fc..0b3f0a14  pacda(0xfffffe0007ed7520); str [x0]         ; metaclass vptr
```

Controls prove the pattern rather than assuming it:

| class | registration fn | name literal | super gMetaClass | size | metaclass vptr |
|---|---|---|---|---|---|
| `IOUserClient` | `0xfffffe000b3cf544` | `0x70c68ab` = `"IOUserClient"` | `0xb80af58` | `0xd8` | `0x7ed5760` |
| `OSObject` | `0xfffffe000b2beb44` | `0x70baefa` = `"OSObject"` | `0` (none) | `0x10` | `0x7ec2b28` |
| **`OSUserMetaClass`** | `0xfffffe000b3f09c8` | `0x70c7cd0` = `"OSUserMetaClass"` | `0xb80aeb8` = **`OSObject`** | `0x58` | `0x7ed7520` |

So the direct superclass of `OSUserMetaClass` is **`OSObject`**, and
`OSUserMetaClass` is a 0x58-byte `OSObject` subclass whose only overrides are
slot 7 (`getMetaClass`) and slot 12 (`Dispatch`).

`__LINKINFO` corroborates the identity independently: `__ZN15OSUserMetaClass8DispatchE5IORPC`,
`__ZN15OSUserMetaClass10gMetaClassE`, `__ZTV15OSUserMetaClass` are present in
both builds.

### 2.1 The slot-12 override, verbatim

```
0xfffffe000b3e8ea0  bti c
0xfffffe000b3e8ea4  ldr  x0, [x0, #0x18]      ; dispatch target = [this+0x18]
0xfffffe000b3e8ea8  cbz  x0, #0xfffffe000b3e8ef4   ; -> kIOReturnUnsupported
0xfffffe000b3e8ebc  ldp  q0, q1, [x1]; stp q0, q1, [sp]   ; copy struct IORPC (0x20)
0xfffffe000b3e8ec4  ldr  x16,[x0]; autda; ldr x8,[x16,#0x60]!
0xfffffe000b3e8ee0  blraa x8, x16                ; tail-dispatch target slot 12
```

`OSUserMetaClass::Dispatch` is a **pure forwarder**: it resolves a target object
stored at `+0x18`, copies the caller's `IORPC`, and tail-calls that target's
slot 12. It neither validates nor consumes `rpc.kernelContent`, so the 27.2
bit-8 clears in `IOUserClient`'s dispatcher are downstream of this forwarder,
not inside it.

## 3. Who creates `OSUserMetaClass` instances

The instance allocator is metaclass slot 13 (`0x7ed7588 -> 0xfffffe000b3e8f84`):
typed allocation of `0x58` bytes through the `kalloc_type` view at
`0xfffffe0007ec5bd0`, refcount `=1` at `+8`, vptr stored at `+0`.

Its only instantiation site found so far:

```
0xfffffe000b3ea86c  (sz 0x84, no direct BL callers — invoked from a table)
  ...
  bl   0xfffffe000b3ea8f0        ; builds the RPC-side state
  ldr  x0, [x20, #0x148]
  ldr  x1, [sp, #8]              ; the new OSUserMetaClass
  mov  w2, #0x29
  bl   0xfffffe000ad5d950        ; attach/assign into [parent+0x148]
```

`0xb3ea8f0` in turn loads `&gMetaClass` (`0xb80a790`) and calls **slot 13**
(`ldr x8,[x16,#0x68]`) on it — i.e. `OSUserMetaClass::alloc`. The enclosing
function is referenced from exactly one data slot, `__DATA_CONST`
`0xfffffe0007f00d00`, and has no `BL`/`B` caller anywhere in the image. Raw
scan output: `analysis/evidence/osusermetaclass-2026-11-17/instantiation-site-24B119.txt`.

Consequences, stated as observations:

* **No name-based instantiation exists.** The class-name literal
  `0xfffffe00070c7cd0` has exactly **one** code reference in 24B119 — the
  registration site above. Nothing calls `OSMetaClass::allocClassWithName`
  (or equivalent) with `"OSUserMetaClass"`, so instances are created only
  through a hardcoded `&gMetaClass` reference from a parent object.
* The parent object is unidentified: the slot holding `0xb3ea86c` sits in a
  mixed descriptor table at `0xfffffe0007f00d00` (stride `0x28`-shaped groups,
  entries mixing function pointers and integers), not in a normal C++ vtable.

## 4. Corrections carried forward

* **Superset claim withdrawn.** The previous note inferred the `0x7ed7490`
  class descended from `IOUserClient` because slots 2–6 and 8–11 reuse the same
  bodies. Those bodies are `OSObject`'s; the class's registered superclass is
  `OSObject` directly.
* **"Private `IORPCMessage.flags` bit" is not settled.** A member-wide bit-8
  census (`kz_flag_bits.py`) finds **304** sites in `com.apple.kernel` alone, and
  bit 8 also appears in `kalloc_type`-family flag paths — e.g.
  `tst w2, #0x100` at `0xfffffe000ac1f334` inside the allocator
  `0xac1f284` used by this very class. Bit 8 is therefore a common flag bit, not
  proven to be an `IORPC`-private flag. Do not build a trigger on that reading
  without resolving which producer writes `rpc.kernelContent->flags`.

## 5. The `0x7e8c980` array, characterised (partial)

`0xfffffe0007e8c980` is one entry of a stride-`0x18` group table
`{u64 key; fn handler; fn field-copier}`:

```
0x7e8c978  u64 0x808              ; key
0x7e8c980  fn  0xfffffe000b3d9ac8 ; handler   <- the previous run's "engine entry"
0x7e8c988  fn  0xfffffe000add6754 ; copier
```

Keys observed: `0x101, 0x201, 0x202, 0x302, 0x303, 0x403, 0x404, 0x503, 0x504,
0x505, 0x604, 0x707, 0x808, 0xe08, 0x1008, 0x10000` — each of the form
`(A << 8) | B` with small `A`/`B`, i.e. two byte-sized fields packed in one
qword. The copier column is a family of small field-shuffling routines in
`0xfffffe000add6xxx` (`ldr w8,[x0,#4]; str x8,[x0,#8]; ldr w8,[x0]; str x8,[x0]`,
…), i.e. struct-layout fixups, not crypto/checksum helpers.

Not settled: the table's base/extent, the consumer loop, and whether the key is
a message id. **No relation to `OSUserMetaClass` is established** — treat the
two threads as separate until a reference links them.

## 6. Verdict and next step

**Bounded reconnaissance; a named owner, still no ingress path and no
vulnerability claim.** What is new and solid: the fix-site-bearing slot-12
override belongs to `OSUserMetaClass` (both builds), it is a pure forwarder to
`[this+0x18]`, it is a 0x58-byte `OSObject` subclass, and it is instantiated
only by a hardcoded metaclass reference from an unnamed parent — never by
class-name lookup.

Next step (static, bounded): identify the parent object at
`0xfffffe0007f00d00` and walk upward to the first MIG/syscall/user-client entry;
that is the only remaining step between "named class" and "app-reachable or
hard negative". Do not spend a device cycle before that link exists.
