# The bit-8 dispatcher is a slot-12 IOUserClient virtual, not `externalMethod`

Date: 2026-11-17
Builds: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target),
`firmware/24B119/kernelcache.release.macho` (iOS 27.2)
Tooling added: `tools/kz-static-diff/kz_slot12_callers.py`,
`kz_slot12_vtable.py`.
Raw output: `analysis/evidence/bit8-slot12-2026-11-17/`
No device run. No vulnerability claim.

## 1. Why this pass happened

The previous checkpoint (`bit8-userclient-dispatch-slot12-2026-11-16.md`)
left two bounded next steps: (1) dump the dispatcher and extract the cookie
branch tree, (2) confirm vtable slot 12 is `externalMethod` with a
`ldr xN,[xM,#0x60]; blraa` caller scan. This pass did both and **step 2 came
back negative**: slot 12 is not `externalMethod`.

## 2. The owning vtable is the IOUserClient base instance vtable

Recovered with the same `__OSMetaClass` pattern used for the HID classes:

* `0xfffffe000b3cf544` calls `OSMetaClass::OSMetaClass` with
  `name = "IOUserClient"` (`0xfffffe00070c68ab`), superclass
  `0xfffffe000b80af58`, `size = 0xd8`, then stores the metaclass vptr
  `pacda(0xfffffe0007ed5760)`.
* Adjacent functions `0xfffffe000b3cf58c` and `0xfffffe000b3cf5b8` construct
  instances: `w8 = 1; str w8,[x0,#8]`, then store
  `pacda(0xfffffe0007ed8070)` into `[x0]`.
* Corroboration that `0xfffffe0007ed8070` is a real C++ vtable: its first two
  entries are destructors, and the primary destructor
  `0xfffffe000b3cd5c8` checks the allocation size against `0xd8` — the same
  size passed to `OSMetaClass` above.

Dump of that table (`iouk-base-vtable-24B119.txt`): entries `+0`/`+1` are
destructors, so the vptr is the table start itself and **slot 12 = byte offset
`0x60`**, entry `0xfffffe0007ed80d0 -> 0xfffffe000b31e208`.

The IOHIDFamily user-client vtables contain the same thunk at the same slot
(relative to their own vptr): e.g. `IOHIDEventServiceUserClient` header base
`0xfffffe0008334508`, vptr `0xfffffe0008334518`, slot 12 at
`0xfffffe0008334578 -> 0xfffffe000b31e208`. Five HID vtables share it
(`hid-vtables-containing-thunk.txt`). So this is a shared IOUserClient base
implementation, not an HID-local override.

## 3. Dispatcher delta is exactly three bit-8 clears

| build | thunk | dispatcher | size |
|---|---|---|---|
| 24A446 | `0xfffffe000b2c8024` (0x2c) | `0xfffffe000b2c8050` | 0x298 (166 insns) |
| 24B119 | `0xfffffe000b31e208` (0x2c) | `0xfffffe000b31e234` | 0x2ac (171 insns) |

`kz_fn_sem_diff.py` over the two dispatchers (`shim-generic-mig-sem-diff.txt`
holds the companion glue diff; the dispatcher diff was read directly) shows the
only semantic change is the insertion of

```
ldr  xN, [x21, #8]
and  xN, xN, #0xfffffffffffffeff
str  xN, [x21, #8]
```

in the three branches selected by the baked cookies, at 24B119
`0xb31e310`, `0xb31e3c0`, `0xb31e408`. Everything else in the diff is
register-allocation churn (three separate `ldr` pairs folded into `ldp`) plus
ADRP page / literal-pool drift. The branch predicates (`[x21] == cookie`,
`[[x1]+0x20] == 1 or 2`, `[x21+0x10] == 1 or 2`, sizes `>= 0x26c / >= 0x104`
and `>= 0x54 / >= 0x3c`) are unchanged.

Cookie constants are **byte-identical across 24A446 and 24B119**:

```
0xf2fa2faa5cc11190  (search-tree root)
0xf2fa2faa5cc11191  branch A   [x21+0x10]==1, size>=0x26c/0x54
0xcaf3bd8932c8486f  branch B   [x21+0x10]==1, ccmp size vs 0x54
0xcfe0c99e739d92f9  branch C   (default for <= root, != B)
0xf609f134c9046444  branch D   [x21+0x10]==2, size>=0x104/0x3c
```

Two of them also appear as data in a `{u64 key, u64 size}` table at
`0xfffffe0007010030`/`0x40` (24B119) and `0x20`/`0x30` (24A446); branch A
copies 16 bytes from that table entry into the caller's output buffer, so the
values are static descriptor keys, not PAC'd pointers.

## 4. The generic glue is unchanged

The 0x20-byte call-struct builder that invokes slot 12 in kernel core,
`0xfffffe000b3fb294` (24B119) ↔ `0xfffffe000b3a4c98` (24A446), both size
`0x458`, is **semantically identical** between builds: the diff is eleven
address/string-offset substitutions and nothing else. The 27.2 change is
therefore confined to the shared per-class wrapper, not to the MIG-style glue.

## 5. Negative result: slot 12 is not `externalMethod`

`kz_slot12_vtable.py` (member-scoped, requires the slot-load base to trace to a
vptr load) finds **11** slot-12 dispatches in `com.apple.kernel`, all of the
form `dispatch(x0 = object, x1 = &stack_struct)` where the argument is a
0x20-byte blob copied from a caller struct:

```
struct { u64 f0; void *f8; u32 f10; u32 f14; void *f18; }   // 0x20 bytes
```

No site passes `(selector, IOExternalMethodArguments *)`. The public XNU
declaration is unambiguous:

```cpp
MIG_SERVER_ROUTINE virtual IOReturn
externalMethod(uint32_t selector, IOExternalMethodArguments * arguments,
    IOExternalMethodDispatch *dispatch = NULL,
    OSObject *target = NULL, void *reference = NULL);
```

so `externalMethod` cannot occupy slot 12 here. The previous checkpoint's
upgrade ("the changed kernel-core dispatch path is linked into an
IOServiceOpen-adjacent client") still stands — slot 12 is an IOUserClient base
virtual reached from `IOServiceOpen`-created clients — but the method is an
internal compact-dispatch virtual whose name is still unknown.

## 6. Established vs inferred vs open

**Established**

* The shared slot-12 thunk/dispatcher is IOUserClient's base implementation;
  the IOHIDFamily user-client vtables inherit it unchanged.
* 27.2 adds exactly three bit-8 clears of `[arg18 + 8]`, one per cookie branch;
  branch predicates and thresholds are unchanged.
* The generic glue function is byte-for-byte equivalent modulo addresses.
* Cookie constants are identical across builds and exist as static data keys.
* Slot 12 is not `externalMethod` (ABI mismatch at every one of 11 call sites).

**Inferred (not proven)**

* That `[args+0x18]` is an object: its `+0x20` is dereferenced as an object
  (`ldr x20,[x21,#0x20]; ldr x16,[x20]; autda; ldr x8,[x16,#0x38]`), `+0x28`
  is passed to `_sendAsyncResult64`, and `+0x38` supplies the async-reference
  array. Under that reading the three clears toggle a flag on a live client
  object.
* Alternative reading: `+0x18` is the copied structure-input buffer, in which
  case clearing bit 8 only touches kernel-private copied input and the change
  is input validation, not object state.

**Open (the gate for any device work)**

* Which caller actually reaches `IOHIDEventServiceUserClient`'s slot 12, and
  what it puts at `+0x00`/`+0x18`. The one glue path traced end-to-end
  (`0xb3fb294`) writes a status code at `+0x00` and a stack buffer at `+0x18`,
  which contradicts the object reading — so either that path serves a
  different class/slot or the blob layout differs per call site. Argument
  provenance is unresolved and no probe should be designed on it.
* The slot-12 virtual's name. Candidates must come from iOS 27's internal
  IOUserClient, not the public header.
* Whether the cleared bit is attacker-settable in 24A446 and what it gates.

## 7. Next step (bounded, static first)

1. Resolve the slot-12 method identity from a subclass that overrides it with
   identifiable content (an IOExternalMethodDispatch table, or a string
   reference), and enumerate which of the 11 call sites can reach a HID
   `IOUserClient`. Do not assume `externalMethod`.
2. Trace one concrete call site end-to-end and settle `args+0x00` / `args+0x18`
   provenance from the registers at the dispatch instruction.
3. Only then design one bounded device probe: structure input of size
   `>= 0x26c` whose first qword is one of the four cookies, sent on the
   openable type-2 HID client, logging the resolved mode, per-stage return
   codes and a positive control. The earlier `--hidsel` sweep only reached
   input sizes `0x200` and never set the cookie field, so neither threshold nor
   branch selection was exercised.

Evidence: `analysis/evidence/bit8-slot12-2026-11-17/`
(`dispatcher-*.s`, `shim-generic-mig-sem-diff.txt`,
`iouc-base-vtable-24B119.txt`, `slot12-vtable-dispatch-sites-24B119.txt`,
`hid-vtables-containing-thunk.txt`).
