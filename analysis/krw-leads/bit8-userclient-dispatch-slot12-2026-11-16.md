# The bit-8 dispatch change sits behind an app-openable HID user client (shared kernel-core dispatcher)

Date: 2026-11-16
Builds: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target),
`firmware/24B119/kernelcache.release.macho` (iOS 27.2)
Tooling added: `tools/kz-static-diff/kz_fn_adrp.py`, `kz_member_authscan.py`.
Raw output: `analysis/evidence/bit8-slot12-2026-11-16/`
No device run. No vulnerability claim.

## 1. Why this pass happened

The previous checkpoint (`bit8-idiom-function-level-2026-11-16.md`) left the
HID half of the 27.2 bit-8 change unresolved at one point: **which class owns
vtable `0xfffffe0008319060`**, the table containing the external-method
dispatcher `0xfffffe000a0fc374` and the 22 changed thunks. It said the owner
was an `IOUserClient`-derived class but could not name it.

This pass names the neighbouring classes and, in doing so, finds something the
earlier pass missed: an **app-vendable** user-client vtable that links straight
into the shared kernel-core dispatcher carrying new bit-8 clears.

## 2. Two tool gaps fixed first

* `kz_fn_strings.py` reports `no start` for every kext-member function because
  `kc_fstarts.func_of` only indexes the `com.apple.kernel` fileset entry. It
  therefore cannot answer "what does this HID function reference?" — a false
  negative that reads as "references nothing".
* `kz_vtable.py find` goes through `kc_fstarts.v2o`, so it raises `KeyError`
  for any member address (it silently worked before only on kernel-core VAs).

New tools: `kz_fn_adrp.py` (all ADRP+ADD/LDR targets of one function, capstone
`.imm` used directly — the raw-immediate decode double-scales and produced
`0xffdf…` garbage) and `kz_member_authscan.py` (member-scoped auth-pointer slot
search). Both are numpy-free.

## 3. Class-name references are recoverable (build attribution matters)

`analysis/evidence/skywalk-bit8-2026-11-16/hid-strings.txt` lists
`IOHIDEventServiceFastPathUserClient` at `0xfffffe00079bd675`; that address is
`"_cap_buffer: power assert failed: %d\n"` in 24A446. Raw byte search shows the
file was generated against **24B119** (where that string really is at
`0x79bd675`); in 24A446 the same string is at `0x79b0435`. Every VA in that
old file must be re-attributed before use — a cross-build VA trap of the same
kind already recorded in §2 of the previous doc.

Correct 24A446 name VAs and their code references (all `add` unless noted):

| class | name VA | code refs |
|---|---|---|
| `IOHIDEventServiceFastPathUserClient` | `0x79b0435` | `0xa0aae78`, `0xa0aafbc`, `0xa0ac0e0` |
| `IOHIDLibUserClient` | `0x79b06d2` | `0xa0ac768`, `0xa0ac8ac`, `0xa0b2f24` |
| `IOHIDResourceDeviceUserClient` | `0x79b2bff` | `0xa0f835c`, `0xa0f84a0`, `0xa0fb628` |
| `IOHIDEventServiceUserClient` | `0x79b2a46` | `0xa0f5bc0`, `0xa0f5d04`, `0xa0f68e4` |
| `IOFastPathUserClient` | `0x79b1aa4` | `0xa0cc808`, `0xa0cca8c`, `0xa0cd3d0` |
| `IOHIDInterface` | `0x79b1f4b` | `0xa0d608c`, `0xa0d61d0`, `0xa0d87e0` |
| `IOHIDEventDriver` | `0x79b24ea` | `0xa0dc890`(ldr), `0xa0dc8f8`(ldr), `0xa0e0364`, `0xa0e04a8`, `0xa0e41cc`, `0xa0e4264`(ldr), `0xa0e4334`(ldr) |
| `IOHIDDevice` | `0x79b0cfa` | `0xa0b37f4`, `0xa0b3898`, `0xa0b3ae4`(ldr), `0xa0bb29c` |

Each user-client class has exactly three `add` sites: two in its
meta-class-init/alloc cluster and one elsewhere. `IOHIDEventDriver`/
`IOHIDDevice` have extra `ldr` sites (property/personality lookups).

## 4. Metaclass vtable vs instance vtable — the pattern

At a meta-class init the code calls `OSMetaClass::OSMetaClass`
(`0xfffffe000a122920`, an auth-stub that resolves through `__DATA_CONST`
`0x8323198` to `0xfffffe000b265500`) with `(name, superMeta, size)`, then
stores a vptr into the returned metaclass object. An adjacent function calls
an allocator and stores a **second** vptr into the new instance.

Measured pairs (base addresses; the stored address point is base `+0x10`):

| class | superclass slot | metaclass vtable | instance vtable |
|---|---|---|---|
| `IOHIDEventServiceFastPathUserClient` | `[0x8323618]` | `0x8313488` | `0x8312e90` |
| `IOHIDLibUserClient` | `[0x8323618]` | `0x8313ee8` | `0x83138e8` |
| `IOHIDResourceDeviceUserClient` | `[0x8323618]` | `0x831f890` | `0x831f280` |
| `IOHIDEventServiceUserClient` | `[0x8323618]` | `0x831e278` | **`0x831dc60`** |
| `IOFastPathUserClient` | `[0x8323618]` | `0x8317ea8` | `0x83178b8` |
| `IOHIDInterface` | `[0x8323698]` | `0x8319650` | **`0x8319060`** |
| `IOHIDEventDriver` | — | `0x831ab48` | `0x831a450` |
| `IOHIDDevice` | `[0x8323698]` | `0x8314c10` | `0x8314580` |

Corroboration for the last two columns being different objects: in
`IOHIDEventServiceUserClient`'s case the second vtable's slots 0/1 are the
class-local destructor pair (`0xa0f5c78`/`0xa0f5c80`), slots 2–11 are shared
kernel-core base methods, and slot 12 is a shared kernel-core dispatch thunk —
the normal shape of a user-client vtable.

Consequence for the open question: the previously anonymous target
`0xfffffe0008319060` is the **instance vtable of `IOHIDInterface`**, inferred
from (a) the adjacent named meta-class init at `0xa0d608c` ("IOHIDInterface"),
(b) the matching allocation size `0x108` in both the named init (`w3=0x108`)
and the adjacent allocators, and (c) `IOHIDInterface` and `IOHIDDevice` sharing
superclass slot `[0x8323698]`. No method in that vtable references a string,
so this rests on structure, not on a symbol.

## 5. The important result: an app-vendable client vtable contains the shared dispatcher

`IOHIDEventServiceUserClient` is one of the three user clients the HID
personalities actually vend (`__PRELINK_INFO`: provider `IOHIDEventService` →
`IOHIDEventServiceUserClient`; `IOHIDDevice` → `IOHIDLibUserClient`;
`IOResources` → `IOHIDResourceDeviceUserClient`).

Its instance vtable slot 12, in both builds:

| build | instance vtable | slot 12 thunk | thunk target | bit-8 clears in target |
|---|---|---|---|---|
| 24A446 | `0x831dc60` | `0xfffffe000b2c8024` | `0xfffffe000b2c8050` | 0 (absent from the 24A446 kernel census) |
| 24B119 | `0x8334508` | `0xfffffe000b31e208` | `0xfffffe000b31e234` | **3** (`mask-kernel-B.txt`) |

The two thunk bodies are identical apart from the target address:

```asm
pacibsp ; sub sp,#0x30 ; stp x29,x30,[sp,#0x20] ; add x29,sp,#0x20
ldp  q0,q1,[x1] ; stp q0,q1,[sp]      ; copy 0x20 bytes of the args struct
mov  x1,sp ; bl <dispatcher>
```

So the shared external-method dispatch path is linked into an
`IOServiceOpen`-reachable user-client class, and 27.2 changed the dispatcher it
calls (three new `and …,#~0x100` sites at `0xb31e234`). None of the 31
IOHIDFamily mask-site functions appears in this client's vtable, i.e. the
app-facing clears live in kernel core, not in the kext. (Checked over 48
vtable slots per class; zero mask-site functions in any of the three clients,
in either build.)

## 6. Established vs inferred

**Established**

* Corrected 24A446 class-name VAs and their exact code-reference sites (§3).
* The metaclass-init/alloc pattern that separates a class's metaclass vtable
  from its instance vtable (§4).
* `IOHIDEventServiceUserClient` instance vtables in both builds, with the
  byte-identical 0x2c slot-12 thunk and its dispatcher target (§5).
* 27.2 adds 3 bit-8 clears to that dispatcher; 24A446's counterpart has none.
* Personality map: HID user clients are `IOHIDEventServiceUserClient`,
  `IOHIDLibUserClient`, `IOHIDResourceDeviceUserClient`.

**Inferred (not proven)**

* That `0x8319060` is `IOHIDInterface`'s instance vtable (§4).
* That vtable slot 12 is the `externalMethod` entry reached by
  `IOConnectCallMethod` rather than some other virtual. The shared-thunk shape
  and the surrounding base-method slots make this likely; it is not confirmed
  by a caller scan.

**Not established**

* Any attacker-reachable selector that makes the dispatcher execute one of the
  three cleared sites; the dispatcher is a cookie binary search and the branch
  predicates are unread.
* What bit 8 gates, whether an app can set or clear it, and whether the 27.0.1
  behaviour is memory-unsafe.
* Whether opening an `IOHIDEventDriver` at type 2 actually instantiates
  `IOHIDEventServiceUserClient` (the personality points at the
  `IOHIDEventService` provider; the measured openable instances were drivers).
* Advisory mapping.

## 7. Consequence for ranking

The previous checkpoint's instruction — "do not spend another device cycle on
the current open type-2 client before the owner is named" — is answered in
part, and the answer *upgrades* the lead rather than closing it: the changed
kernel-core dispatcher is reachable in principle through a user-client class
that the platform itself vends to services. This is above the `kalloc_type`
wall, app-adjacent, and worth one carefully designed measurement. It remains
bounded reconnaissance: no selector mapping, no trigger, no memory-safety
effect.

## 8. Next step (bounded)

1. Static: dump the 24B119 dispatcher `0xfffffe000b31e234` and its 24A446
   counterpart `0xfffffe000b2c8050`; extract the cookie constants, the branch
   tree and the three cleared sites; identify which input field selects a
   branch. This stays inside one build per comparison.
2. Static: confirm slot 12 is `externalMethod` by finding a caller that loads
   vtable offset `0x60` on a user client (`ldr xN,[xM,#0x60]; blraa`) up to a
   MIG/`is_io_connect_method` boundary.
3. Only then device: find the actual `IOHIDEventService` provider instance
   (not `IOHIDEventDriver`) and drive `IOConnectCallMethod` with the recovered
   structure shape, logging per-stage results and a positive control. Do not
   repeat the flat selector sweep that returned uniform `kIOReturnBadArgument`.

Raw: `analysis/evidence/bit8-slot12-2026-11-16/`.
