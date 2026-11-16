# The bit-8 dispatch flag: function-level confirmation, and a cross-build VA trap

Date: 2026-11-16
Builds: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target),
`firmware/24B119/kernelcache.release.macho` (iOS 27.2)
Tooling added: `tools/kz-static-diff/kz_mask_bytes.py`.
Raw output: `analysis/evidence/bit8-byte-census-2026-11-16/`
(`census.txt`, `census-all.txt`, `pairs-hid.txt`).
No device run. No vulnerability claim.

## 1. Why this pass happened

The previous checkpoint (`skywalk-bit8-dispatch-flag-2026-11-16.md`) recorded a
systemic 27.2 change — 443 new `and ...,#~0x100` sites concentrated in
per-selector external-method thunks — and left two things open:

1. whether the change is real *at the function level* rather than an artefact of
   block-level diffing, and
2. a methodological hazard nobody had written down: several of that pass's
   follow-ups compared **literal VM addresses across builds**.

This pass does (1) properly and records (2), because (2) silently produced a
false attribution mid-run and would do so again.

## 2. The trap: a literal VA means nothing across builds

Members are laid out differently between 24A446 and 24B119, so the same VM
address — and even the same **file offset** — holds unrelated code in the other
build. Measured example:

| VA | 24A446 | 24B119 |
|---|---|---|
| `0xfffffe000a14b460` | `IOMobileGraphicsFamily-DCP.__TEXT_EXEC`, file off `0x3147460`, bytes `100040f9f10300aa` | `IOHIDFamily.__TEXT_EXEC`, **same file off** `0x3147460`, bytes `5f2403d57f2303d5` |

So the address the earlier pass called "the HID dispatcher" is a genuine HID
function start in 24B119 (`0xfffffe000a14b460`, size `0x2ec`, the cookie
binary-search dispatcher) but *IOMobileFramebufferAP / DCP* code at that address
in 24A446. Its true 24A446 counterpart is `0xfffffe000a0fc374` — also size
`0x2ec`, also the sole caller of the corresponding thunk. Both dispatchers are
structurally identical; only the VA differs.

**Rule:** attribute code only through a member's own segment window, or pair
functions by shape/index within a member. Never carry a VA from one build into
another, and never treat "this VA is outside member X in build Y" as evidence
about build X.

Consequence for prior notes: the addresses in `skywalk-bit8-dispatch-flag`
§9–§11 are all used **within** a single build, so they stand. Anything that
compared an A address against B bytes does not.

## 3. Byte-exact census (new tool)

`kz_mask_bytes.py` counts the idiom as raw bytes inside each member's own
`__TEXT_EXEC` slice, so it cannot be perturbed by literal pools or a capstone
desync.

Two different quantities must not be conflated:

* **masked-immediate census** (capstone, all register forms) — the earlier
  pass's `34 → 477`;
* **exact 8-byte form** `and x11,x11,#~0x100 ; str x11,[x23,#8]` — this tool.

Exact-form totals: **A = 0, B = 54** image-wide. Per member (`census.txt`):

| member | A | B | delta |
|---|---:|---:|---:|
| `com.apple.iokit.IOHIDFamily` | 0 | 12 | +12 |
| `com.apple.iokit.IOSkywalkFamily` | 0 | 12 | +12 |
| `com.apple.iokit.IOUSBHostFamily` | 0 | 9 | +9 |
| `com.apple.driver.AppleFirmwareKit` | 0 | 8 | +8 |
| `com.apple.iokit.IOPCIFamily` | 0 | 4 | +4 |
| `com.apple.iokit.IOTimeSyncFamily` | 0 | 4 | +4 |
| `com.apple.iokit.IOStorageFamily` | 0 | 2 | +2 |
| `com.apple.driver.AppleARMPlatform` | 0 | 2 | +2 |
| `com.apple.driver.AppleCentauriManager` | 0 | 1 | +1 |

`com.apple.kernel` scores **0 for this exact form in both builds** even though
its masked-immediate census is 16 → 169: its sites use other register
allocations. This is why the exact-form number is a lower bound on one idiom
shape, not a replacement for the 477 figure.

The independent capstone-based `kz_mask_by_member.py` was re-run this session
and reproduces the earlier table exactly (kernel +153, Skywalk +107, USB +48,
HID +31, Centauri/ARMPlatform/IOStorage/IOPCI/FirmwareKit/corecapture/TimeSync
+13..+17; total 34 → 477), so that table is confirmed, not retracted.

## 4. Function-level confirmation: the HID thunk family

The HID member carries **22** functions with the thunk prologue constant pair
`mov w?,#0x2bf ; movk w?,#0xe000,lsl#16` (the baked default
`kIOReturnIPCError`), in **both** builds, in the same order. Pairing by sequence
index (`pairs-hid.txt`):

| observation | result |
|---|---|
| pairs | 22 / 22 |
| size delta | **+4 bytes on every pair** |
| instruction delta | **+1 on every pair** |
| B clears bit 8 where A does not | **22 / 22** |

Representative pair 0:

```asm
24A446 0xfffffe000a0fc660 (sz 0xe4)     24B119 0xfffffe000a14b74c (sz 0xe8)
  ldr  x8, [x0]                           ldp  x10, x22, [x0]
  ldr  w8, [x8, #0x20]                    ldp  w9, w8, [x0, #0x10]
  cmp  w8, #2                             ldr  x23, [x0, #0x18]
  b.ne reject                             ldr  x11, [x23, #8]
                                          and  x11, x11, #0xfffffffffffffeff   <-- NEW
                                          str  x11, [x23, #8]                 <-- NEW
                                          ldr  w10, [x10, #0x20]
                                          cmp  w10, #2
                                          ...
```

The 4-byte growth is exactly the two new instructions. The remaining body is
the same logic with merged loads. 9 further HID functions carry the clear
without the thunk prologue, which reconciles the 31-site census with the
22-function thunk family.

## 5. Established vs inferred

**Established**

* The bit-8 clear is a real 27.2 code change, present in 0 of these members in
  24A446 and in all of them in 24B119, at the byte level.
* In IOHIDFamily it is applied uniformly to a 22-function thunk family, always
  as the same +4-byte / +1-instruction insertion, immediately after loading the
  object at `[args+0x18]` and before the version/type check.
* The thunk family exists unchanged in count and order in both builds; the
  dispatchers (`0x2ec`, cookie binary search) match in size and role.
* Literal VAs are not comparable across builds (§2), and one concrete collision
  is documented.

**Inferred (not proven)**

* That the cleared bit is per-client state whose 27.0.1 persistence is a bug.
  No effect of the bit has been observed.
* That these thunks are reached by the client opened at type 2 during
  `--opencand`/`--hidsel`. The uniform `kIOReturnBadArgument` from that probe
  is *not* the dispatcher's `kIOReturnIPCError` default, so the call probably
  never reached this dispatcher at all — meaning the open type-2 client is
  likely a different class from the thunk owner. This is inference.

**Not established**

* Owning class names for the thunks (no symbols; `LC_SYMTAB nsyms=0`).
* Any app reachability, any attacker influence over bit 8, any advisory mapping,
  any memory-safety effect. No device cycle was spent.

## 6. Consequence for ranking

Unchanged: this stays bounded reconnaissance above the `kalloc_type` wall, with
the socket-UAF conversion blocker and the IOSurface-carveout ceiling still the
live limits. What is new is a clean, function-level statement of the change
(22/22, +4 bytes, one insertion) and a documented trap that would otherwise
corrupt the next cross-build comparison.

## 7. Next step (bounded, static)

1. Resolve the owning class of the 22 HID thunks by walking the reference chain
   from the dispatcher at `0xfffffe000a0fc374` (24A446) / `0xfffffe000a14b460`
   (24B119) — the dispatcher is the sole caller of each thunk, so the class is
   one level up. Do this **within one build**.
2. Enumerate that class's external-method selectors and its `IOServiceOpen`
   client types; compare against the measured `--hidsel` selector table.
3. Only if the class turns out to be app-openable, design a trigger with a
   positive detector for the stale-bit effect. Do not spend another device cycle
   on the current open type-2 client without that identification.

## 8. Follow-up: the owning vtable is located (class name still open)

Bounded static continuation, **within 24A446 only**.

* The dispatcher `0xfffffe000a0fc374` (`0x2ec`) has exactly one direct caller:
  a **0x30-byte stub** at `0xfffffe000a0fc344`.
* That stub is referenced by exactly **one** arm64e auth-pointer slot, file
  offset `0x13150d0` = VA `0xfffffe00083190d0`, inside IOHIDFamily
  `__DATA_CONST`. Walking the surrounding qwords gives a genuine C++ vtable:
  `offset-to-top = 0` and `RTTI = NULL` at `0xfffffe0008319060`/`...068`, then
  function pointers. Entries mix **IOHIDFamily-local methods**
  (`0xfffffe000a0d6144`, `...d614c`, `...d61ac`, `...d6340`, `...d65a4`,
  `...10180`) with kernel-core base-class implementations
  (`0xfffffe000b26xxxx`, `0xb2exxxx`), i.e. shared base methods plus per-derived
  overrides — the standard shape. So the dispatcher is a **virtual method of an
  IOUserClient-derived class**, not free-floating glue.
* **No string is referenced by any of the seven local vtable methods** (ADRP+ADD
  scan against IOHIDFamily `__TEXT`), so the class name is still unresolved.
  The vtable address itself has no literal/auth/chained reference in the image,
  so naming needs the `__OSMetaClass` path rather than a pointer scan.
* **The 22 thunks are not all fed by one dispatcher.** Direct BL/B callers land
  in at least three distinct functions: `0xfffffe000a0fc374` (thunks
  `a0fc660`/`a0fc744`/`a0fc82c`/`a0fcaac`), `0xfffffe000a0fd994`
  (`a0fd9c8`), and `0xfffffe000a0fea30` (`a0ffc1c`, `a0ff590`). One thunk
  (`a0fdd94`) has two callers. The thunk family therefore spans several client
  classes, consistent with `--opencand` measuring several distinct openable HID
  services.

Raw: `analysis/evidence/bit8-byte-census-2026-11-16/vt-hid-24A446.txt`.

## 9. Pitfall recorded

`kz_blw_scan.py` and `kz_vtable.py find` take a VA plus a build; giving them a
VA resolved in a *different* build returns a confident-looking wrong answer
(a false member attribution, or zero hits that read as "no caller"). Always
resolve the VA inside the build you are scanning.
