# The 16 Skywalk "real edits" reduce to one systemic 27.2 change: clear bit 8 of `[client+8]` in user-client dispatch thunks

Date: 2026-11-16
Builds: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target),
`firmware/24B119/kernelcache.release.macho` (iOS 27.2)
Tooling added: `tools/kz-static-diff/kz_member_dump.py`, `kz_block_funcs.py`,
`kz_skywalk_id.py`, `kz_fn_sem_diff.py`, `kz_fn_classify.py`,
`kz_delta_cluster.py`, `kz_mask_sites.py`, `kz_mask_ctx.py`, `kz_ref_sites.py`,
`kz_ptr_slots.py`, `kz_thunk.py`, `kz_raw.py`, `kz_const_use.py`,
`kz_member_vtable.py`, `kz_mask_image.py`, `kz_bit8_image.py`,
`kz_mask_by_member.py`.
Raw output: `analysis/evidence/skywalk-bit8-2026-11-16/`.
No device run. No vulnerability claim.

## 1. Why this pass happened

The previous checkpoint (`member-diff-drift-vs-real-2026-11-16.md`) left this
next step: *identify the callees of the 16 real IOSkywalkFamily blocks and check
whether any sits under an app-reachable socket path.* This pass did that
attribution and followed where it led. It did **not** find a socket-path caller;
it found something more systemic instead, recorded here as bounded
reconnaissance.

## 2. Correction to the earlier member-diff record

`kz_newfunc_align.py` replace lines report **block coordinates**, not function
coordinates: `szA`/`szB` are the *sum* of the sizes of the functions inside the
replace run, and the A/B addresses are first/last function starts. Mapping the
16 blocks onto `LC_FUNCTION_STARTS` gives the true extents:

| block (A start) | block sum | containing functions |
|---|---:|---|
| `0xfffffe000a2ea33c` | `0x618` | 8 funcs, first is `0x134` bytes |
| `0xfffffe000a2ea9b4` | `0x380` | 3 funcs, first is `0x8c` bytes |
| `0xfffffe000a2eae70` | `0x724` | 7 funcs |
| `0xfffffe000a2ec578` | `0x2750` | 38 funcs |
| `0xfffffe000a2f315c` | `0x3450` | 46 funcs |

So "large core routines growing +0..+60 bytes" was wrong: the blocks are
multi-function runs whose *aggregate* size changed by a few bytes. The earlier
doc's §3.1 text should be read with that correction.

## 3. Method

`kz_fn_classify.py` re-runs the normalised instruction diff inside every replace
block and splits each non-equal region into:

* **drift** — instruction *shape* identical (mnemonic + register operands +
  memory base), only immediates/displacements differ, i.e. struct-layout/ABI
  movement; and
* **code** — shape differs, i.e. genuine logic change.

`kz_delta_cluster.py` then groups the code regions by their exact masked
instruction text so one repeated idiom is counted once.

## 4. Results

### 4.1 Only the 16 shape-checked blocks carry code changes

All 154 replace blocks in IOSkywalkFamily were classified. Exactly the 16 blocks
flagged REAL by `kz_pair_shape_check.py` contain code deltas (571 instances,
106 distinct masked-text shapes); the other 138 blocks are pure drift.

Per-block totals (`classify-all-skywalk.txt`):

```
A@a2ea33c code=15 drift=17   A@a2eb9a4 code=24 drift=31
A@a2ea9b4 code=5  drift=9    A@a2ec578 code=191 drift=73
A@a2eae70 code=14 drift=22   A@a2f0ac8 code=50 drift=91
A@a2eb5f4 code=5  drift=9    A@a2f315c code=110 drift=141
...
```

### 4.2 The dominant delta is one idiom

The most common code delta (36 instances, plus ~30 near-identical siblings with
different register allocation) is:

```
A:  ldr x10,[x9] ; ldr w10,[x10,#0x20] ; cmp w10,#N
B:  ldp x12,x19,[x9] ; ldp w11,w10,[x9,#0x10]
    ldr x9,[x9,#0x18]        ; x9 = *(args+0x18)
    ldr x13,[x9,#8]
    and x13,x13,#0xfffffffffffffeff   <-- NEW
    str x13,[x9,#8]                   <-- NEW
    ldr w12,[x12,#0x20] ; cmp w12,#N
```

i.e. 27.0.1 performs the type check directly; 27.2 **first clears bit 8 of the
qword at offset +8 of the object pointed to by `[arg+0x18]`**, then does the same
type check. The rest of the instruction stream is the same logic with different
registers.

### 4.3 The idiom is image-wide and new

Counting `and xN, xN, #0xfffffffffffffeff` over every `__TEXT_EXEC` site in the
kernelcache:

| build | sites |
|---|---:|
| 24A446 (27.0.1) | **34** |
| 24B119 (27.2) | **477** |

Per member (`mask-by-member.txt`):

| member | 24A446 | 24B119 | delta |
|---|---:|---:|---:|
| `com.apple.kernel` | 16 | 169 | +153 |
| `com.apple.iokit.IOSkywalkFamily` | 0 | 107 | +107 |
| `com.apple.iokit.IOUSBHostFamily` | 0 | 48 | +48 |
| `com.apple.iokit.IOHIDFamily` | 0 | 31 | +31 |
| `com.apple.driver.AppleCentauriManager` | 0 | 17 | +17 |
| `com.apple.driver.AppleARMPlatform` | 0 | 16 | +16 |
| `com.apple.iokit.IOStorageFamily` | 0 | 16 | +16 |
| `com.apple.iokit.IOPCIFamily` | 0 | 16 | +16 |
| `com.apple.driver.AppleFirmwareKit` | 0 | 13 | +13 |
| `com.apple.driver.corecapture` | 0 | 13 | +13 |
| `com.apple.iokit.IOTimeSyncFamily` | 0 | 13 | +13 |
| *unchanged members* (AVE2 1/1, ProcessorTrace 6/6, APFS 9/9, AGXG18P 1/1, lifs 1/1) | | | 0 |

So this is a **cross-kext convention change applied to hardware user-client
dispatch thunks**, not a Skywalk-specific fix. The 34 pre-existing 27.0.1 sites
show the same idiom already existed (e.g. conditional clears of bits 8 and 9 in
the compound-VNOP path, `0xfffffe000adba93c`; CFIL verdict paths), so 27.2
extended an existing pattern to a large set of thunks.

### 4.4 What the thunks look like

Representative 27.2 thunk, `IOHIDFamily 0xfffffe000a14b74c` (`mask-hid.txt`):

```asm
mov  w19,#0x2bf ; movk w19,#0xe000,lsl#16     ; default = 0xE00002BF kIOReturnIPCError
ldp  x10,x22,[x0]                              ; [x0] -> obj, [x0+8] -> out struct
ldp  w9,w8,[x0,#0x10]                          ; two size fields
ldr  x23,[x0,#0x18]                            ; client object
ldr  x11,[x23,#8] ; and x11,#~0x100 ; str x11,[x23,#8]   <-- the new clear
ldr  w10,[x10,#0x20] ; cmp w10,#2              ; version/type check
ldr  x10,[x23,#0x10] ; cmp x10,#2
cmp  w9,#0x6c ; b.lo reject
cmp  w8,#0x3c ; b.lo reject
ldr  x0,[x23,#0x20] ; ... bl lookup
mov  x17,#0xe4fe ; blraa x20,x17               ; indirect call through arg 3
; then serialize a fixed reply template into [x22+0x1c..0x34]
```

The same shape appears in the kernel-core dispatcher
`0xfffffe000b3172ec` (0x18a4 bytes, **32** mask sites), which binary-searches a
tree of ~dozen baked vtable cookies and rejects with `0xE00002BF`
(`kIOReturnIPCError`).

## 5. What is established vs inferred

**Established**

* Between 27.0.1 and 27.2, 443 new sites appear that clear bit 8 of a qword at
  object offset +8, concentrated in per-selector external-method thunks across
  11 members plus the kernel core.
* In those thunks the cleared object is reached as `[arg+0x18]`, its first qword
  is compared against baked vtable cookies, and validation failure returns
  `kIOReturnIPCError`.
* The thunks call the real implementation indirectly (`blraa` with a fixed
  discriminator), after which they serialize a constant reply template.
* Bit 8 is already a meaningful flag elsewhere in the kernel: 376 `orr #0x100`
  and 81 `tst #0x100` sites in 24A446 (384/82 in 24B119), essentially unchanged.

**Inferred (not proven)**

* The bit is a per-client state/flag bit that 27.2 deliberately resets before
  dispatching a method. A plausible reading is "clear stale per-operation state
  on a reused client object", which would make the 27.0.1 behaviour a
  state-leak bug class. This is an interpretation, not a demonstrated effect.

**Not established**

* Which field/class the object at `[arg+0x18]` is (no symbols in the kext
  members; `LC_SYMTAB` has `nsyms=0`).
* Whether any of these thunks is reachable from an unprivileged, unsigned app —
  no caller was resolved above the thunk, and no entitlement gate was examined.
* Whether the change maps to any published advisory, and whether the 27.0.1
  behaviour is memory-unsafe (no crash, panic or type-confusion was measured;
  no device cycle was spent).
* Whether the cleared bit can be influenced by an app.

## 6. Consequence for ranking

This does **not** displace the standing state: the socket-UAF conversion blocker
(no observable field differential; type-isolated slot) and the
external-object/IOSurface ceiling remain the live limits. It adds one new
*above-the-type-wall* reconnaissance target with an unusually clean signal
(a single repeated instruction triplet, 34→477 sites), but it stays bounded
until the thunk's owning user client and its entitlement gate are named.

Do not spend a device cycle on it until §7 step 1 completes.

## 7. Next steps (bounded)

1. Resolve one thunk to its user client: decode the chained-fixups pointer that
   references e.g. `IOHIDFamily 0xfffffe000a14b74c` (raw scans find nothing, so
   the reference is a chained fixup, not an auth-table entry) and walk the
   method table to its `IOServiceOpen` class name.
2. Check the entitlement/`IOCatalogue` gate for that class in 24A446.
3. Only if app-openable, design a bounded probe that creates/destroys the client
   repeatedly and looks for an observable that depends on bit 8 (a stale-state
   detector with a positive control), rather than assuming the clear is a fix.

## 8. Tooling pitfalls found this pass
* `"__PRELINK_TEXT".find("__TEXT")` is **false** — the substring is `_TEXT`, not
  `__TEXT`. An image-wide scan filtered on `"__TEXT" in segname` silently
  skipped all 14.5 MB of `__PRELINK_TEXT` and undercounted the idiom.
  (`kz_mask_image.py` now filters on `"TEXT"`.)
* A 64-bit `and` operand must be masked with `& (2**64 - 1)`; capstone reports
  the bitmask immediate signed/oddly, so a literal compare fails.
* Capstone raises `CsError(CS_ERR_SKIPDATA)` when `.operands` is read on a
  skipdata pseudo-instruction — wrap it.

## 9. Follow-up: the thunks are IOUserClient external-method implementations, and candidate classes are named

After §7 step 1, one thunk was traced to its dispatcher statically.

### 9.1 Thunk → externalMethod

`kz_blscan_all.py` shows `IOHIDFamily 0xfffffe000a14b74c` has exactly one direct
caller, function `0xfffffe000a14b460` (sz `0x2ec`), which is an
**external-method dispatcher**:

```asm
ldr  x9,[x1,#0x18] ; ldr x9,[x9]        ; client object / vtable cookie
; binary search over ~dozen baked cookies with cmp/b.le/b.gt ...
; on match:
ldp  q0,q1,[x1] ; stp q0,q1,[sp]        ; copy input struct to stack
adrp x16,<fn> ; add x16,x16,#off
mov  x17,#<discriminator> ; pacia x16,x17   ; sign a function pointer
mov  x2,x16 ; mov x0,sp ; mov x1,x8
bl   <per-class thunk>
; default (no cookie match): bl 0xa17202c
```

So each per-selector thunk is `(x0 = input struct on stack, x1 = target, x2 =
signed function pointer)` and calls through `blraa` with that signed pointer.
The `pacia`/`blraa` pair with a per-thunk discriminator is the DriverKit /
param-block invoke pattern (`site.<Class>AsyncParamBlock` strings exist for the
same classes), i.e. these thunks marshal an async callback, not plain IPC.

### 9.2 Candidate class names (from the members' own strings)

| member | strings naming user clients |
|---|---|
| IOHIDFamily | `IOHIDEventServiceFastPathUserClient`, `IOHIDLibUserClient`, `IOHIDEventServiceUserClient`, `IOHIDResourceDeviceUserClient`, `IOFastPathUserClient`; also `%s:0x%llx %s is not entitled for IOHIDLibUserClient keyboard access` and `IOUserClientEntitlements` |
| IOUSBHostFamily | `AppleUSBHostDeviceUserClient`, `AppleUSBHostInterfaceUserClient`, `IOUSBDeviceUserClient`, plus **`UsbUserClientEntitlementRequired`** |
| IOSkywalkFamily | `IOSkywalkBSDClient`, `IOSkywalkKernelPipeBSDClient`, `IOSkywalkNetworkBSDClient` |

The HID string `... is not entitled for IOHIDLibUserClient keyboard access` and
the USB `UsbUserClientEntitlementRequired` string show these families carry
explicit entitlement gates. **That is a reachability negative signal, not a
measurement** — no open sweep was run.

### 9.3 Consequence

The owning classes are named well enough to design an open-only reachability
sweep (service names, not selectors), but nothing here changes the §5 verdict:
the bit-8 clear is still unproven as a fix, and the most affected surfaces
(HID/USB) look entitlement-gated. The kernel-core half (+153 sites) is the more
interesting remaining piece because it sits in shared IOKit glue, but its
dispatchers (`0xfffffe000b31e234`, `0xfffffe000b328164`) are reached only
through 0x2c-byte thunks whose outer entry was not resolved.

### 9.4 Next step (still bounded, static)

Resolve the outer entry of one kernel-core dispatcher: find who references the
0x2c thunk at `0xfffffe000b31e208` (raw scans find nothing, so the reference is
a chained fixup — decode the chain at the thunk's page rather than matching a
literal). If it lands on an `is_io_connect_method`/MIG boundary, the +153
kernel-core sites become reachable-surface candidates; otherwise leave closed.
