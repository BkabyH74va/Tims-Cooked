# HID half of the 27.2 bit-8 surface: selector map measured, uniform refusal

Date: 2026-11-16
Builds: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target, primary),
`firmware/24B119/kernelcache.release.macho` (iOS 27.2, fixed reference)
Devices: iPhone 13 Pro (iPhone14,2, iOS 27.0 build 24A5390f, secondary) and
iPhone 18,1 (iOS 27.0.1 build 24A446, primary)
Tooling added: `tools/kz-static-diff/kz_blw_scan.py`, `kz_flag_bits.py`
New carrier mode: `--hidsel` (`bench100HIDSel()` + `sigChar`/`callPatched`)
Raw logs: `analysis/evidence/hidsel-2026-11-16/`

## 1. Why this pass happened

The previous checkpoint (`skywalk-bit8-dispatch-flag-2026-11-16.md` §11.3) left
this step: *resolve the HID user client that owns the open type-2 service,
enumerate its external-method selectors, and see whether any selector lands in a
changed virtual method.* `--opencand` had already measured the four HID
event-driver services as **openable at client type 2**, the first openable surface
among the families whose 27.2 thunks clear bit 8 of `[object+8]`.

This pass did the static attribution and then measured the surface on both phones.
Result: **the external methods of every openable HID service refuse every selector
uniformly**, while a statically-recovered control client answers. Bounded negative;
the changed thunks are not shown reachable from any measured HID entry point.

## 2. Static attribution

### 2.1 The changed thunks and their single dispatcher

`mask-hid.txt` lists the 31 IOHIDFamily functions carrying the new
`and xN,xN,#~0x100` site (24B119): `0xfffffe000a14b74c` … `0xfffffe000a14ed4c`.

`kz_blw_scan.py` (new — word-level BL/B decoder, immune to the linear-sweep
desynchronisation that made the older `kz_blscan_all.py` miss real sites) shows:

| function | direct callers |
|---|---|
| `0xfffffe000a14b74c` (representative changed thunk) | exactly 1: `0xfffffe000a14b460` |
| `0xfffffe000a14b460` (sz `0x2ec`) | exactly 1: `0xfffffe000a14b430` (sz `0x30`) |

`0xfffffe000a14b460` is an **external-method dispatcher**: it loads
`x9 = [args+0x18]` (the target object), then `ldr x9,[x9]` — the target's vtable
pointer — and binary-searches ~11 baked 64-bit cookies
(`0xbe04e3d42572fd52`, `0xca9744a1af98f7de/f7df`, `0xec13cf336ecc6eacc`,
`0xf964ed7a299eb3a5`, `0x9f3263b463025b4e/5b4f`, `0x9bcf029fa80af1b5`,
`0x9cd93af0504ec45d`, `0xa8ccbd83dbbed4cd`, `0xc4a89d6fd6fd065c`). On a match it
copies the args struct to the stack, signs a per-class implementation pointer with
`pacia`, and calls it. On **no** match it branches to `0xfffffe000a14b72c`, which
calls the auth-stub `0xfffffe000a17202c`.

`0xfffffe000a17202c` is one entry of a stub block (`adrp`+`add`+`ldr`+`braa`,
16 bytes each) whose GOT slot `0xfffffe0008339d18` decodes to kernel-core
`0xfffffe000b3172ec` — i.e. the cookie-mismatch default routes into shared IOKit
glue.

Note the cookie pairs differing only in the low bit (`…fd52`/`…fd53`,
`…f7de`/`…f7df`, `…5b4e`/`…5b4f`): a PAC-signed pointer whose address component
differs by one byte cannot be two distinct vtables, so these constants are more
likely **per-object type/version tags than plain vtable addresses**. The
"vtable cookie" reading in the earlier doc is therefore not settled.

### 2.2 The entry trampoline sits at slot 12 of a real vtable

`kz_member_vtable.py find 24B119 com.apple.iokit.IOHIDFamily 0xfffffe000a14b430`
returns exactly one slot: `0xfffffe000832f978`, i.e. index 12 of the table whose
address point is **`0xfffffe000832f918`**. The two words immediately before the
address point (`0x832f908`, `0x832f910`) are zero — the Itanium offset-to-top / RTTI
pair — which confirms a C++ vtable rather than a flat dispatch array. Its other
slots mix kext implementations (`0xa125214`, `0xa14b430`, `0xa125674`, …) with
shared kernel-core ones (`0xb2be688`, `0xb2bb330`, `0xb2be404`, …).

`0xfffffe000a14b430` itself has **no** direct caller, **no** chained-fixup
reference, and **no** plain or auth pointer slot pointing at the vtable address
anywhere in the member (raw-VA scan, low-32-offset scan, `adrp+add`/`adrp+ldr` scan
all empty). The owning class name therefore remains unresolved.

### 2.3 Bit 8 is neither set nor tested inside IOHIDFamily

`kz_flag_bits.py 24B119 com.apple.iokit.IOHIDFamily 8` finds only 5 sites, all on
**32-bit** registers (`orr w8,w5,#0x100`), unrelated to the qword at `[obj+8]`.
So within the kext nothing sets or reads the bit that the 31 thunks clear; the
flag's producer and consumer live elsewhere (shared glue or another owner), which
is why the semantics stay inference.

## 3. Device measurement

Mode `--hidsel` was built into a **dev-signed carrier and run on both devices**
(`BUILD SUCCEEDED`, install + launch over USB, container pulled afterwards).

Design points that make the result interpretable:

* **positive control** — `AppleJPEGDriver`, whose dispatch table was recovered
  statically (selectors 1/3 take 0x58-byte structs, 4/5 take 0x1000);
* **four shapes** derived from the changed thunk itself, including the one it
  requires (`structureInput ≥ 0x6c`, `structureOutput ≥ 0x3c`, `u32` at input
  `+0x20` equal to 2);
* **input-size sweep** up to 0x200 (step 8) for selectors 0, 1, 2 and 12;
* **compact per-selector signature** so uniformity is printed, not inferred.

### 3.1 Control passes

```
[5:06:19 PM] control class AppleJPEGDriver
[5:06:19 PM] control opened type 0
[5:06:19 PM]    jpeg sel 0 in 0x0/out 0x0     -> ok            <- kr 0
[5:06:19 PM]    jpeg sel 1 in 0x58/out 0x58   -> kr=-536870196  (0xE00002CC)
[5:06:19 PM]    jpeg sel 3 in 0x58/out 0x58   -> kr=-536870196
[5:06:19 PM]    jpeg sel 4 in 0x1000/out 0x1000 -> Error
[5:06:19 PM]    jpeg sel 5 in 0x1000/out 0x1000 -> kr=-536870196
```

So `IOConnectCallMethod` works, per-selector discrimination works, and non-
`BadArgument` answers are observable on both devices.

### 3.2 Every openable HID service refuses everything

Openable services (class name contains `hid`):

| device | opened |
|---|---|
| 13 Pro (24A5390f) | `AppleSPUHIDDriver`, `AOPTouchHIDDriver`, `IOHIDEventDriver`, `AppleProxHIDEventDriver` (4) |
| 17 Pro (24A446) | `AppleSPUHIDDriver`, `IOHIDEventDriver`, `AppleSphinxProxHIDEventDriver` (3) |

For every one of them, selectors `0..0x3f` × the four shapes returned the
signature `BBBB` (`kIOReturnBadArgument`) uniformly, including selector `0x100`
(far beyond any plausible dispatch table). The size sweep found no
non-`BadArgument` shape up to `in=0x200`, `out ∈ {0, 0x3c}` for selectors
0, 1, 2, 12:

```
[5:06:19 PM] IOHIDEventDriver t2 non-uniform=0
[5:06:19 PM]    sweep sel 0: none up to 0x200
[5:06:19 PM]    sweep sel 1: none up to 0x200
[5:06:19 PM]    sweep sel 2: none up to 0x200
[5:06:19 PM]    sweep sel 12: none up to 0x200
```

Identical output on the 13 Pro. The probe completed (`??? done`), the app process
stayed alive, and both devices remained enumerated; no panic, respring or reboot
was observed.

## 4. Established vs inferred

**Established**

* The 31 changed IOHIDFamily thunks share one external-method dispatcher
  (`0xfffffe000a14b460`), reached only through `0xfffffe000a14b430`.
* That entry trampoline occupies slot 12 of a genuine C++ vtable at
  `0xfffffe000832f918` in the kext's `__DATA_CONST`, and nothing in the image
  references that vtable address literally.
* IOHIDFamily never sets or tests bit 8 of a 64-bit field anywhere in the member.
* On both builds, every openable HID service returns `kIOReturnBadArgument` for
  every selector/shape tried, while a control client on the same transport returns
  distinguishable codes including `kr=0`.

**Inferred (not proven)**

* The uniform refusal is most likely the dispatcher's cookie-mismatch default path
  (which routes to kernel-core `0xfffffe000b3172ec`) rather than shape rejection,
  because even `selector 0x100` is refused identically. This is an interpretation:
  the alternative (an exact-shape requirement outside the swept range) is not
  excluded, and the sweep covered only `out ∈ {0, 0x3c}` and `in ≤ 0x200`.

**Not established**

* Which class owns vtable `0xfffffe000832f918`, and whether any of its instances is
  reachable from an unsigned app.
* Whether bit 8 is attacker-influenceable at all.
* Any mapping of the bit-8 change to an advisory.

## 5. Consequence for ranking

The HID half of the bit-8 surface does **not** currently convert into an
app-reachable trigger: the only openable clients refuse every measured entry point,
and the one surface that does answer (`AppleJPEGDriver`) is unchanged between
builds. Combined with the earlier bounded negatives, the bit-8 idiom stays
reconnaissance, not a lead with a trigger.

The **kernel-core half** (+153 mask sites, slot 12 of kernel-core vtables) remains
the more interesting piece and is still blocked on the same two unknowns: the
owning class names (no literal vtable reference) and the flag's setter/consumer.

Do not spend another HID device cycle without either a named class or a matching
client type.

## 6. Reproduction

```
# sources (self-consistent pair: HEAD carrier + this probe)
bash ~/build_race.sh                       # or the isolated build in §7
xcrun devicectl device install app --device <udid> \
  .build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device process launch --device <udid> --terminate-existing \
  --console com.bench27.agxprobe --hidsel
# then pull Documents/session-*.log from the app data container
```

## 7. Workspace hazard found (operational, not research)

The shared checkout's `carrier/AGXProbe/ReachabilityProbe.swift` had **uncommitted
deletions** that removed `bench100`–`bench107` while `ViewController.swift`
(committed, unmodified) still references them. The shared tree therefore only
compiled because Xcode reused stale objects; a clean build failed with
`has no member 'bench105HIDProperties'` et al.

This run built from an **isolated copy** (`/tmp/hidselproj` on the build host) using
the committed HEAD versions of `ReachabilityProbe.swift`/`ContentView.swift` plus
the new probe, so the shared working tree was not touched. A second trap: the
keychain re-locks between SSH invocations, and a detached build that does not
unlock inside its own process tree fails codesign with `errSecInternalComponent`
even when `security show-keychain-info` reports `no-timeout`. The unlock must run
in the same process tree as `xcodebuild`.
