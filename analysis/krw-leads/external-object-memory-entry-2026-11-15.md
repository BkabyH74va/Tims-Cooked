# External-object primitives: memory-entry creation is NOT refused for an unsigned app

Date: 2026-11-15
Devices: secondary iPhone14,2 (iOS 27.0, 24A5390f) and primary iPhone18,1
(iOS 27.0.1, 24A446), both driven from the macOS build host over USB.
Carrier mode: `--mementry` (`carrier/AGXProbe/SockUafSpray.c:mem_entry_probe` plus
the Swift `memAliasProbe()` in `carrier/AGXProbe/ContentView.swift`).

## Why this measurement exists

A standing note in this project (and in the research skill) says
`mach_make_memory_entry_64` returns `KERN_FAILURE` "on every call" for an unsigned app,
measured on two devices, and concludes that any probe beginning by manufacturing its own
memory object is dead — closing the IOSurface-backed external-object route (a preferred
above-the-type-isolation lead class) before any harness is written.

Parallel work on this device reports the opposite. This run settles it directly.

## Method

Two independent paths in one launch:

* **C path** (`mem_entry_probe`): `vm_allocate` a 64 KiB writable region, write a marker,
  `mach_make_memory_entry_64` over it, then `vm_map` the returned handle, then read the
  marker through the second mapping.
* **Swift path** (`memAliasProbe`): same construction, but the alias uses `mach_vm_map`,
  declared with `@_silgen_name` because the SDK marks `<mach/mach_vm.h>` unsupported.
  Two alias attempts are made: `VM_FLAGS_ANYWHERE`, and `VM_FLAGS_FIXED` at
  `base + 0x40000000`. The fixed-VA round trip is the one that proves physical aliasing:
  distinct virtual addresses, same bytes.

Nothing leaves the app's address space; no device writes, no entitlements beyond the
free provisioning profile.

## Result — identical on both builds

```
[*] mementry vm_allocate -> 0 (0x0) at 0x102828000
[*] mementry make_memory_entry_64 -> 0 (0x0) handle=0x780f size=65536
[*] mementry vm_map(alias) -> 17 (0x11) at 0x0
[*] memalias make_memory_entry_64 -> 0 handle=0x781b size=0x10000
[*] memalias mach_vm_map(ANYWHERE) -> 0 at 0x102828000
[*] memalias mach_vm_map(FIXED 0x14b400000) -> 0 at 0x14b400000
[*] memalias marker base=0xc0ffee27 aliasAnywhere=0x02828000 aliasFixed=0xc0ffee27 samePage=YES
```

| step | result |
|---|---|
| `mach_make_memory_entry_64` over our own writable pages | **KERN_SUCCESS** (handle allocated, size echoed) |
| classic `vm_map` of that handle | **KERN_INVALID_ARGUMENT (17)** |
| `mach_vm_map` (ANYWHERE) | KERN_SUCCESS (returned the base VA itself) |
| `mach_vm_map` (FIXED, `base+0x40000000`) | **KERN_SUCCESS**, distinct VA |
| marker written through the base, read through the fixed alias | `0xc0ffee27` — **same physical page** |

(The `aliasAnywhere=0x02828000` field is a `%08x` truncation of `0x102828000`; the ANYWHERE
call simply reused the source VA, which is why the FIXED attempt was added.)

## Verdict

* Proven: **an unsigned sandboxed app can create its own memory entry** on iOS 27.0 and
  27.0.1, and can map it a second time at a chosen address with byte-identical contents.
  The "sandbox refuses memory-entry creation" claim is false on this configuration.
* Proven: there is an API split — the classic `vm_map` entry point is refused
  (`KERN_INVALID_ARGUMENT`) while `mach_vm_map` succeeds. The skill note that iOS "marks
  `mach_vm_*` unsupported" is about the C header's `#error`, not about the symbols:
  declaring the symbol directly works.
* Consequence for the lead ranking: the **IOSurface-backed external-object route is open**,
  and so is the ClearSword-style physical-primitive chain that starts from it (peer work
  on this device additionally reports `IOSurfaceCreate` with `IOSurfaceMemoryRegion =
  "PurpleGfxMem"`, `IOSurfacePrefetchPages`, and a distinct-VA alias over an IOSurface).
  This belongs above the `kalloc_type` wall and outranks more grooming of the socket-UAF.

## Not established

* Whether an attacker-chosen physical address can be mapped (needs the IOSurface/prefetch
  step plus a free target VA), and whether a page can be freed under a live mapping —
  those are the ClearSword race steps and were **not** exercised here.

## Device safety

No app crash, no kernel panic, no reboot on either device. Crash-report pulls before and
after: the secondary gained one `SiriSearchFeedback-*.ips` and one Retired power-session
file (Apple housekeeping); the primary gained nothing. No AGXProbe or kernel entries.
