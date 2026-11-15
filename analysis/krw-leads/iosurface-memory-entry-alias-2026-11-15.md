# IOSurface-backed memory entry + distinct-VA alias — measured on iOS 27.0

Date: 2026-11-15
Devices: secondary iPhone14,2 (iOS 27.0, 24A5390f) — measured. Primary iPhone18,1
(iOS 27.0.1, 24A446) — **blocked**: the device is locked and
`devicectl device process launch` refuses with
`SBMainWorkspace ... Locked ("Unable to launch ... because the device was not, or
could not be, unlocked")`; there is no remote unlock path, so no primary run was
attempted beyond the two refused launches.
Carrier mode: `--iosurfphys` (`runIOSurfPhysMode()` in `carrier/AGXProbe/ContentView.swift`).
This is step 2 of `analysis/krw-leads/external-object-memory-entry-2026-11-15.md`.

## Question

`--mementry` proved an unsigned app can wrap **its own anonymous pages** in a
memory entry and alias them at an address of its choosing. Those pages were ones
the app already owned, so the primitive was self-referential. The open question
was whether the same construction wraps pages the kernel/IOSurface owns — which
is what a physical-page chain needs.

## Method

Two surfaces created in one launch:

* **A** — `IOSurfaceCreate` with `IOSurfaceMemoryRegion = "PurpleGfxMem"`,
  width 64, height 2, `kCVPixelFormatType_32BGRA`, bpe 4, row 256,
  `IOSurfaceAllocSize = 2 * vm_page_size`.
* **C** — identical shape with no region key (control).

Then, per stage, with every result logged separately:

1. write distinct markers (`0xAAAA0001` / `0xBBBB0002`) through each surface's own
   base-address mapping and read them back;
2. `mach_make_memory_entry_64(mach_task_self(), size=allocA, offset=baseA,
   VM_PROT_READ|WRITE)` over **surface A's base**;
3. reserve a VA with `vm_allocate(ANYWHERE)`, `vm_deallocate` it, then
   `mach_vm_map(VM_FLAGS_FIXED)` the returned memory object at that reserved VA
   and read the marker back through the alias;
4. request an **oversize** entry (`8 * allocA = 0x40000`) over the same base and
   compare the requested size against the size the call returns, to test whether
   the entry can wrap neighbouring allocations;
5. `IOSurfacePrefetchPages(A)` via `@_silgen_name`.

Nothing leaves the app's task address space; the only writes are the four marker
bytes in surfaces the app created.

## Result — secondary, iOS 27.0 (clean run, app exited normally)

```
[*] iosurfphys start: memory entry over an IOSurface base + distinct-VA alias
[*] iosurfphys A(PurpleGfxMem) id=22 base=0x1031bc000 alloc=0x8000
[*] iosurfphys C(control)      id=150 base=0x1031c8000 alloc=0x8000
[*] iosurfphys |delta(A-C)| = 0xc000 (C is above A)
[*] iosurfphys stage1 marker A=0xaaaa0001 (read back 0xaaaa0001) C=0xbbbb0002 (read back 0xbbbb0002)
[*] iosurfphys stage2 make_memory_entry_64(size=0x8000) -> kr=0 (0x0) handle=0x6903
[*] iosurfphys stage3 reserve -> kr=0 (0x0) slot=0x1031d4000
[*] iosurfphys stage3 mach_vm_map -> kr=0 (0x0) at 0x1031d4000
[*] iosurfphys stage3 marker source=0xaaaa0001 aliasFixed=0xaaaa0001 samePhysicalPage=YES
[*] iosurfphys stage4 make_memory_entry_64(requested=0x40000) -> kr=0 (0x0) handle=0x6803 returned=0x8000 clamped=YES
[*] iosurfphys stage4 mach_vm_map -> kr=0 (0x0) at 0x1031d4000
[*] iosurfphys stage4 oversize alias: off0=0xaaaa0001 off1alloc=n/a (beyond mapping) n/a (|delta| beyond mapping)
[*] iosurfphys stage5 IOSurfacePrefetchPages(A) -> kr=0 (0x0)
=== iosurfphys done ===
```

(An earlier run of the same mode crashed with SIGSEGV in the *app*, at our own
out-of-bounds read of the stage-4 alias; the read was indexing past a mapping
whose size the kernel had clamped. Fixed by bounds-checking every read against
the returned size. No kernel involvement — see Device safety.)

## Proven

* **`IOSurfaceCreate` accepts `IOSurfaceMemoryRegion = "PurpleGfxMem"`** on
  iOS 27.0, for a 0x8000-byte surface.
* **`mach_make_memory_entry_64` succeeds over the base address of that
  IOSurface** (`kr=0`, handle allocated, size echoed). The previous "sandbox
  refuses memory-entry creation" note was already refuted for our own pages;
  this extends it to kernel-allocated IOSurface backing pages.
* **The returned object maps at an address of our choosing** (`VM_FLAGS_FIXED`
  at a VA we reserved), and the alias reads back exactly the marker written
  through the surface's own mapping — **distinct virtual addresses (0x1031bc000
  vs 0x1031d4000), same physical page**. So the external-object route is not
  limited to anonymous app memory.
* **Oversize requests are clamped.** Requesting `8 * alloc = 0x40000` over the
  same base returns size `0x8000`; the entry cannot be widened to cover
  neighbouring allocations through the size argument.
* `IOSurfacePrefetchPages` resolves and returns `KERN_SUCCESS` on the
  PurpleGfxMem surface.

## Suspected / not established

* **Not established: that the alias reaches memory the app does not own.** The
  marker round-trip only proves both mappings name the same pages; those pages
  are ones the app can already write through the surface's own base mapping.
  "IOSurface memory region" selects an allocation pool, not a proof of GPU-only
  residency — no GPU VA access was exercised here.
* **Not established: mapping at an attacker-chosen *physical* address, and
  freeing a page under a live mapping.** Both remain the missing steps of the
  ClearSword-style chain. Clamping closes the obvious "widen the entry" route.
* The route from "alias of a live surface's pages" to "read/write of arbitrary
  freed physical pages" needs the kernel itself to hold a stale mapping after
  the surface is torn down; a user-held alias mapping pins the pages by
  definition, so that experiment must remove the user mapping first and keep
  only the memory object. Not yet run.

## Interpretation for the lead ranking

This confirms half of step 2 from `external-object-memory-entry-2026-11-15.md`:
the external-object/memory-entry construction reaches **IOSurface-backed**
pages from an unsigned sandboxed app, which is above the `kalloc_type` heap
wall, and it is now reproduced by direct measurement rather than inferred from
peer reports. It is **not** a kernel read/write primitive: nothing observed here
reads or writes a byte the app could not already reach through the surface's own
mapping, and the size-clamp closes the widening avenue. The remaining gap is the
stale-page step.

## Next concrete step

Extend the probe to the stale-page race, removing the user alias before the
surface dies so only the memory object remains:

1. create surface A, write a marker, take entry E over its base;
2. map E once to confirm aliasing, then **`vm_deallocate` that mapping**;
3. `CFRelease` surface A;
4. spray fresh IOSurfaces to reclaim the pages;
5. map E again and read: marker intact ⇒ the entry retains the object; content
   matching a freshly sprayed surface ⇒ the entry names freed physical pages
   that have been reallocated (the primitive).

Because step 3 needs real CF ownership, implement it in C (`SockUafSpray.c`
style, `IOSurfaceCreate` + `CFRelease`, `mach_vm_map` obtained with `dlsym`),
not in Swift where the imported `IOSurfaceRef` release semantics are unclear.

## Device safety

Secondary: two runs. Run 1 crashed the app (SIGSEGV) at our own out-of-bounds
read of the stage-4 alias — an app bug, fixed and re-run cleanly. No kernel
panic, no respring, no reboot observed; the device remained connected and
responsive, and the follow-up run completed normally. Primary: untouched
(launches refused while locked).

## Related

* `analysis/krw-leads/external-object-memory-entry-2026-11-15.md` — the
  original `--mementry` result and the standing-blocker refutation.
* `analysis/f1/GEOMETRY-PROBE-RESULTS.md` — IOSurface geometry probes and the
  disclosed backing-pointer layout.
