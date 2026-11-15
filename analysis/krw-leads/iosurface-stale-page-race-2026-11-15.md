# Stale IOSurface memory entry follows reallocated physical pages — measured

Date: 2026-11-15
Devices: secondary iPhone14,2 (iOS 27.0, 24A5390f) — measured twice, both runs
consistent. Primary iPhone18,1 (24A446) — **not run** (device locked; see
`iosurface-memory-entry-alias-2026-11-15.md`).
Carrier mode: `--iosurfrace` (`iosurf_race_probe()` in `carrier/AGXProbe/SockUafSpray.c`,
dispatch `runIOSurfRaceMode()` in `carrier/AGXProbe/ContentView.swift`).
Raw console capture: `analysis/evidence/iosurface-race-2026-11-15/iosurfrace-13pro.log`.

## Question

`--iosurfphys` proved a memory entry can wrap an IOSurface's backing pages and alias
them at a chosen VA — but the pages were ones the app could already reach through the
surface's own mapping. The missing step of the ClearSword-style chain is **freeing a
page while something still names it**. A user mapping pins the object, so the variant
that matters must drop every user mapping before the surface dies and keep only the
memory object.

## Method

One C function, staged, all lines mirrored to stdout:

* **phase 0 (control)** — create a PurpleGfxMem surface, note its base,
  `CFRelease` it, spray 64 fresh surfaces, check whether the old base address is
  handed out again. This establishes that recycling is observable at all.
* **phase 1** — create a PurpleGfxMem surface (`IOSurfaceAllocSize = 0x8000`), write
  marker `0xAAAA0001` through its base mapping, read it back.
* **phase 2** — `mach_make_memory_entry_64` over that base (`VM_PROT_READ|WRITE`).
* **phase 3** — map the entry once (`VM_FLAGS_ANYWHERE`), confirm the marker reads
  back identically through the alias, then **`vm_deallocate` that alias** so no user
  mapping of the object remains.
* **phase 4** — `CFRelease` the surface (only the memory object survives), spray 64
  fresh surfaces, look for the old base among them, then map the entry **again** and
  read.
* **phase 5 (discriminator)** — the phase-4 read alone cannot distinguish "the entry
  pinned its own copy" from "the entry names pages that were reallocated", because a
  freshly recycled page still holds the old bytes until something overwrites them.
  So: write `0x77770002` through the reclaimed surface's own base mapping and read the
  stale alias again. Alias follows ⇒ same physical pages as the new owner. A second,
  different sprayed surface is written with `0x66660003` as a control.

All writes are 4 bytes into surfaces this app created. Nothing outside the app's task
address space is touched except through the stale mapping this probe deliberately keeps.

## Result — iOS 27.0, two consecutive runs (identical outcome)

```
[*] iosurfrace syms create=0x1cd01d980 id=0x1cd01d360 base=0x1cd021b20 alloc=0x1cd01f14c mach_vm_map=0x24285c814
[*] iosurfrace phase0 control base=0x104b68000 alloc=0x8000
[*] iosurfrace phase0 after release + spray(64): base_reused=YES idx=0
[*] iosurfrace surface id=0xad base=0x104b68000 alloc=0x8000 marker=0xaaaa0001 rb=0xaaaa0001
[*] iosurfrace entry(size=0x8000) -> kr=0 (0x0) handle=0x6e53
[*] iosurfrace alias1 -> kr=0 (0x0) at 0x104b70000 marker=0xaaaa0001 same=YES
[*] iosurfrace alias1 deallocated; no user mapping of the object remains
[*] iosurfrace surface CFReleased; only the memory entry remains
[*] iosurfrace spray(64): old base reclaimed=YES idx=0
[*] iosurfrace alias2(after release) -> kr=0 (0x0) at 0x10a258000 read=0xaaaa0001
[*] iosurfrace spray_base_content=0xaaaa0001
[*] iosurfrace discriminator: wrote 0x77770002 into reclaimed surface, alias now reads 0x77770002 (after control write: 0x77770002)
[*] iosurfrace VERDICT alias_follows_new_owner=YES marker_intact=no
[*] iosurfrace rc=0 recycleCtl=1 markerWrote=1 entryKR=0 alias1=1 baseReused=1 verdict=2
=== iosurfrace done ===
```

| step | result |
|---|---|
| allocator recycles the released base during a 64-surface spray (control) | **YES**, index 0, both runs |
| memory entry over the surface base | KERN_SUCCESS |
| alias before release round-trips the marker | YES |
| old base handed to a fresh surface after `CFRelease` | **YES**, index 0 |
| stale entry maps successfully *after* the surface is gone | KERN_SUCCESS |
| stale alias read before overwrite | `0xAAAA0001` (old bytes, ambiguous) |
| **stale alias after writing `0x77770002` into the reclaimed surface** | **`0x77770002`** |

## Proven

* **The memory entry survives the destruction of the IOSurface.** `mach_vm_map` on
  the surviving object after `CFRelease` returns `KERN_SUCCESS` — the object is not
  torn down with the client.
* **The entry names the physical pages, not a private copy.** When the released
  surface's pages were recycled into a new surface created afterwards, a value written
  through the new owner's mapping appeared through the stale alias. Two distinct virtual
  mappings — one made by the new surface's own client mapping, one made by the surviving
  memory object — see each other's writes. That is physical aliasing across an
  allocation generation.
* The mechanism is not confined to the first run: two consecutive launches produced
  the same verdict.

## What this is, honestly

* This is a **physical-page alias primitive**: read (and, by symmetry, write) access
  to whatever physical pages an IOSurface occupied after those pages are freed and
  reallocated. It sits above the `kalloc_type` heap wall and is reachable from an
  unsigned, sandboxed app — the first such primitive measured on this device.
* It is **not yet kernel read/write**. In both runs the reclamation target was another
  IOSurface created by the same app, whose contents the app could influence anyway.
  The value is the proof that the aliasing crosses an allocation generation rather than
  being an artefact of one live object.
* The write direction (write through the stale alias, observe through the new owner's
  mapping) is the same physical fact observed from the other side and is **not separately
  measured** here.
* Nothing about KASLR, kernel-task port, or a kernel object type selection has been
  established. Turning this into kR/W needs a grooming step that lands those pages in a
  kernel-owned object, which is unmeasured.

## Interpretation for the lead ranking

This closes the "free a page under a live mapping" gap listed in
`external-object-memory-entry-2026-11-15.md`, at least for the
user-side-of-the-kernel case: the naming object can outlive its client and follow the
pages. The external-object route stays the top open lead, and its next question changes
from "can we alias freed pages?" (yes) to "**what can we get those pages reallocated
into?**"

## Next concrete steps

1. **Reclaim-type expansion.** Repeat the phase-4 spray with allocations other than
   IOSurfaces — large `mmap`/`malloc` blocks, `Data`/`NSMutableData`, file-backed
   `mmap`s, and IOSurface sizes spanning multiple allocation classes — and record which
   ones land on the old base *and* become visible through the stale alias. The goal is a
   reclaimer that is not itself an IOSurface, i.e. a step toward arbitrary kernel memory.
2. **Write-direction confirmation.** Write through the stale alias and read through the
   reclaimed surface's own mapping (and vice versa as a control).
3. **Primary device.** Re-run both `--iosurfphys` and `--iosurfrace` on iPhone18,1
   (24A446) once it is unlocked; both modes are benign and bounded.
4. **Static fix-site hunt.** Diff the IOSurface kext between 24A446 and 24B119 around
   the memory-entry / `IOSurfacePrefetchPages` / teardown paths: if Apple changed the
   lifetime handling of memory entries over surfaces, that change *is* the bug class we
   just demonstrated dynamically.

## Device safety

Two clean runs on the secondary; the app completed normally each time and remained
running afterwards. SpringBoard and backboardd present, device still connected and
responsive. No kernel panic, respring, or reboot observed. Primary untouched (launched
refused while locked). One earlier `--iosurfphys` run crashed the app on our own
out-of-bounds read; fixed, and no kernel involvement.
