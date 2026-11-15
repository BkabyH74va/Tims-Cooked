# Cross-type reclaim of freed IOSurface pages — measured negative

Date: 2026-11-15
Device: secondary iPhone14,2 (iOS 27.0, 24A5390f) — one run, 13 rounds.
Primary iPhone18,1 (24A446): **not run**, still locked (`SBMainWorkspace … Locked`).
Carrier mode: `--iosurfreclaim` (`iosurf_reclaim_probe()` in
`carrier/AGXProbe/SockUafSpray.c`, dispatch `runIOSurfReclaimMode()` in
`carrier/AGXProbe/ContentView.swift`).
Raw console capture: `analysis/evidence/iosurface-reclaim-2026-11-15/iosurfreclaim-13pro.log`.

## Question

`analysis/krw-leads/iosurface-stale-page-race-2026-11-15.md` proved a surviving
memory entry names the *physical* pages of a destroyed PurpleGfxMem IOSurface and
follows them into a NEW IOSurface. The open question listed there is: **what can
those freed pages be made to be reallocated into?** This probe measures every
reclaimer type reachable from an unsigned sandboxed app.

## Method

For each (surface kind, reclaimer kind) pair the probe:

1. creates a fresh IOSurface (either `IOSurfaceMemoryRegion = "PurpleGfxMem"` or a
   plain surface with identical geometry), writes a marker through its base;
2. wraps the base in a memory entry (`mach_make_memory_entry_64`);
3. maps the entry once to confirm aliasing, then **`vm_deallocate`s that alias**, so
   no user mapping of the object remains;
4. `CFRelease`s the surface;
5. sprays 48 blocks of one reclaimer kind, each filled with a unique tag
   (`0x5A5A0000 | kind<<12 | idx`) — `vm_allocate`, anonymous `mmap`, `malloc`,
   file-backed `mmap(MAP_SHARED)`, or another IOSurface;
6. maps the surviving entry again and **scans the entire object word-by-word** for
   any recorded tag.

A tag observed through the stale alias is direct proof that an allocation outside
the IOSurface allocator landed on the released physical pages. As a positive
control, an IOSurface reclaimer is included in every set. All writes are 4 bytes
into blocks this app owns; reads through the stale alias are bounded to the
object size.

## Result — 13 rounds

| round | surface | reclaimer | made | old base reused by a sprayed surface | tag visible through stale alias | marker intact |
|---|---|---|---|---|---|---|
| 0 | plain 0x8000 | `vm_allocate` | 48 | n/a | **no** | YES |
| 1 | plain 0x8000 | `mmap` anon | 48 | n/a | **no** | YES |
| 2 | plain 0x8000 | `malloc` | 48 | n/a | **no** | YES |
| 3 | plain 0x8000 | file `mmap` | 48 | n/a | **no** | YES |
| 4 | plain 0x8000 | IOSurface | 48 | **YES** idx=0 | **no** | YES |
| 5 | PurpleGfxMem 0x8000 | `vm_allocate` | 48 | n/a | **no** | YES |
| 6 | PurpleGfxMem 0x8000 | `mmap` anon | 48 | n/a | **no** | YES |
| 7 | PurpleGfxMem 0x8000 | `malloc` | 48 | n/a | **no** | YES |
| 8 | PurpleGfxMem 0x8000 | file `mmap` | 48 | n/a | **no** | YES |
| 9 | PurpleGfxMem 0x8000 | IOSurface 0x8000 | 48 | **YES** idx=0 | **YES** kind=5 idx=0 off=0 | no |
| 10 | PurpleGfxMem 0x4000 | IOSurface 0x4000 | 48 | **YES** idx=0 | **YES** kind=5 idx=0 off=0 | no |
| 11 | PurpleGfxMem 0x8000 | IOSurface 0x8000 | 48 | **YES** idx=0 | **YES** kind=5 idx=0 off=0 | no |
| 12 | PurpleGfxMem 0x10000 | IOSurface 0x10000 | 48 | **YES** idx=0 | **YES** kind=5 idx=0 off=0 | no |

Representative log lines:

```
[*] iosurfreclaim r9 region=1 alloc=0x8000 id=0x9e base=0x103390000 marker=0xc0de0001 rb=0xc0de0001
[*] iosurfreclaim r9 entry(size=0x8000) -> kr=0 (0x0) handle=0x7713
[*] iosurfreclaim r9 alias1 kr=0 marker=0xc0de0001 same=YES
[*] iosurfreclaim r9 surface released; only the entry remains
[*] iosurfreclaim r9 sweep kind=5 made=48
[*] iosurfreclaim r9 old base handed to sprayed surface idx=0
[*] iosurfreclaim r9 map entry -> kr=0 (0x0) at 0x1087b8000
[*] iosurfreclaim r9 MATCH kind=5 idx=0 off=0x0 val=0x5a5a5000
[*] iosurfreclaim WRITE-DIR: wrote 0x88880009 through stale alias, reclaimed surface reads 0x88880009 -> CONFIRMED
[*] iosurfreclaim r9 VERDICT hit=1 kind=5 idx=0 off=0x0 word0=0x5a5a5000 marker_intact=no
```

and the negative rounds:

```
[*] iosurfreclaim r6 sweep kind=2 made=48
[*] iosurfreclaim r6 map entry -> kr=0 (0x0) at 0x1087b8000
[*] iosurfreclaim r6 no tag visible; word0=0xc0de0001
[*] iosurfreclaim r6 VERDICT hit=0 ... marker_intact=YES
```

## Proven

* **No app-reachable allocation type reclaims the freed pages.** Across 8 rounds
  (4 reclaimer kinds × both surface kinds), `vm_allocate`, anonymous `mmap`,
  `malloc` and file-backed `mmap` never produced a single tag match through the
  stale alias, while the IOSurface control matched in 4/4 applicable rounds. The
  detector is positive by construction: the same scan logic sees the IOSurface
  control immediately, so the negatives are not a blind detector.
* **Plain (non-region) IOSurface pages are pinned by the surviving entry.** When
  the base *virtual address* was handed to a fresh plain surface (round 4,
  `old base handed to sprayed surface idx=0`), the stale alias still read the old
  marker and none of the new surface's tag. Base-VA reuse is not physical-page
  reuse for plain surfaces.
* **PurpleGfxMem pages live in a shared backing object.** After release, a fresh
  PurpleGfxMem surface receives the same physical pages and the stale alias sees
  its contents — at three allocation sizes (0x4000, 0x8000, 0x10000).
* **Write direction confirmed.** Writing `0x888800xx` through the stale alias and
  reading through the reclaimed surface's own base returns the same value in all
  four PurpleGfxMem rounds. The alias is bidirectionally live with the new owner,
  not just readable.

## Honest limits

* This is **bounded negative for app-level cross-type reclamation**, not a proof
  that nothing outside IOSurface can ever take those pages. Kernel-internal
  reclaimers were not tested and cannot be driven from this harness; a
  kernel-owned allocation of the same class could in principle land on the pages.
* The reclaimer blocks were allocated *after* the release. A kernel allocation
  that happened concurrently with the surface teardown is a different window.
* Still no KASLR slide, kernel-task port, or kernel object selection. Not kR/W.
* One run on one device; the primary (24A446) remains unmeasured because it is
  locked.

## Interpretation

The external-object route is narrower than the stale-page result suggested: the
memory entry does not expose freed pages to the general page pool, it exposes a
range of a specific backing object that only the IOSurface/GPU allocator
sub-allocates. The practical ceiling of this primitive is therefore the set of
IOSurface-shared pages — i.e. a physical alias inside IOSurface's own region,
unless a kernel object can be induced to take those pages.

Next concrete actions:

1. Re-run `--iosurfphys` and `--iosurfrace` on the primary (24A446) when unlocked;
   both modes are benign and bounded.
2. Static: identify the shared PurpleGfxMem backing object and its allocator in the
   IOSurface/IOGPU kexts between 24A446 and 24B119 (does 27.2 change anything about
   how these ranges are handed out?), and whether any non-IOSurface client can
   allocate from the same object.
3. Socket-UAF: instrument the reclaimed datagram socket's API-visible fields
   against a no-race control, to name the corrupted field
   (`analysis/socket-uaf-crosstype-2026-11-14.md` next step).

## Device safety

One clean run on the secondary; the app completed normally and stayed alive
(devicectl reported `App terminated due to signal 15` when the console session was
closed, which is the wrapper's own SIGTERM, not a crash). No kernel panic, respring
or reboot observed. Primary untouched.

## Static follow-up: where `PurpleGfxMem` comes from

A raw search of the 24A446 kernelcache for `PurpleGfxMem` finds four occurrences,
each resolved to its fileset member:

| file off | VA | member | context |
|---|---|---|---|
| `0x651a35` | `0xfffffe0007655a35` | `com.apple.driver.AppleMobileDispH18P-DCP` | carveout name table `PurpleGfxMem` / `PurpleGfxMem%u`; adjacent `IOMFB %s: failed (no carveout)` and `read_carveout` |
| `0x9c97ff` | `0xfffffe00079cd7ff` | `com.apple.iokit.IOMobileGraphicsFamily` | `PurpleGfxMem` beside `IOMFB: %s : getMemoryRegion Failed for Surface = 0x%p, sid ...` |
| `0xa1ba17` | `0xfffffe0007a1fa17` | `com.apple.iokit.IOSurface` | region-name table `ScalableMemory` / `PurpleGfxMem` / `(unknown)` |

Code sites referencing those strings (numpy-free ADRP+ADD/LDR scan over each
member's own `__TEXT*`, capstone `skipdata=True`, immediates masked):

* DCP `0xfffffe000920e818` (sz `0x88`) references both carveout strings at
  `+0x4c`/`+0x64`: it falls back to the literal `PurpleGfxMem` when the indexed
  carveout lookup fails, otherwise formats `PurpleGfxMem%u` with an index.
* IOMobileGraphicsFamily `0xfffffe000a18ec14` (sz `0x44`) lazily creates the
  symbol used by its `getMemoryRegion` failure log.
* IOSurface `0xfffffe000a340d50` (sz `0x4c`) builds the `IOSurfaceMemoryRegion`
  property symbol; the surface-create path `0xfffffe000a32b7b4` (sz `0x3710`)
  consumes it at `+0x33f4`/`+0x349c`.

Interpretation: `PurpleGfxMem` is a **display-controller carveout** name
registered by `AppleMobileDispH18P-DCP`; IOSurface carries it in its region-name
table and the IOMobileGraphicsFamily/IOMFB client allocates surfaces out of that
carveout. This matches the device result exactly: those pages are
sub-allocations of one shared carveout vm_object, so IOSurface-to-IOSurface
recycling aliases physically, while plain surfaces and ordinary app allocations
never enter that object. The carveout's other consumer is the display pipeline
(framebuffer pages), not CPU kernel objects — which is consistent with the
cross-type sweep finding no non-IOSurface reclaimer.
