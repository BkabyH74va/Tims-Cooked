# IOSurface memory regions — `ScalableMemory` measured, physical reuse stays carveout-only

Date: 2026-11-15
Devices: secondary iPhone14,2 (iOS 27.0, 24A5390f) and primary iPhone18,1
(iOS 27.0.1, 24A446), both driven from the macOS build host over USB.
Carrier mode: `--iosurfreclaim` (`iosurf_reclaim_probe()` /
`rcl_round()` in `carrier/AGXProbe/SockUafSpray.c`), extended this session to
sweep three IOSurface memory regions instead of two.
Raw logs: `analysis/evidence/iosurface-scalable-2026-11-15/`.

## Question

The external-object primitive (`--iosurfrace`) proves that a memory entry over
an IOSurface keeps naming the *physical* pages after the surface client is
freed, and that a fresh **PurpleGfxMem** surface takes those pages. That
reuse property is the only reason the primitive is interesting at all — if any
other app-reachable allocator could take those pages, the stale alias would
point into general-purpose memory instead of one GPU carveout.

PurpleGfxMem is not the only region name the IOSurface kext knows. This run
asks: **does a surface created with a different region name behave the same
way, and can a freed region surface's pages be taken by a surface of a
*different* region?**

## Static: the region names that exist

The `com.apple.iokit.IOSurface` member has a small set of region-name strings
in `__TEXT`:

| string | VA (24A446) |
|---|---|
| `IOSurfaceMemoryRegion` (property key) | `0xfffffe0007a19786` |
| `IOSurfaceSmaMemoryRegion` | `0xfffffe0007a1c17f` |
| `ScalableMemory` | `0xfffffe0007a1fa08` |
| `PurpleGfxMem` | `0xfffffe0007a1fa17` |
| `(unknown)` | `0xfffffe0007a1fa30` |

Code references resolved with an ADRP+ADD scan (`scratch/adrp_refs2.py`, capstone):

* `ScalableMemory` is referenced once, at `0xfffffe000a344ec8`, inside
  `0xfffffe000a344e70` (size `0x14c`). That function looks the name up
  (`bl 0xfffffe000a344d08`), then calls a vtable method at `+0xd0` on the
  returned object with the caller's parameters; if the lookup fails it logs
  `"Failed to install %s memory region; checking in anyway"` and falls back.
  This is the surface-create path consuming the app-supplied
  `IOSurfaceMemoryRegion` value.
* `PurpleGfxMem` is referenced once, at `0xfffffe000a3431c8`, inside
  `0xfffffe000a343034` (size `0x294`), a property-update path that walks the
  client's surface list and installs the region name on entries whose
  properties contain `vram` / `sma` keys.
* `(unknown)` has no direct reference (it is the fallback label of the same
  name table).

So `ScalableMemory` is a first-class region value, not a leftover string.

## Carrier change (this commit)

`iosr_make_sized(use_region, alloc)` now maps the selector:

| selector | `IOSurfaceMemoryRegion` value |
|---|---|
| 0 | *(absent — plain/default)* |
| 1 | `PurpleGfxMem` |
| 2 | `ScalableMemory` |

`iosurf_reclaim_probe()` now runs 23 rounds:

* sets 1–3 — victims of region 0, 1 and 2 at `0x8000`, each against five
  reclaimers (`vm_allocate`, anonymous `mmap`, `malloc`, file-backed `mmap`,
  same-region IOSurface spray);
* set 4 — five cross-region controls: victim `{plain, Purple, Scalable}` sprayed
  with plain/Purple/Scalable surfaces;
* set 5 — the existing PurpleGfxMem size-class recycling control
  (`0x4000`/`0x8000`/`0x10000`).

The marker word was widened to `0xC0DE0000 | (region & 3)` so region 2 is
distinguishable from plain.

## Result — identical on both builds

```
round  victim spray  sweeper   stage
...
10     2      2      vm       0
11     2      2      mmap     0
12     2      2      malloc   0
13     2      2      file     0
14     2      2      iosrf    0
15     2      0      iosrf    0
16     2      1      iosrf    0
17     2      2      iosrf    0
18     1      2      iosrf    0
19     0      2      iosrf    0
20     1      1      iosrf    class 0x4000  1
21     1      1      iosrf    class 0x8000  1
22     1      1      iosrf    class 0x10000 1
```

* Every ScalableMemory victim round (10–17, 15–17, 19) reports
  `no tag visible; word0=0xc0de0002` and `marker_intact=YES`. Nothing took
  those pages: not `vm_allocate`, `mmap`, `malloc` or file-backed mappings,
  and not fresh surfaces of *any* region.
* The PurpleGfxMem positive controls still hit: round 9 and rounds 20–22 show
  `MATCH kind=5 idx=0 off=0x0` with `word0=0x5a5a5000` and
  `marker_intact=no`, and the write-direction confirmation
  (`wrote 0x888800xx through stale alias, reclaimed surface reads 0x888800xx`)
  is reproduced at every size class.
* Creation of ScalableMemory surfaces succeeds (the marker written through the
  base address reads back as `0xc0de0002` on the first try), so the negative
  is not a refusal of the region name.
* On several ScalableMemory rounds the log also shows
  `old base handed to sprayed surface idx=0` while the stale entry still reads
  the old marker — i.e. the virtual base address is recycled but the pages are
  not, exactly as with plain surfaces.
* The primary (24A446) produced the same table, including
  `round 14 region=2 sweeper=iosrf stage=0` and the four PurpleGfxMem control
  hits.
* `--iosurfphys` was also re-run on the primary and reproduced the secondary
  behaviour exactly (`entry -> kr=0`, `mach_vm_map -> kr=0` at the reserved VA,
  `samePhysicalPage=YES`, oversize entry clamped from `0x40000` to `0x8000`,
  `IOSurfacePrefetchPages -> kr=0`); raw log
  `analysis/evidence/iosurface-scalable-2026-11-15/iosurfphys-17pro.log`.
* No app crash, no respring and no reboot on either device; the probe printed
  its completion marker on both. The primary had been SpringBoard-locked during
  every previous attempt at these modes; it was unlocked for this run.

## Verdict

**Bounded negative.** Physical-page reuse after surface release is a property
of the **PurpleGfxMem** (DCP display-carveout) backing object alone. Surfaces
backed by the default allocator and by `ScalableMemory` behave identically:
the surviving memory entry keeps the pages assigned, and no app-reachable
allocator — including other IOSurfaces of a different region — takes them.

Consequence for the external-object lead: the ceiling recorded earlier stands
and is now measured for a third region type and across region boundaries. The
stale memory entry is an alias into one shared carveout vm_object, not into
general kernel memory. Not kR/W.

## Reproduction

```
# carrier extension
--- a/carrier/AGXProbe/SockUafSpray.c   (iosr_make_sized, rcl_round, iosurf_reclaim_probe)
# build + install + run on either device
bash ~/build_race.sh
xcrun devicectl device install app --device <udid> \
  ~/agx-probe-project/.build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device process launch --device <udid> --terminate-existing \
  --console com.bench27.agxprobe --iosurfreclaim
```

## Appendix — exhaustive per-member function-size inventory (24A446 → 24B119)

As reconnaissance for the next fix-site hunt, every fileset member's
`LC_FUNCTION_STARTS` were compared index-by-index between the two kernelcaches
(301 members; no capstone needed). Members whose function count is unchanged
(`cntΔ = 0`) but whose paired sizes differ are candidates; the count includes
alignment-only drift and is **not** a semantic diff.

| member | funcs | size Δ | note |
|---|---:|---:|---|
| `com.apple.iokit.IOSCSIArchitectureModelFamily` | 734 | 226 | string set byte-identical |
| `com.apple.iokit.IOSkywalkFamily` | 2166 | 98 | 0 added / 1 removed string |
| `com.apple.driver.FairPlayIOKit` | 479 | 70 | 419 added / 385 removed strings |
| `com.apple.iokit.IOUSBHostFamily` | 1977 | 56 | |
| `com.apple.driver.AppleUSBEthernetHost` | 109 | 31 | |
| `com.apple.iokit.IOBiometricFamily` | 509 | 28 | |
| `com.apple.iokit.IOStorageFamily` | 563 | 17 | |
| `com.apple.iokit.IOPCIFamily` | 723 | 17 | |
| `com.apple.driver.AppleARMPlatform` | 2238 | 17 | |
| `com.apple.driver.DiskImages.UDIFDiskImage` | 191 | 10 | |

No member in this table has been examined semantically yet; nothing here is a
vulnerability claim.
