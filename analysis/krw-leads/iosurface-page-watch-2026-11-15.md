# Watching a released PurpleGfxMem surface: no non-IOSurface reclaimer

Date: 2026-11-15
Device: secondary iPhone14,2 (iOS 27.0, 24A5390f), one clean run.
Primary iPhone18,1 (24A446): **not run** — still locked (`SBMainWorkspace … Locked`).
Carrier mode: `--iosurfwatch` (`iosurf_hold_probe()` in `carrier/AGXProbe/SockUafSpray.c`,
dispatch `runIOSurfWatchMode()` in `carrier/AGXProbe/ContentView.swift`).
Raw console capture: `analysis/evidence/iosurface-watch-2026-11-15/iosurfwatch-13pro.log`.

## Question

`--iosurfreclaim` proved that no *app-reachable* allocation type
(`vm_allocate`, anonymous `mmap`, `malloc`, file-backed `mmap`) takes the freed
pages of a released PurpleGfxMem IOSurface. It could not test the remaining
hypothesis: a **kernel-internal** reclaimer acting while the pages are unowned,
or any allocation made concurrently with the teardown rather than after it.

This probe keeps the carveout window open and drives heavy kernel churn while
watching the stale memory entry. It does **not** need to know or tag the
reclaimer: the whole watched range is pre-filled with a unique per-offset marker
pattern, so *any* content change anywhere in the range is a positive hit.

## Method

Each round:

1. create a fresh `IOSurfaceMemoryRegion = "PurpleGfxMem"` surface, alloc `0x8000`;
2. fill every word with `0xC0DE0000 | (word_index & 0xFFFFF)` and read back word 0;
3. wrap the base in `mach_make_memory_entry_64` (`KERN_SUCCESS`, handle logged);
4. map the entry once (`mach_vm_map` ANYWHERE) to confirm aliasing, then
   **`vm_deallocate` that alias so no user mapping pins the pages**;
5. `CFRelease` the surface;
6. run 48 watch iterations, each: map the entry → scan all 0x8000 bytes for
   mismatches → unmap → churn (rotating six kinds, 48 ops each: TCP/UDP/AF_UNIX/raw
   sockets, pipes, `vm_allocate`+write, temp files, mach receive ports, plain
   non-region IOSurfaces) → 40 ms pause.

Round 0 is an **in-run positive control**: immediately after the release, eight
fresh PurpleGfxMem surfaces are created and their bases tagged with
`0x5A5A0000|idx`. If the control shows a mismatch, the detector is proven live
and the pages demonstrably remain reclaimable *during* the map/unmap watch cycle
(that cycle cannot be pinning them).

Rounds 1–3 are the test rounds: release, churn only, watch.

## Result

| round | role | worst mismatch | first off / value | changed iters | verdict |
|---|---|---|---|---|---|
| 0 | control (spray fresh region surfaces) | **1** | `0x0` / `0x5a5a0000` | 48/48 | detector live; new owner holds the pages |
| 1 | test (churn only) | **0** | — | 0/48 | nothing took the pages |
| 2 | test | **0** | — | 0/48 | nothing took the pages |
| 3 | test | **0** | — | 0/48 | nothing took the pages |

```
[*] iosurfhold r0 ctrl=1 id=0x16 base=0x105178000 alloc=0x8000 marker=0xc0de0000 entryKR=0 handle=0x7113
[*] iosurfhold r0 alias1 kr=0 marker=0xc0de0000 same=YES (no user mapping remains)
[*] iosurfhold r0 surface released; window open (control: spray fresh region surfaces)
[*] iosurfhold r0 control spray kept=8 old_base_reused=YES idx=0
[*] iosurfhold r0 VERDICT ctrl=1 worstMismatch=1 firstOff=0x0 firstVal=0x5a5a0000 changedIters=48/48 mapFail=0
[*] iosurfhold r1 VERDICT ctrl=0 worstMismatch=0 firstOff=0x0 firstVal=0x0 changedIters=0/48 mapFail=0
[*] iosurfhold r2 VERDICT ctrl=0 worstMismatch=0 firstOff=0x0 firstVal=0x0 changedIters=0/48 mapFail=0
[*] iosurfhold r3 VERDICT ctrl=0 worstMismatch=0 firstOff=0x0 firstVal=0x0 changedIters=0/48 mapFail=0
[*] iosurfhold done rounds=4 testWorstMismatch=0 -> no non-IOSurface reclaimer seen
```

Additional observations:

* Every round reused the same base address (`0x105178000`) and the same
  `IOSurfaceID` (`0x16`), i.e. the region allocator is deterministic for this
  size class across immediate create/release cycles.
* `mapFail=0` throughout: the stale entry always mapped after the release.
* No new crash report was produced by the run (newest `.ips` on the device at
  10:42 UTC, before the run; the app completed normally and was terminated by the
  console wrapper's own SIGTERM).

## Proven

* The detector is positive by construction: the same scan saw the control's
  `0x5A5A0000` tag at offset 0 in 48/48 iterations, so a zero in the test rounds
  is a measured absence, not a blind detector.
* During ~3 s per test round of socket/pipe/VM/file/mach-port/plain-IOSurface
  churn — with no user mapping holding the pages for more than a few
  microseconds at a time — **nothing outside the IOSurface region allocator
  touched the freed pages**. No marker word changed.
* Combined with `--iosurfreclaim` (app-visible reclaimers allocated *after*
  release: zero tag matches), this closes the remaining window where a
  non-IOSurface reclaimer could have been missed by the earlier sweep's
  allocate-after-release design.

## Honest limits

* The churn set exercises *generic kernel allocations* (kalloc zones, VM objects,
  VFS). Such allocations draw from normal page pools, not from the display
  carveout, so a null result here is strong evidence but not a formal proof that
  no kernel object can ever name those physical pages.
* Not tested: GPU/display-pipeline allocations (Metal/IOGPU/AGX allocations,
  framebuffer pages). Those are the only subsystems plausibly backed by the same
  physical range; a follow-up would need a Metal churn stage in the carrier.
* One device, one build (24A5390f). The primary (24A446) remains locked and
  unmeasured.
* Still no KASLR slide, kernel-task port, or kernel-object selection: **not
  kR/W**, and this lead's ceiling stays at "physical alias inside IOSurface's own
  shared backing object".

## Static support: who knows about `PurpleGfxMem`

A per-member byte sweep of the whole 24A446 fileset (excluding the shared
`__LINKEDIT`) for `carveout` / `Carveout` / `CARVEOUT` / `PurpleGfxMem` /
`ScalableMemory` / `getMemoryRegion` / `MemoryRegion`:

* `PurpleGfxMem` appears in exactly **three** members —
  `com.apple.driver.AppleMobileDispH18P-DCP` (carveout name table),
  `com.apple.iokit.IOMobileGraphicsFamily` (`IOMFB: %s : getMemoryRegion Failed
  for Surface = 0x%p, sid = %d`), and `com.apple.iokit.IOSurface`
  (region-name table beside `ScalableMemory`).
* `IOMobileGraphicsFamily-DCP` carries `CarveoutRegion`,
  `carveout memory region "%s" not found`, and the same `getMemoryRegion`
  failure message — it is the DCP-side consumer of the carveout table
  (`AppleMobileDispH18P-DCP` code at `0xfffffe000920e818` falls back to the
  literal `PurpleGfxMem` when the indexed lookup fails).
* No other member references the region name. An unnamed kernel client would
  still have to go through the DCP/IOMobileGraphicsFamily path to obtain those
  pages, which is consistent with the device result.

Interpretation: the external-object primitive's ceiling is confirmed to be the
IOSurface/GPU shared carveout. Turning it into kernel read/write would require a
kernel object allocated from that same carveout, and neither the device watch nor
the static string sweep finds such a client beyond the display pipeline.

## Device safety

One benign run on the secondary. The app stayed alive and finished its probe;
no panic, respring or reboot, and no new crash report. Primary untouched
(locked).

## Extension: GPU (Metal) allocation churn

The first run above used only generic kernel churn. Since GPU allocations are the
only remaining plausible allocator from the same physical range, the probe was
extended with an external churn callback (`hold_set_callback()` in C, implemented
in Swift) that runs every watch iteration and creates and releases, for each of
`{0x1000, 0x2000, 0x4000, 0x8000, 0x10000}`, both a `.storageModePrivate` and a
`.storageModeShared` Metal buffer (`extChurn=10` per iteration), writing into the
shared ones' contents so their pages are really touched.

Re-measured on the same secondary device (raw log
`analysis/evidence/iosurface-watch-2026-11-15/iosurfwatch-metal-13pro.log`):

| round | role | worst mismatch | changed iters |
|---|---|---|---|
| 0 | control | **1** (`0x5a5a0000` at offset 0) | 48/48 |
| 1 | test (+ Metal churn) | **0** | 0/48 |
| 2 | test | **0** | 0/48 |
| 3 | test | **0** | 0/48 |

GPU buffer allocation/release of the exact carveout size classes during the window
did not take the freed pages either. The control again proves the pages were
reclaimable during the whole window.

### Harness crash during development (attributed)

The first Metal-enabled build crashed with `SIGSEGV`/`EXC_BAD_ACCESS`
(`KERN_INVALID_ADDRESS at 0x0`) in the callback:

```
libsystem_platform.dylib  _platform_memmove
AGXProbe.debug.dylib      UnsafeMutableRawPointer.storeBytes<A>
AGXProbe.debug.dylib      closure #1 in gMetalChurnCallback
AGXProbe.debug.dylib      iosurf_hold_probe
```

Cause: calling `contents()` on a `.storageModePrivate` MTLBuffer and storing to
it — private storage is not CPU-mappable, the pointer is NULL, and the store
faults. This is a harness bug, not a device or kernel defect: the crash report is
an app-level fault in our own process, no panic/respring/reboot occurred, and the
device stayed enumerated. Fix: allocate private buffers without touching
`contents()`, write only through shared-mode buffers, and guard the pointer
against NULL. Re-run after the fix was clean (the table above).

Evidence: `analysis/evidence/iosurface-watch-2026-11-15/AGXProbe-crash-metal-churn-13pro.ips`.

## Bottom line

Both the generic-kernel and the GPU-allocation churn measurements agree: while a
PurpleGfxMem surface's pages are unowned, no allocator reachable from this app —
including the GPU allocator at matching size classes — takes them except the
IOSurface region allocator itself. The external-object primitive's ceiling stays
the IOSurface/GPU shared backing object; it does not reach kernel CPU memory.

## Static close-out: the carveout path is unchanged in 27.2

`tools/opencode-temp/kc_fnfp_find.py` fingerprints a function with
relocation-normalised instructions and searches the other build for an exact
counterpart, so address drift does not matter:

| 24A446 function | role | 24B119 counterpart | verdict |
|---|---|---|---|
| `AppleMobileDispH18P-DCP` `0xfffffe000920e818` (sz `0x88`) | carveout name/index lookup (falls back to literal `PurpleGfxMem`) | `0xfffffe00092560ec` | **identical** |
| `IOMobileGraphicsFamily-DCP` `0xfffffe000a15496c` (sz `0x2c0`) | DCP-side memory-region consumer (`CarveoutRegion`, `getMemoryRegion` failure log) | `0xfffffe000a1a3c50` | **identical** |

No fix-site signal exists on the carveout allocation path in 27.2. Together with
the device measurements above, there is no evidence that the IOSurface/GPU
carveout aliasing is or was a fixed vulnerability, and no kernel client outside
that allocator could be shown to reach those pages.
