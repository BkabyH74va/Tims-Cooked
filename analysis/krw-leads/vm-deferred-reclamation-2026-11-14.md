# Lead: VM deferred-reclamation MIG surface (`mach_vm_deferred_reclamation_buffer_*`) — app reachability

Date: 2026-11-14
Device measurement: iPhone 13 Pro, iOS 27.0 / build 24A5390f (secondary unit)
Static source: `firmware/24A446/kernelcache.release.macho` (27.0.1) and `firmware/24B119`
(27.2), plus `mach/mach_vm.defs` from the macOS 27 SDK (same XNU generation).

Status: **bounded negative.** The kernel implements a Mach-VM "deferred reclamation"
subsystem whose routines take a task port and operate on that task's own address space,
but **iOS exposes no client stub for any of them**, so a sandboxed app cannot call it
through libSystem. The subsystem is also almost certainly gated off at runtime.

---

## 1. Why this lead was taken

The standing blocker is that heap-level kR/W is structurally blocked by `kalloc_type`
type isolation. The handoff therefore asks for work *above* the type-isolation wall: the
VM/VFS layer, physical-page primitives, and IOSurface-backed external objects.

While triaging changed VM-layer functions between 24A446 and 24B119, one cluster stood
out because it is not heap code at all: a set of Mach-VM MIG routine names present in the
kernel image for a task-scoped page-reclamation API. That API takes a **task port** as its
first argument and makes the kernel act on that task's `vm_map` — exactly the class of
primitive that bypasses type isolation entirely.

## 2. What the kernel image contains (static, proven)

### 2.1 The MIG routine table exists in the image

`__PRELINK_TEXT`, VAs `0xfffffe0007d55380`-`0xfffffe0007d55620`, holds a contiguous,
ordered list of MIG routine names:

```
m_region_recurse
mach_vm_region
_mach_make_memory_entry
mach_vm_purgable_control
mach_vm_page_info
mach_vm_page_range_query
mach_vm_remap_new_external
mach_vm_deferred_reclamation_buffer_allocate      <- 0xfffffe0007d5541f
mach_vm_deferred_reclamation_buffer_flush         <- 0xfffffe0007d5544c
mach_vm_range_create
mach_vm_deferred_reclamation_buffer_resize        <- 0xfffffe0007d5548b
mach_vm_update_pointers_with_remote_tags
mach_vm_deferred_reclamation_buffer_query         <- 0xfffffe0007d554df
mach_vm_reallocate
...
```

The order matches `mach/mach_vm.defs` declaration order exactly (including the `skip;`
slot where `mach_vm_deferred_reclamation_buffer_update_reclaimable_bytes()` used to be),
which is how MIG numbers routines from the subsystem base `4800`.

Neither `reclaim_ring` nor `get_rings_for_task` appears anywhere in **either** build
(`kc_findstr` over both kernelcaches: 0 occurrences). The `mach_vm_reclaim_ring_*`
symbols exported by the iPhoneOS 27.2 SDK are therefore macOS-side only; iOS 27.0/27.0.1
and 27.2 all use the deferred-buffer generation.

### 2.2 The kernel-side implementation is compiled in

`osfmk/vm/vm_reclaim.c` is present in full. 32 `vm_reclaim:` log strings exist
(e.g. `0xfffffe00070d2bda`), and the string `reclaim is disabled`
(`0xfffffe00070d2c1c`) is the log line from
`vm_deferred_reclamation_buffer_init_internal()`'s failure path when
`vm_reclaim_max_threshold == 0`. A register-tracking ADRP+ADD scan
(`scratch/adrp_track.py`) resolves **43 code references** to those strings, landing in
five functions:

| function start | size | role (from log strings it references) |
|---|---|---|
| `0xfffffe000acd9aa8` | `0x48` | thread name / init |
| `0xfffffe000acda5a0` | `0xb0` | list/queue management |
| `0xfffffe000acdc060` | `0x12c` | copyin/copyout + reclaim chunk |
| `0xfffffe000acdc2a4` | `0x70` | exception delivery |
| `0xfffffe000acdcebc` | `0x3bc` | reclaim thread main loop |

The public XNU source of this file (`osfmk/vm/vm_reclaim.c`) shows the mechanism:
a task-owned userspace buffer of `{address,size,deadline}` entries, with the kernel
copying `head`/`tail`/`busy` and the entry array straight out of the task's own address
space via `copyin_atomic64`, then performing `vm_map_remove_guard()` on the owning
task's map. Nothing in that path allocates or frees typed kernel memory, which is why
it is interesting next to the type-isolation wall.

### 2.3 No fix landed in 27.2

`tools/opencode-temp/kc_diff_all.json` lists 542 semantically-changed
`com.apple.kernel` functions between 24A446 and 24B119. In the range containing the
vm_reclaim cluster (`0xfffffe000acd0000`-`0xfffffe000ace0000`) there are five changed
functions — `0xfffffe000acd1e18`, `acd4d34`, `acd5224`, `acd64fc`, `acd8e50` — and
every one of them is `vm_pageout.c` / `iopl_valid_data()` UPL validation, not
vm_reclaim. **None of the five vm_reclaim functions above is in the changed list.**

So Apple did not patch this subsystem in 27.2. There is no CVE fix-site signal here,
which lowers its value as an exploit path but also means whatever behaviour it has is
still present on 27.2.

## 3. Device measurement (proven, 13 Pro / 24A5390f)

Added `--reclaim` to the carrier (`SockUafSpray.c` `vm_reclaim_probe()`, declaration in
`AGXProbe-Bridging-Header.h`, dispatch + `vmReclaimProbe()` in `ContentView.swift`).
Build `BUILD_EXIT=0`; installed and launched on the 13 Pro.

```
[*] reclaim dlsym _mach_vm_deferred_reclamation_buffer_allocate -> 0x0
[*] reclaim dlsym _mach_vm_deferred_reclamation_buffer_flush    -> 0x0
[*] reclaim dlsym _mach_vm_deferred_reclamation_buffer_resize   -> 0x0
[*] reclaim dlsym _mach_vm_deferred_reclamation_buffer_query    -> 0x0
[*] reclaim ctl dlsym _mach_vm_allocate           -> 0x0
[*] reclaim ctl dlsym _mach_vm_deallocate         -> 0x1c466ca44
[*] reclaim ctl dlsym _mach_vm_purgable_control   -> 0x0
[*] reclaim ctl dlsym _mach_vm_range_create       -> 0x0
[*] reclaim ctl dlsym _mach_vm_reallocate         -> 0x0
[*] reclaim ctl dlsym _mach_vm_reclaim_ring_allocate -> 0x0
[*] reclaim: _mach_vm_reallocate not exported either
[*] reclaim rc=-1 dlsym=0 ...
```

What this establishes:

1. **`dlsym` works and the negative result is real.** `_mach_vm_deallocate` resolves to
   a live address through the same call, so the NULLs above are a genuine absence from
   the app-visible symbol table, not a lookup artifact.
2. **No iOS client stub exists for any of the four deferred-reclamation routines, nor
   for `mach_vm_reallocate`.** All would have to be reached by hand-rolled Mach IPC.
3. `_mach_vm_allocate` also returns NULL even though the probe links against it
   successfully, i.e. it is a *hidden* export: linkable, but not resolvable by
   `dlsym`. This is a caveat on any future attempt — absence from `dlsym` alone does
   not prove a symbol is unlinkable.

## 4. Why this is probably inert anyway

`vm_deferred_reclamation_init()` runs at EARLY_BOOT and starts `reclaim_thread`
unconditionally, so the machinery is alive. But every allocation path goes through
`vm_deferred_reclamation_buffer_init_internal()`, whose first check is
`if (!vm_reclaim_max_threshold) return KERN_NOT_SUPPORTED;`. That tunable
(`TUNABLE_DT_DEV_WRITEABLE(..., "kern.vm_reclaim_max_threshold", ..., default 0)`)
is read from the device tree `/defaults` node, and **the tunable name string does not
appear anywhere in the iOS kernelcache** (0 occurrences of `vm_reclaim_max_threshold`),
unlike the surrounding log strings. On iOS there is no observable indication that it is
set non-zero, and nothing in userspace can set it.

## 5. Verdict and honest bounds

* **Proven:** the kernel implements the API; the names/order match the SDK `.defs`;
  vm_reclaim.c is compiled in with 43 code refs; the code is unchanged in 27.2;
  an app on iOS 27.0/27.0.1 cannot resolve any client stub for it.
* **Not proven:** that the routines are unreachable. Hand-rolled Mach messages to
  `mach_task_self()` with the correct `msgh_id` could still reach the server side; that
  requires deriving the routine numbers from `mach_vm.defs` order (base 4800) and was
  deliberately not attempted, because (a) the gate tunable is very likely zero, and
  (b) an incorrect id can land on an unrelated `mach_vm` routine.
* **Not proven:** that the feature is enabled at runtime.

**Bound:** treat as closed for app-carried work unless a future iOS build exports a
stub (watch the SDK `.tbd` each release — the family has already been renamed once,
from `..._update_reclaimable_bytes` to `..._query`, and macOS moved to
`mach_vm_reclaim_ring_*`). Re-open if a stub appears.

## 6. Reproduce

```
# carrier build (macOS host)
bash ~/build_race.sh                                  # BUILD_EXIT=0
xcrun devicectl device install app --device <UDID> \
    ~/agx-probe-project/.build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device process launch --device <UDID> --console --terminate-existing \
    com.bench27.agxprobe --reclaim
```

Tools added to the scratch/tool area this run (not part of the repo):
`scratch/adrp_track.py` (register-tracking ADRP+ADD string-reference scanner; validated
against the known CoW reference at `0xfffffe000ac89234`), `scratch/adrp_refs.py`,
`scratch/fninfo2.py`, `scratch/fileset_lookup2.py`.
