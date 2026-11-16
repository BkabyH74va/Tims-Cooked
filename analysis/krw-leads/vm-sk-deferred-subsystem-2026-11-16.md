# `vm_sk_deferred` subsystem — full static map (2026-11-16)

Date: 2026-11-16
Builds: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target) and
`firmware/24B119/kernelcache.release.macho` (iOS 27.2)
Tools: `tools/kz-static-diff/` (`kz_fnreport.py`, `annot.py`, `kz_chainfind.py`,
`kz_adrp_ref_np.py`), numpy-free. No device run; no vulnerability claim.

This extends `vm-sk-deferred-subsystem-2026-11-15.md`. That document recorded the
new function list but could not attribute the subsystem beyond "VM layer". This
pass resolves the call graph, the allocation/fill site, the counterpart pair, and
the integration file. Verdict at the end.

## 1. Attribution: UPL/pageout integration, shared-region name cluster

Two independent pieces of evidence, kept separate:

* **Proven by code:** the integrating function `0xfffffe000ad53d8c` carries an
  assertion whose `__FILE__` string is `vm_upl.c` (referenced at
  `0xfffffe000ad553c8`). It calls two `vm_pageout.c` helpers
  (`0xfffffe000ad27d20`, `0xfffffe000ad27ab4` = the
  `vector_upl_set_subupl was passed a NULL upl` / `Trying to remove sub-upl when
  none exists` routines) and the deferred processor `0xfffffe000ad4cce0`. So the
  deferral decision is made inside the **UPL / page-list** layer, not in a
  standalone VM core helper.
* **Probable, from strings:** the `vm_sk_deferred*` source strings are linked
  immediately between `vm_shared_region.c` and `vm_shared_region_pager.c`
  (`vm_sk_deferred.c` @ file offset `0x5c641`, VA `0xfffffe0007060641`), and the
  sysctl names `vm_sk_deferred_high_watermark_mib` /
  `vm_sk_deferred_max_age_secs` sit in the kernel's sysctl-name table directly
  beside `shared_region_trace_level`, `vm_shared_region_destroy_delay` and
  `panic_on_dyld_issue`. The expansion of the `sk` prefix is **not resolved**.

Corroborating layout fact: the new queue lock `0xfffffe000b8932a8`, list head
`0xfffffe000b76e720`, count `+0x2b0` and byte total `+0x2b8` are referenced only
inside this cluster; `kz_adrp_ref_np.py` and `kz_chainfind.py chainrefs` found no
code site outside it referencing them.

## 2. Exact call graph in 24B119

Boundaries from `LC_FUNCTION_STARTS`; callers from `kz_chainfind.py callers`
(BL/B scan over every executable segment) plus `kz_fnreport.py`.

| function | size | role | direct callers |
|---|---:|---|---|
| `0xfffffe000ac1fc90` | `0x48` | typed allocator entry (`kalloc_type`-shaped: loads `{type,view}` from arg0, per-CPU zone lookup, tail-calls `0xfffffe000ac93f5c`) | 721 |
| `0xfffffe000ad4cce0` | `0x44c` | per-entry processor (`vm_sk_deferred.c`); ends with `Page modified after framebank withdraw %p` assert at `0xfffffe000ad4d124` | 5 |
| `0xfffffe000ad4d12c` | `0x32c` | **enqueue** (real one) | 1: `ad53d8c` @ `0xad54020` |
| `0xfffffe000ad4d458` | `0x1a0` | cancel queued entry (match `{object,flags,page_count}`) | 1: `ad26ee0` @ `0xad26f60` |
| `0xfffffe000ad4d5f8` | `0x18c` | enqueue-A: gated on list-empty + flag byte `0xb8932c4` | 1: `ad1c1b8` @ `0xad1c6f4` |
| `0xfffffe000ad4d784` | `0x238` | process-all under lock | 1: `ad0e5c8` @ `0xad0e5f4` |
| `0xfffffe000ad4d9bc` | `0x1d4` | drain worker | called from `ad4db90` |
| `0xfffffe000ad4db90` | `0xc8` | `vm_sk_deferred_drain` thread body | 1: `ad1f7a4` @ `0xad1fb8c` |
| `0xfffffe000ad4dc58` | `0x310` | auxiliary (calls processor) | — |
| `0xfffffe000ad53d8c` | `0x1678` | **integrating UPL/pageout helper**; enqueues or processes per page | 19 |
| `0xfffffe000ac01a08` | `0x2b8` | withdraw-result helper (`TB_FATAL: invalid result returned from withdraw`) | 1: `ad4cce0` @ `0xad4cd88` |

### 2.1 Enqueue argument decode (`0xfffffe000ad4d12c`)

```
x0 = owner object          ; refcount at +0x28, field +0x60 consumed
x1 = page-like object      ; +0x18 flags, +0x20, +0x88, +0x90 consumed
w2 = page-count delta
```

The helper allocates the queue entry through `0xfffffe000ac1fc90` with
`(global descriptor 0xfffffe0007f0cb00, 5)`, NULL-checks it, then fills:

| entry offset | value |
|---|---|
| `+0x00/+0x08` | circular list links (inserted at head `0xb76e720`) |
| `+0x10` | `[x1+0x88]` (per-page object pointer) |
| `+0x18` | `[x1+0x90]` (flags word) |
| `+0x1c` | page count = `(end >> 14)` where `end = align_down([x1+0x20] - [x0+0x60], 16 KiB) + 0x3fff + w2` |
| `+0x20` | `x0` (owner object) |
| `+0x28` | page-aligned base address |
| `+0x30` | timestamp (per-CPU counter) |

It then clears bit `0x1000000` of `[x1+0x18]`, zeroes `[x1+0x88]`/`[x1+0x90]`,
bumps `[x0+0x28]` with an overflow guard (drops through
`refcnt.c` `0xfffffe000b492328` if the guard trips), increments the queue count
at `0xb8932b0` and the byte total at `0xb8932b8`, and compares the total against
a watermark loaded from `[0xfffffe0007dfe658] << 6`; on overflow it wakes the
drain side through `0xfffffe000ac8d068` (the `ml_set_interrupts_enabled_with_debug`
routine, 517 callers).

If the allocation fails (`cbz x0 -> 0xfffffe000ad4d2d4`), the same page range is
**processed inline** by tail-calling the processor `0xfffffe000ad4cce0` with
`{owner, page_count, base}` instead of queueing. That fallback is a state
mutation, not an error path.

## 3. Counterpart mapping (24A446 ↔ 24B119)

The 27.2 functions have **no counterpart** in 24A446 (`vm_sk_deferred`,
`vmsk_page_count`, `Page modified after framebank withdraw` are absent from the
27.0.1 image; raw byte search confirms 0 hits). The one function that pairs is
the **frame-bank deposit builder**:

| | 24A446 | 24B119 |
|---|---|---|
| function | `0xfffffe000acd5224` | `0xfffffe000ad26ee0` |
| size | `0x460` | `0x574` (+`0x114`) |
| contains | `exclaves_frame_bank_deposit failed with ret=%u` @ `0xacd567c`; `__FILE__ vm_pageout.c` @ `0xacd566c` | same string @ `0xad2744c`; adds cancel `ad4d458` @ `0xad26f60` and a page-list loop calling `ad37930` @ `0xad27290` |
| sole caller | `0xfffffe000ac80474` | `0xfffffe000acd1bc4` |

Decoded behaviour of the 24A446 side: it builds a physical-address page list by
walking DART regions (`d_region_find_key()` @ `0xace059c`, message
`"d_region_find_key() no key for region '%s'"`), checks SPTM frame/paddr types
(`sptm.h`, `sptm_get_frame_type`, `sptm_get_paddr_type` strings), then calls
`0xfffffe000ab96720(count, n, list)` = the frame-bank deposit. Return `0` =
success, `0x35` = retry once, anything else logs
`exclaves_frame_bank_deposit failed with ret=%u` and returns. Its three callers
are `0xb343530` (no direct callers), `0xb34568c` ← `0xb3530cc`, and
`0xb3486a4` ← `0xb348450`; their string sets are IOMemoryDescriptor-shaped
(`IOMemoryDescriptor 0x%zx prepared read only`), i.e. the deposit sits behind
memory-descriptor preparation, not directly behind an app syscall.

Also in 24B119: the new unnamed helper `0xfffffe000ad2586c` (`0x3b8`) is called
from `0xfffffe000ad23b5c` = `vm_object_iopl_request` (size `0x1cb8`, matches the
known shrink `0x20f0 -> 0x1cb8`) at `0xfffffe000ad24f18`. Both previously
unnamed 27.2 helpers are VM page helpers with wide caller sets
(`0xfffffe000ad350fc`: 63 callers; `0xfffffe000ad37930`: 12 callers including
`ad26ee0` and the deferred processor `ad4cce0`).

## 4. Verdict

* **Reconnaissance, not a fix site.** The subsystem does not exist in the target
  build, so it cannot itself be a 27.0.1 bug. Its only possible value is as a
  fix-site signal, and the paired 27.0.1 function differs solely by *lacking*
  the deferred-cancel bookkeeping — no memory-safety delta was established here.
  Do not record this as "27.2 fixed a 27.0.1 bug".
* **Reachability unresolved, and currently unfavourable.** Every identified
  caller lives in `com.apple.kernel`; no user-client method, MIG routine or
  syscall was found above the integration point. The integration function is in
  `vm_upl.c`, so UPL construction (file-backed mmap/msync, sub-UPL handling) is
  the nearest app-facing neighbour, but the deferral gate is an internal
  argument flag (`[sp-0x74]` bit 12 in `ad53d8c`) and no app-controlled caller
  was shown to set it.
* **No device cycle spent**: without a concrete API predicate there is nothing
  bounded to measure.

## 5. Next step (only if this line is resumed)

Enumerate the 19 callers of `0xfffffe000ad53d8c`, determine which of them can
supply bit 12 of the flag argument, and walk that caller up to a user-client
method or syscall. If none can, close the lead as bounded reconnaissance and
return the effort to the IOSurface notify-race line or a fresh kext-lifetime
candidate.
