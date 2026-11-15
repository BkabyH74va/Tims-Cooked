# 27.2 kernel-core reconnaissance: a new `vm_sk_deferred` deferred-page subsystem

Date: 2026-11-15
Builds: `firmware/24A446/kernelcache.release.macho` (27.0.1, target) and
`firmware/24B119/kernelcache.release.macho` (27.2)
Tool: `tools/kz-static-diff/kz_newfunc_align.py` (numpy-free; fingerprint +
`difflib.SequenceMatcher` alignment of `LC_FUNCTION_STARTS`)
Evidence: `analysis/evidence/kernel-newfuncs-2026-11-15/`

This is **reconnaissance, not a vulnerability claim**. It records newly added
kernel-core code in 27.2 and one bounded negative found while looking for fix
sites. No device run is associated with this document.

## Method

Function boundaries come from `LC_FUNCTION_STARTS` per fileset member. Each
function is fingerprinted by its disassembled instruction stream with
kernel-slide-sensitive operands normalised (`ADRP` literal -> `#A`, `ADD` of an
ADRP-derived register -> `#S`, in-function branch targets -> `L+off`, external
-> `E`, memory displacements on ADRP bases -> `#G`). The two ordered function
lists are aligned with `difflib.SequenceMatcher`; opcodes with **no
counterpart at all** (pure insert/delete) are the strongest "new function"
signal. Pure inserts were then re-checked against every A fingerprint to filter
out relocations whose only change is an embedded line number.

Caveat retained from the skill: fingerprint equality is *not* proof of
unchanged code, and a replace block with unequal function counts mixes
additions with rewrites; every entry below is labelled accordingly.

## Result: functions added in the 27.2 kernel core

17 pure-insert functions were found (24B119):

| function | size | referenced strings |
|---|---:|---|
| `0xfffffe000abefee0` | `0x1a8` | none |
| `0xfffffe000abf0088` | `0x14` | none |
| `0xfffffe000abf2bec` | `0x1c` | none |
| `0xfffffe000ac011a4` | `0x64` | `exclaves.tightbeam.c` |
| `0xfffffe000ac01208` | `0x14` | none |
| `0xfffffe000acdaee4` | `0x128` | `use unsupported VM_WIMG type for managed page ...` |
| `0xfffffe000ad2586c` | `0x3b8` | none |
| `0xfffffe000ad4cce0` | `0x44c` | `vm_sk_deferred.c` |
| `0xfffffe000ad4d12c` | `0x32c` | none |
| `0xfffffe000ad4d458` | `0x1a0` | none |
| `0xfffffe000ad4d5f8` | `0x18c` | none |
| `0xfffffe000ad4d784` | `0x238` | none |
| `0xfffffe000ad4d9bc` | `0x1d4` | none |
| `0xfffffe000ad4db90` | `0xc8` | `vm_sk_deferred.c`, `vm_sk_deferred_drain` |
| `0xfffffe000ad4dc58` | `0x310` | none |
| `0xfffffe000adabf14` | `0x1b8` | none |
| `0xfffffe000aeb9948` | `0xc8` | none |

Five entries are relocations, not additions:

* `0xfffffe000acdaee4` references the same VM_WIMG panic string as the 24A446
  function at `0xfffffe000ac89d44`; the normalised instruction streams differ only
  in a line-number immediate (`#0x65f` -> `#0x666`).
* `0xfffffe000ac011a4` references `exclaves.tightbeam.c`, as does 24A446
  `0xfffffe000abaee64` (same size, ratio 0.96).
* `0xfffffe000abf0088`, `0xfffffe000abf2bec`, `0xfffffe000ac01208` have no exact
  A fingerprint but match A functions of identical size elsewhere
  (`0xab9eec4`, `0xaba3310`, `0xabb0804`) and are treated as moved helpers.

That leaves **12 genuinely new functions**. One of them,
`vm_sk_deferred_drain` (`0xfffffe000ad4db90`), shows a 0.98 normalised ratio
against 24A446 `VM_object_reaper_thread` (`0xfffffe000acb7a5c`), but the two
reference different source files and symbols: Apple reused the same
"reaper-thread" template (start thread, claim a gate at `[thread+0x228]`,
tail-call a per-entry worker), so the high similarity is **not** evidence of
relocation. The remaining 11 have low best-match ratios (0.09-0.67) against
same-sized A functions and form one coherent new subsystem.

## The `vm_sk_deferred` subsystem (27.2 only)

### Identifiers present in 24B119 and absent from 24A446

```
site.struct vm_sk_deferred_entry          @0xfffffe000705c618
vm_sk_deferred.c                          @0xfffffe000705c641
vm_sk_deferred: failed to start drain thread (%d) @%s:%d
vm_sk_deferred_drain                      @0xfffffe000705c751
!os_add_overflow(*__counter, page_count, __counter)
!os_sub_overflow(*__counter, e->vmsk_page_count, __counter)
vm_sk_deferred_high_watermark_mib         (sysctl name string)
vm_sk_deferred_max_age_secs               (sysctl name string)
Page modified after framebank withdraw %p
```

The struct field prefix `vmsk_` and the two sysctls (byte watermark, max age)
describe a **deferred processing queue measured in pages**, drained by a
dedicated kernel thread.

### Queue structure (inferred from the drain/enqueue functions)

Globals referenced only inside this cluster (whole-kernel ADRP+ADD scan):

| global | role |
|---|---|
| `0xfffffe000b8932a8` | queue lock (lock byte, `casa`/`casl`) |
| `0xfffffe000b76e720` | circular doubly-linked list head |
| `0xfffffe000b8932b0` | entry count |
| `0xfffffe000b8932b8` | deferred byte total |

Inferred entry layout (from `ad4d9bc` / `ad4d458`): `+0x00/+0x08` list links,
`+0x10` object pointer, `+0x18` flags word, `+0x1c` page count (`vmsk_page_count`),
`+0x20` per-page object pointer, `+0x28` base address.

### Behaviour

* `vm_sk_deferred_drain` (`0xfffffe000ad4db90`, size `0xc8`) is a thread body:
  it starts a thread on failure path ("failed to start drain thread"), takes the
  gate, atomically claims the queue, pops entries, and calls the per-entry
  processor with `{object, flags, page_count, per-page-object, base}`.
* `0xfffffe000ad4d784` is a process-all variant: it walks the queue under the
  lock, processes each entry, releases the per-page object, and frees the entry.
* `0xfffffe000ad4cce0` is the per-entry processor. It computes an end address as
  `base + page_count * 0x4000` (16 KiB stride), then loops over that range
  under a per-CPU gate (`0xfffffe000b7cd548`), calling page-lookup and
  per-page helpers (`0xfffffe000ad350fc`, `0xfffffe000ad37930`).
* `0xfffffe000ad4d458` cancels a queued entry by matching
  `{object, flags, page_count}`; `0xfffffe000ad4d5f8`/`0xfffffe000ad4d12c`
  are enqueue paths.

### Integration points (callers, all inside the kernel core)

| caller function | evidence | calls |
|---|---|---|
| `0xfffffe000ad1f7a4` | references `VM_pageout_scan`, `com.apple.xnu` | drain thread `ad4db90` |
| `0xfffffe000ad53d8c` | references `ptm_frame_is_last_mapping` | enqueue path `ad4d12c` |
| `0xfffffe000ad0e5c8` | VM helper (no strings) | process-all `ad4d784` |
| `0xfffffe000ad26ee0` | zone/heap descriptor strings | cancel `ad4d458` |
| `0xfffffe000ad1c1b8` | region-check assertion strings | enqueue path `ad4d5f8` |
| `0xfffffe000b16e938` | no strings; adjacent BSD-socket strings in the same alignment block | drain worker `ad4d9bc` |

The `VM_pageout_scan` caller makes this a **page-reclamation-adjacent**
mechanism: pageout drains the deferred queue. The frame-bank context strings
(`Page modified after framebank withdraw %p`) tie the deferred entries to page
frames that were withdrawn from a bank.

### Relation to the existing frame-bank service

`framebankxnuteller_*` type-descriptor strings exist in **both** builds, as do
`TB_FATAL: invalid result returned from withdraw` (24A446
`0xfffffe000704e8df`) and `exclaves_frame_bank_deposit failed with ret=%u`.
So a frame bank teller already exists in 27.0.1; 27.2 adds a deferred layer
around it rather than the bank itself. The 27.0.1 equivalent behaviour (if any)
is inline and unidentified.

## What this is not

* No evidence that 27.0.1 has a bug fixed by this subsystem. The corresponding
  27.0.1 code path has not been identified, and "new in 27.2" alone is not a
  fix site.
* The subsystem's user-space reachability is **unresolved**. Pageout-driven
  drain can be influenced indirectly by app memory pressure, but no concrete
  app-triggerable path to enqueue/cancel a `vm_sk_deferred_entry` has been shown.
* The `vm_sk_` prefix meaning is unknown; "sk" is recorded as an abbreviation,
  not expanded.

## Next step (concrete)

1. Identify the enqueue/allocation sites: walk the callers of
   `0xfffffe000ad4d5f8` and `0xfffffe000ad4d12c` upward and find where the
   entry object is allocated and filled (`vmsk_page_count` producer).
2. Resolve what the deferred entries are lent to: the frame-bank
   deposit/withdraw path (`framebankxnuteller`) is the strongest candidate;
   trace `exclaves_frame_bank_deposit` in 27.0.1 to see whether an app-reachable
   service (shared region / dyld pager / sealed volume decompression) performs
   withdrawals.
3. Only if step 1-2 produce a user-facing API should a device probe be built.
   Do not spend device cycles on pageout pressure without a specific predicate.

## Bounded negatives recorded in the same pass

* **`map_block_buf` is not a fix.** The 27.2 diagnostic
  `"map_block_buf: pbt=%u block_size=%zu too small for addr_offs=%u size_offs=%u"`
  (referenced at `0xfffffe000a19d760`, function `0xfffffe000a19d678`,
  `com.apple.iokit.IOMobileGraphicsFamily-DCP`, size `0x380`) has an exact
  27.0.1 counterpart at `0xfffffe000a14e4a4` (size `0x2c0`, paired by index).
  Both versions compute `max(addr_offs+8, size_offs+4)` and reject when
  `block_size` is smaller; 27.2 only adds the log message.
* **`lifs io_lock_override` checks pre-exist.** The set path
  (24A446 `0xfffffe000ab2f858`, size `0x64`; 24B119
  `0xfffffe000ab7f604`, size `0x6c`) rejects an already-set override and calls a
  panic/log helper in both builds; the new message adds the owning thread. The
  clear path grows `0x15c -> 0x194`: after successfully clearing, 27.2
  additionally zeroes `[obj+0xc8]` (two qwords), sets bit `0x200000` of
  `[obj+0x160]`, and calls two helpers before unlocking. That is a plausible
  bookkeeping/wakeup fix, but no trigger and no memory-safety consequence were
  established, and it is recorded as unproven.

## Member-level change counts (index-paired, unverified)

`tools/opencode-temp/kc_member_diff.py` reports, for members whose function
count is unchanged (so index pairing is at least aligned):

| member | funcs | size-delta | changed pairs |
|---|---:|---:|---:|
| `com.apple.iokit.IOSkywalkFamily` | 2166 | +276 | 108 |
| `com.apple.iokit.IOSCSIArchitectureModelFamily` | 734 | +226 | 253 |

These are **coverage numbers, not semantic diffs**: a "SIZE" pair only says the
paired functions differ in length. Neither member is known to be app-reachable
(SCSI especially), so they are recorded here as reconnaissance backlog, not
leads.
