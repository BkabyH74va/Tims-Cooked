# UPL / `iopl_valid_data` cluster, re-attributed and instruction-diffed (2026-11-14)

> **Correction (same day):** §3's claim that 27.2 *adds* a DART/APF/SID
> validation call inside `vm_object_iopl_request` is **wrong**. The 27.0.1
> image already contains it (`bl 0xacd3ca8 -> 0xad3ff9c`, sz `0x1a88`), with
> the identical `[obj+0xa6]` tag gate and `[obj+0xa8] |= 0x80`. Both builds
> touch exactly the same 18 `vm_object` field offsets. See
> `analysis/krw-leads/upl-dart-not-a-272-addition-2026-11-14.md`.

Status: **static analysis only — no device run, no vulnerability claim.**
Scope: supersedes the function attributions in
`analysis/krw-leads/upl-page-validation-changes-2026-11-14.md`. That document called
`0xfffffe000acd5224` "`iopl_valid_data`" and treated its growth as the main signal. Both
attributions were wrong; this file corrects them and records what the diff actually says.

Method (all tooling reproducible from `tools/kz-static-diff/`):

* Exact boundaries from `LC_FUNCTION_STARTS` (`tools/opencode-temp/kc_fstarts.py`).
* Disassembly with capstone **and `skipdata=True`** — without it capstone stops silently at
  literal pools (it truncated a 0x20f0-byte function to 86 instructions).
* Capstone stores arm64 immediates as **signed int64**; every branch/ADRP annotation must be
  masked with `& (2**64 - 1)` first or all targets come out negative and unusable.
* String references resolved by raw byte search + an ADRP+ADD/LDR scanner (`kz_adrp_ref.py`),
  not by the older substring/`func_refs` heuristics, which produced false attributions here.
* Code lives in `__TEXT_EXEC` (`0xfffffe0008498000..0xb4430000`); kernel format strings live in
  `__PRELINK_TEXT`.

---

## 1. Corrected identities

| 24A446 address | size | identity | proof |
|---|---|---|---|
| `0xfffffe000acd1e18` | `0x20f0` → `0x1cb8` | **`vm_object_iopl_request`** | 4 panic strings referenced from inside it: `external object with non-zero paging offset` @ code `0xacd3dfc`; `missing/bad page in kernel object` @ `0xacd3dc4`, `0xacd5b58`, `0xacd5b90`; `Wired page missing.` @ `0xacd3d58` |
| `0xfffffe000acd4d34` | `0x4f0` → `0x4e8` | **`iopl_valid_data`** | 7 `iopl_valid_data:` panic strings referenced from inside it (NULL upl, vector upl, unsupported upl flags, object == kernel or compressor, object purgable, busy+absent, busy page w/o absent, `%p is reusable`, `%p already wired`, missing expected page) |
| `0xfffffe000acd5224` | `0x460` → `0x574` | **unnamed page-list builder** (not `iopl_valid_data`) | allocates `*arg4 * 4` bytes, fills a ppnum array from `arg3[i*8]`, filters against two globals; no diagnostic strings of its own |
| `0xfffffe000acd64fc` | `0x128` → `0x104` | unnamed entry validator | reads `[base + idx*8]` and `[+4]`, indexes a global pointer array, does PAC (`pacda`/`autda`) with tag `0x8ac7` |
| `0xfffffe000acd8e50` | `0x194` → `0x1b8` | unnamed 16-entry aggregator | 27.0.1 sums 17 results of a `sz=0x444` helper over two 8-entry arrays; 27.2 copies 16 fixed-stride records after a type-tag check (`== 0x31`) |

`vm_object_iopl_request` also contains SPTM/TXM logic (`sptm_get_frame_type`,
`sptm_get_paddr_type returned failure for paddr 0x%llx`), so it is not a plain page-out
helper — it is the IOPL entry point with an SPTM frame-type path.

Call graph (measured):

```
vm_object_iopl_request  (0xacd1e18)
  <- BL 0xac80644 in func 0xac80474   (also calls 0xacd5224 at 0xac80668)
  <- BL 0xacd1cf0 in func 0xacd1140
  <- BL 0xad7f94c in func 0xad7f8f0
iopl_valid_data         (0xacd4d34)
  <- BL 0xb347c20 in func 0xb347a08   (size 0x418, only string 'warning')
```

`iopl_valid_data`'s caller has **no direct BL/B to its own start** and no plain 64-bit
pointer reference exists in `__DATA`/`__DATA_CONST` (checked with `kz_ptrrefs.py`), so it is
reached indirectly (stub / chained-fixup pointer). The caller chain is unresolved and needs
chained-fixup decoding before any reachability statement can be made.

---

## 2. The one semantic change in `iopl_valid_data`

Normalized instruction streams differ in exactly one behaviour (plus a reordering in the
callee). 24A446 = 27.0.1, 24B119 = 27.2.

```asm
; 27.0.1 — 0xfffffe000acd4f90..0xacd4fd8
    sxtw  x21, w24              ; wired_count
    ldr   w8, [x19, #0x30]
    add   w8, w8, w24           ; object->wired_page_count += count
    str   w8, [x19, #0x30]
    ldr   w8, [x19, #0x74]
    tbnz  w8, #0xc, L_skip      ; <-- GATE PRESENT ONLY IN 27.0.1
    ldrb  w9, [x19, #0xaa]
    tst   w9, #0x38
    b.eq  L_skip
    ldr   x9, [x19, #0x58]      ; pager-ish pointer
    cbz   x9, L_skip
    cmn   x9, #1
    b.ne  L_call
    adrp  x9, GLOBAL_c58        ; fallback global, [global+0x320] must be non-NULL
    ldr   x9, [x9, #0xc58]
    cbz   x9, L_skip
L_call:
    mov   x0, x19
    mov   x1, x21
    bl    0xfffffe000acc57c8    ; sz=0x188 in 27.0.1, sz=0x194 in 27.2
L_skip:
    tbnz  w8, #0xe, L_out       ; same bit-14 gate in both builds
    ...
```

```asm
; 27.2 — 0xfffffe000ad26c50..0xad26c94
    sxtw  x21, w24
    ldr   w8, [x19, #0x30]
    add   w8, w8, w24
    str   w8, [x19, #0x30]
    ldrb  w8, [x19, #0xaa]      ; no [obj+0x74] bit-12 gate
    tst   w8, #0x38
    b.eq  L_skip
    ... identical ...
```

The removed gate tests **bit 12 of the 32-bit word at `vm_object + 0x74`**.

**Bit 12 is very likely the `internal` flag.** Proof of the relationship, in
`vm_object_iopl_request` itself (24A446 `0xacd1ecc..0xacd1edc`):

```asm
    ldr   w8, [x19, #0x74]
    tbnz  w8, #0xc, L_no_check
    ldr   x9, [x19, #0x60]      ; paging_offset
    cbnz  x9, L_panic           ; -> "external object with non-zero paging offset"
L_no_check:
```

That is exactly the open-source `vm_object_iopl_request` guard
`if ((!object->internal) && (object->paging_offset != 0)) panic(...)`, so a set bit 12
suppresses the *external* check ⇒ bit 12 = `internal`. (Flag name inferred, not proven; the
bit position is measured.)

Consequence: in 27.0.1 an **internal** object skips the pager/ledger accounting call
outright; in 27.2 it enters the path and is gated only by `[obj+0xaa] & 0x38` and by
`[obj+0x58]`. For most internal objects `[obj+0x58]` is NULL and the callee returns
immediately, so the behavioural delta is narrow.

The callee (`0xacc57c8` → `0xad172e8`) also changed shape but not meaning: the early-exit
test `[obj+0x74] & 0x100000` moved from the top of the function to after the
preemption-disable counter increment, and the object register is spilled/restored.

---

## 3. What else changed nearby (recorded, not yet interpreted)

`vm_object_iopl_request` shrank by `0x438` bytes. Block-size-sorted structural diff of the
two annotated functions (303 change blocks; most are register renaming and stack-offset
shifts from the different frame sizes) shows the substantive ones:

* **A 196-instruction region deleted/replaced by 2 instructions** —
  `A[1534:1730]` (`0xacd36xx`-range, the `vm_page_grab`-statistics block that reads
  `0xb79ceb8`, `0xb7af8c0`, `0xb79cefc`, `0xb7af6b4` and calls `0xb11eda0`) collapses to
  `B[1450:1452]`.
* **A 141-instruction block added in 27.2** at `0xfffffe000ad25420`, reached when the helper
  `0xfffffe000ad2586c` (`sz=0x3b8`) returns 0:
  ```asm
      ldrb  w1, [x19, #0xa6]
      cmp   w1, #2          ; b.eq skip
      cmp   w1, #0x22       ; b.eq skip
      cmp   w1, #0x80       ; b.eq skip
      ... build small stack struct ...
      bl    0xfffffe000ad92f44   ; sz=0x1a88
      ldr   w8, [x19, #0xa8]
      orr   w8, w8, #0x80
      str   w8, [x19, #0xa8]
  ```
  `0xfffffe000ad92f44` is a **DART/APF/SID validator**: its strings include
  `dart %p (%s): Bypassed SID remap %u->%u`, `Invalid APF slice %u limits [%#llx,%#llx]`,
  `SID crosscheck failed actual %u expected %u`, `No space for %s: allocSize %#zx need %#zx`,
  `invalid SID configuration: %#x`. It has 10 call sites, one of which is this new block.
  So 27.2 newly runs a DART Stream-ID / APF-slice validation on the IOPL path, gated on a
  byte tag at `vm_object + 0xa6` not being `2`, `0x22` or `0x80`.
* Two smaller deletions in the page-list helpers: `0xacd64fc` lost a `[entry+4] & 2`
  early-out and a `[ptr_array_elem + 0x1c] != 0` null check; `0xacd8e50` was rewritten from
  a 17-call sum into a 16-record copy guarded by `type == 0x31` plus a flag byte.

None of these is a demonstrated vulnerability. They are recorded so the next session starts
from identities and addresses instead of the previous misattribution.

---

## 4. Verdict and next steps

**Verdict: bounded static lead — no primitive, no device claim.** `iopl_valid_data` is a
panic-only validator: every failure mode in it is a `panic()`, so even a fully reachable
trigger yields a DoS, not read/write. The single 27.2 behavioural delta in it is the removal
of an `internal`-flag gate around a ledger-accounting call, which reads as refactor/hardening
rather than a memory-safety fix.

Ordered next steps, cheapest first:

1. Decode the caller chain of `iopl_valid_data` (chained fixups / stub), starting from
   `0xfffffe000b347a08`, to settle app reachability. Until this is done no device run is
   justified.
2. Name the byte fields at `vm_object + 0xa6`, `+0xa8`, `+0xaa` and the word at `+0x74` by
   matching the iOS 27 `vm_object.h` layout against measured offsets (the file is
   `osfmk/vm/vm_object_internal.h`, referenced from `vm_object_iopl_request`).
3. Decide whether the new 27.2 DART/SID/APF validation block corresponds to a real
   vulnerability class in 27.0.1 (device-address-space mapping without SID validation). If
   yes, that — not `iopl_valid_data` — becomes the lead to pursue, and it is above the
   `kalloc_type` wall by construction.
4. Only then consider a device probe, secondary unit first.
