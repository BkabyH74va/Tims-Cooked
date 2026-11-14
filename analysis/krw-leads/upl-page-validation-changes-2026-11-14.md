# Open lead: 27.2 changed the UPL/page-validation path (`vm_pageout.c`, `iopl_valid_data`)

Date: 2026-11-14
Status: **open — not yet analysed.** Recorded here so the next session starts from the
address list instead of rediscovering the neighbourhood.

## Why it matters

The standing blocker is `kalloc_type` type isolation at the heap layer. The handoff asks
for work above that wall — VM/VFS, physical-page primitives, page-replacement races.
This is the first place in the 24A446 → 24B119 diff where Apple actually **changed
code in exactly that layer**, and the layer is reached by ordinary file I/O (UPL =
Universal Page List, the page cluster structures built by the VFS write path).

It is therefore both (a) app-reachable in principle and (b) carrying a genuine fix-site
signal, unlike the surrounding VM functions, which are unchanged.

## The changed functions

From `tools/opencode-temp/kc_diff_all.json` (com.apple.kernel, mnemonic-profile diff,
rebase-immune), in address order:

| 24A446 addr | size A → B | sim | attribution (string refs resolved with `scratch/adrp_refs.py`) |
|---|---|---|---|
| `0xfffffe000acd1e18` | `0x20f0` → `0x1cb8` | 0.82 | **`vm_pageout.c`** — `vm_object_iopl_request()` error/assert strings (`unexpected error 0x%x from vm_fault_page()`, `Wired page missing.`, `missing/bad page in kernel object`, `external object with non-zero paging offset`) |
| `0xfffffe000acd4d34` | `0x4f0` → `0x4e8` | 0.99 | references **`iopl_valid_data:`** strings (`busy+absent page on page queue`, `%p is reusable`, `missing expected page at offset %lx`, `unsupported upl, flags = %x`, `object %p purgable %d`, `vector upl`) |
| `0xfffffe000acd5224` | `0x460` → **`0x574`** | 0.79 | **`iopl_valid_data`** path: large rewrite, +0x114 bytes, and the delta set is dominated by `paciza` (+1), `casa` (+1), `casl` (+1), `ldp` (+3), `ldr` (+10), `bl` (+8) — i.e. new exclusive-access/atomic and pointer-authentication logic around the page-list walk |
| `0xfffffe000acd64fc` | `0x128` → `0x104` | 0.88 | no string refs resolved |
| `0xfffffe000acd8e50` | `0x194` → `0x1b8` | 0.77 | no string refs resolved |

The five vm_reclaim functions (`0xfffffe000acd9aa8`-`0x...cebc`) sit immediately after
this cluster and are **unchanged** in 27.2 — see
`analysis/krw-leads/vm-deferred-reclamation-2026-11-14.md`.

## What is suspected, not proven

* That 27.2 hardened `iopl_valid_data()`/`vm_object_iopl_request()` against a
  page-state inconsistency that 27.0.1 accepts.
* That the path is reachable from a sandboxed app through `write()`/`msync()` on a
  mapped file — **unproven**. No caller analysis and no device run has been done.
* Nothing here is a vulnerability claim. The changes could equally be a refactor that
  happens to add atomics.

## Next falsifiable step

1. Diff `0xfffffe000acd5224` against `0xfffffe000ad26ee0` instruction-by-instruction and
   identify the *new* condition (`paciza` + `casa`/`casl` suggest a compare-and-swap on
   an authenticated page-list pointer; find what invariant it now enforces).
2. Identify which of the two 27.0.1 behaviours the new check rejects, and which
   userspace operation can produce that state (file `write()`/`msync()`/`mmap` +
   `fcntl(F_FULLFSYNC)` are the obvious entry points).
3. Only then build a device probe on the secondary unit.

Tooling: `scratch/adrp_refs.py` (per-function string refs),
`scratch/adrp_track.py` (register-tracking ADRP+ADD scanner over a whole image),
`scratch/kc_norm_skip.py` (normalised cross-build diff; supports skipdata).
