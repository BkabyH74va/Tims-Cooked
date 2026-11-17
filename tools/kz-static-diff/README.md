# kz-static-diff — kernelcache static-diff helpers

Small, self-contained arm64 (kernelcache) analysis scripts used to produce
`analysis/krw-leads/upl-iopl-cluster-diff-2026-11-14.md`.

They derive the repository root from `__file__`, so they run from anywhere:

```sh
python kz_funcinfo.py 24A446:0xfffffe000acd4d34   # needs numpy
python annot.py 24A446 0xfffffe000acd4d34 0x4f0 out.s
python kz_side.py a.s b.s          # semantic side-by-side diff
python kz_blocks.py a.s b.s        # change blocks sorted by size
python kz_sum.py a.s b.s           # change blocks with sample text
python kz_adrp_ref.py 24A446 0xfffffe000705dfcd   # code sites referencing a VA
python kz_fn_adrp.py 24A446 com.apple.iokit.IOHIDFamily 0xfffffe000a0d65a4 0x60 \
        0xfffffe00079b0000 0xfffffe00079c3000          # all ADRP+ADD/LDR targets of one function
python kz_member_authscan.py 24A446 com.apple.iokit.IOHIDFamily 0xfffffe000a0fc660 \
        0x200                                           # member-scoped arm64e auth-pointer slots
python kz_ptrrefs.py 24A446 0xfffffe000b347a08    # data slots holding a pointer (numpy)
python kz_calls.py out.s 0xfffffe000acd1e18 0x20f0 24A446 --offsets   # numpy-free call fingerprint
```

`kz_funcinfo.py` and `kz_ptrrefs.py` import `numpy`, which is **not** installed in
the PC Python; use `kz_calls.py` / `kz_chainfind.py` / `annot.py` instead.

Builds are `24A446` (iOS 27.0.1, target) and `24B119` (iOS 27.2). Requires
`tools/pylibs/capstone` and `tools/opencode-temp/kc_fstarts.py` (both already in-repo).

## Pitfalls these scripts exist because of

1. **Capstone stores arm64 immediates as signed int64.** Branch and ADRP targets above
   `0x8000000000000000` come out negative; every annotation must mask with
   `& (2**64 - 1)` or all target resolution silently compares against positive literals
   and reports zero hits.
2. **Capstone stops at literal pools.** Kernelcache functions contain embedded literal
   islands, so a plain `md.disasm()` truncates mid-function — it returned 86 instructions
   for a `0x20f0`-byte function. Always set `md.skipdata = True`.
3. **`func_refs`/`adrp_track.py` mis-attribute strings** when the reference pattern is not
   a clean ADRP+ADD (intermediate branch, register reuse). Verify string attribution with
   `kz_adrp_ref.py`, which decodes every ADRP/ADD/LDR pair in `__TEXT*` and reports the
   exact code site.
4. **Main kernel code is in `__TEXT_EXEC`** (`0xfffffe0008498000..0xb4430000` on 27.0.1),
   while kernel format strings are in `__PRELINK_TEXT`. Scanning only `__TEXT` misses
   both.
5. Pass native Windows paths (or `$LOCALAPPDATA/...`) to these scripts: a bare `/tmp/x.s`
   is interpreted differently by git-bash and by native CPython.
6. `kc_fstarts.load_build()` covers only the `com.apple.kernel` entry, so every
   tool built on it (`kz_fn_strings.py`, `kz_vtable.py find/dump/diff`) reports
   "no start" / `KeyError` for kext-member VAs. Use the `kc_member`-based tools
   for a member. Separately, string-VA lists are build-specific: an address
   copied from a 24B119 scan names different bytes in 24A446, and a scan run on
   it returns a clean-looking zero.
7. **Slot indices must be measured from the stored vptr, not the table start.**
   Arm64e tables frequently carry a two-entry header (offset-to-top, typeinfo)
   before the first function, but the object stores a vptr *past* it. A flat
   "slot N = table base + N*8" therefore lands on the wrong entry while looking
   plausible. Recover the stored vptr from the instance constructor
   (`str pacda(...),[x0]`) or from a neighbour whose index you already know,
   then read `(entry - vptr)/8`. Sanity check with the destructors at slots 0/1
   and with a size check against the `OSMetaClass(..., size)` argument.
8. **A BL-site census for a vtable slot is only meaningful with the slot-load
   base traced to a vptr load.** Matching bare `ldr xT,[xN,#imm]` plus `blraa`
   counts object field loads as virtual dispatches (250 hits for offset 0x60,
   most false); requiring `xN` to come from `ldr xN,[xObj]` drops it to the real
   set. `kz_slot12_vtable.py` implements the strict form.

