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
