# Kernelcache 27.0.1 -> 27.2: added diagnostic strings and their code refs

Date: 2026-11-14
Images: `firmware/24A446/kernelcache.release.macho` (27.0.1) and
`firmware/24B119/kernelcache.release.macho` (27.2), both plaintext.

Purpose: iOS 27.0.1 shipped with **no published CVE entries**, so every fix in 27.2 is a
bug that is live on our target build. Apple's advisories do not name functions, so this
sweep looks for diagnostics that 27.2 *added* and resolves where they are referenced from,
which names the fixed code even in a stripped kernelcache.

Method (`scratch/added_strings_refs.py`, reproducible):

1. collect printable strings (>= 6 chars) from `__PRELINK_TEXT`/`__TEXT`/`__DATA_CONST`/
   `__DATA` of both images;
2. diff the sets -> 2,423 strings added in 27.2;
3. filter to vulnerability vocabulary -> 105 candidates;
4. one-pass ADRP+ADD/LDR scan of every `__TEXT*` segment in 24B119 -> 714,043 targets;
5. keep candidates with at least one code reference -> **96**, listed below grouped by
   subsystem.

Caveat: these addresses are *reference sites* inside the fixed function, not function
starts. Pairing a 27.2 function to its 27.0.1 counterpart still needs exact boundaries
(`LC_FUNCTION_STARTS`) or string xrefs; do not infer identity from proximity.

## 1. AVEVideoEncoder (`com.apple.driver.AppleAVE2`) — 58 changed functions

New bounds checks for HEVC/AVC bitstream parameters, matching CVE-2026-112705,
CVE-2026-112689, CVE-2026-112470/-112469/-112468, CVE-2026-112466:

| added string (abridged) | ref site |
|---|---|
| `AVE_HEVC_CheckVPSExtBounds` (symbol-name string) | `0xfffffe00087c5d00` (+ 5 more in the same block) |
| `HEVC log2_max_pic_order_cnt_lsb_minus4 is out of range` | `0xfffffe00087c5450`, `0x87c7620`, `0x87c8124`, `0x87c8ca4`, `0x87c981c` |
| `number of sub layer is out of range` | `0xfffffe00087c53e4`, `0x87c7104`, `0x87c7bd0`, `0x87c8780`, `0x87c9308` |
| `HEVC VPS count is out of range` | `0xfffffe00087c5540`, `0x87c723c`, `0x87c7d08`, `0x87c88b8`, `0x87c9440` |
| `HEVC VPS num_add_layer_sets is out of range` | `0xfffffe00087c5740`, `0x87c73c4`, `0x87c7e94`, `0x87c8a40`, `0x87c95c8` |
| `HEVC SPS count is out of range` | `0xfffffe00087c587c`, `0x87c7568`, `0x87c806c`, `0x87c8bec`, `0x87c9764` |
| `HEVC PPS count is out of range` | `0xfffffe00087c598c` |
| `HEVC RPS count is out of range` | `0xfffffe00087c5aa4` |
| `AVC PPS count is out of range` | `0xfffffe00087c4c60` |
| `AVC log2_max is out of range` | `0xfffffe00087c4d6c` |
| `MCTF strength count out of range` (HEVC / AV1) | `0xfffffe00087c5b60`, `0x87c63c8` |

The repeated reference pattern (one string referenced from 4–5 nearby sites around
`0x87c5xxx`–`0x87c9xxx`) indicates a cluster of new validation helpers called from several
parameter-set parsers. This is the strongest "kernel write/read" candidate found so far
because the AVE encoder is driven through public AVFoundation/VideoToolbox APIs.

### Exact boundaries for the VPS extension checker

`LC_FUNCTION_STARTS` gives the helper itself as **`0xfffffe00087c5bb8`, size `0x4d8`** in
24B119 (the function whose `__func__` is `AVE_HEVC_CheckVPSExtBounds`). It has **five**
direct `BL` call sites:

| call site | containing function (start, size) |
|---|---|
| `0xfffffe00087c520c` | `0xfffffe00087c4dc4`, `0xdf4` |
| `0xfffffe00087c6fc0` | `0xfffffe00087c6f00`, `0xac8` |
| `0xfffffe00087c7a8c` | `0xfffffe00087c79c8`, `0xbb4` |
| `0xfffffe00087c863c` | `0xfffffe00087c857c`, `0xb84` |
| `0xfffffe00087c91c4` | `0xfffffe00087c9100`, `0x8ec` |

What it validates (`arg1` is a multi-kilobyte descriptor): a count at `[arg1+4]` capped at
`0x40`; byte arrays at `arg1+0xf78`, `arg1+0x17fb`, `arg1+0x1a40`, `arg1+0x1a41`; per-entry
sub-layer arrays at `arg1+0x1a41 + n*0x40` summed and capped at `0x41`. All of these are
HEVC VPS/SPS sub-layer and layer-set counts — exactly the fields an out-of-range
`num_layer_sets_minus1` / `sps_max_sub_layers_minus1` would drive out of bounds in 27.0.1,
where these checks do not exist.

### Counterparts localised (2026-11-15)

The five callers and the new helper have been paired against their 24A446 counterparts by
string anchors, and the helper's validated fields are read off (`AVE_HEVC_CheckInfo`
`0x878e220` sz `0x5a4` -> `0x87c4dc4` sz `0xdf4`; two Check* helpers are new in 27.2). The
HEVC VPS parser itself is unchanged between builds, so the defect is in consumption of the
parsed layer-set/sub-layer counts, not in parsing. Full table and field offsets:
`analysis/krw-leads/ave-vps-validation-cluster-2026-11-15.md`.

## 2. Apple Neural Engine (`com.apple.driver.AppleH16ANEInterface`) — 255 changed functions

See `analysis/krw-leads/ane-userclient-reachability-2026-11-14.md` for reachability.
New checks include procedure/symbol index range checks and IO-count checks at
`0xfffffe0008ccaecc`, `0x8ccb584`, `0x8d49468`, `0x8d4ea68`, `0x8d37134`, `0x8cc5cb8`.

## 3. APFS / lifs

| added string | ref site |
|---|---|
| `%s:%d: %s Cannot decompress data from inode %lld on a sealed volume` | `0xfffffe000a9d8cfc` |
| `%s:%d: %s Failed to invalidate and push %llu:%llu for ino %llu, err %d` | `0xfffffe000a9faddc` |
| `%s:%d: %s Invalid residency reason %d, out of bounds` | `0xfffffe000aa34c60` |
| `"%s: io_lock_override is already set for lnode %p by thread %p"` | `0xfffffe000ab7f668` |

The first is directly relevant to decmpfs: 27.2 now refuses decompression on a sealed
volume. The 27.0.1 counterpart does not have this check.

## 4. Other notable additions

| added string | ref site | note |
|---|---|---|
| `VM entry %p lock shared lock overflow <v:%d c:%c%c w:%c%c %c/%d>` | `0xfffffe000b48aa88` | VM/lock accounting |
| `vm: configured segment limit would overflow slot mapping index, reducing to %d` | `0xfffffe000b486024` | VM segment map |
| `map_block_buf: pbt=%u block_size=%zu too small for addr_offs=%u size_offs=%u` | `0xfffffe000a19d760` | block-mapping helper (kext TBD) |
| `Patching invalid NCM 1.1 NTB parameter wNdpOutAlignment %d` | `0xfffffe0009b60b34` | USB-NCM parsing |
| `Histogram bin count (%ld) exceeds maximum (%d)` | `0xfffffe00091b4cd4` | statistics |
| `"Unexpected: invalid aggressor LCD index"` | `0xfffffe0009bdb980` | display |

## 5. How to use this list

For each advisory whose component matches a row above, the next step is: get exact function
boundaries around the ref site with `tools/opencode-temp/kc_fstarts.py` (per member), then
diff the function against its 24A446 counterpart to read the *old* logic, then decide which
app-reachable API supplies the malformed values. Subsystem overlap is not enough — trace
the changed function's callers before building a probe.
