# AppleAVE2 HEVC VPS validation cluster — 24A446 vs 24B119

Date: 2026-11-15
Images: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target build) and
`firmware/24B119/kernelcache.release.macho` (iOS 27.2).
Member: `com.apple.driver.AppleAVE2`, kernel-mode `__TEXT_EXEC`
(24A446 `0xfffffe000871d710..0x...88edee8`, 24B119 `0xfffffe0008753d00..0x...89283a8`).

Follows the "immediate next step" in `HANDOFF.md`: localise the 27.2 HEVC/AVC
parameter-set bounds checks and decide which values reach them from an app.

## Method

`kc_fstarts.load_build()` only covers the `com.apple.kernel` fileset entry, so the kext
region was loaded per member (`LC_FILESET_ENTRY` → own segment table → own
`LC_FUNCTION_STARTS`; scratch loader `kc_member.py`). Verified against the previously
published boundaries: the helper is `0xfffffe00087c5bb8` size `0x4d8` and the first caller
is `0xfffffe00087c4dc4` size `0xdf4`, exactly as recorded.

Counterparts across builds were found by **string anchors** (`__func__` names and
diagnostic strings referenced from inside each function), not by address proximity.
Normalized-instruction-stream hashing over all 2,995 / 2,998 functions gives 1,978 exact
matches and 372 / 375 changed/unmatched, so the five callers below really are changed.

## The fix cluster

| function | 24A446 | 24B119 | delta |
|---|---|---|---|
| `AVE_HEVC_CheckInfo` | `0xfffffe000878e220` sz `0x5a4` | `0xfffffe00087c4dc4` sz `0xdf4` | **+0x850** |
| `AVE_Client_CheckDMVInfo` | `0xfffffe000878f564` sz `0x310` | `0xfffffe00087c6f00` sz `0xac8` | +0x7b8 |
| `AVE_Client_CheckGGMInfo` | `0xfffffe000878f874` sz `0x4d4` | `0xfffffe00087c79c8` sz `0xbb4` | +0x6e0 |
| `AVE_Client_CheckMCTFInfo` | *absent* | `0xfffffe00087c857c` sz `0xb84` | new |
| `AVE_Client_CheckLRMEInfo` | *absent* | `0xfffffe00087c9100` sz `0x8ec` | new |
| `AVE_HEVC_CheckVPSExtBounds` | *absent* | `0xfffffe00087c5bb8` sz `0x4d8` | new |

The pairings were confirmed by shared diagnostic strings on both sides
(`AVE_HEVC_CheckInfo`, `layer number is out of range`, `wrong parameters`, ...); the
24A446 members contain none of the VPS strings. Both absent-in-24A446 helpers were
confirmed absent by whole-kext substring search for their `__func__` names.

## What the new code checks

`AVE_HEVC_CheckVPSExtBounds(pA, pB)` is called once from each of the five functions
above, always as `x1 = pInfo + 0x1880` (the embedded HEVC VPS/Layer-set descriptor) and
`x0 = pInfo`. Measured reads relative to `x1`:

| field (name inferred from the diagnostic text) | offset | new bound |
|---|---|---|
| `[x1+4]` (loop count) | `+0x4` | `< 0x40` |
| `vps_num_layer_sets_minus1` | `+0xf78` | `+ num_add_layer_sets + 1 <= 0x41` |
| `num_add_olss` | `+0x2a45` | running total `<= 0x40` |
| `layer_id_in_nuh[i]`, `i < [x1+4]` | `+0x17fb + i` | each byte `< 0x40` |
| per-layer-set sub-layer sums, stride `0x40` | `+0x1a41 + j*0x40 + k` | sum `< 0x41` |

The callers additionally validate fields of `pInfo` directly before calling:

```
ldr w8,[x20,#0x768]   cmp w8,#8     ; < 8
ldr w8,[x20,#0x1888]  cmp w8,#6     ; <= 6   (max sub layers)
ldr w8,[x20,#0x27f8]  cmp w8,#0xf   ; <= 15  (num layer sets)
ldr w8,[x20,#0x2c10]  cmp w8,#0x10  ; <= 16  (num hrd parameters)
ldr w8,[x20,#0x27f4]  cmp w8,#0x3f  ; < 64   (max layers)
```

(`0x27f8 - 0x1880 == 0xf78`, so the helper's and the caller's layer-set field are the same
word seen through different bases.)

`vps_num_layer_sets_minus1` is a **10-bit** HEVC syntax element (values 0..1023). The
27.2 outer check caps it at 15; the helper caps derived totals near 64. Nothing in 24A446
performs either check — the string `vps_num_layer_sets_minus1` does not appear anywhere in
the 24A446 kext.

## What did *not* change

The HEVC VPS parser itself is byte-for-byte the same size and structurally identical
across the builds:

| function | 24A446 | 24B119 |
|---|---|---|
| HEVC VPS parser (`HEVC_VPS`, `vps_extension`) | `0xfffffe000885873c` sz `0xd5c` | `0xfffffe0008892968` sz `0xd5c` |
| VPS-extension consumer | `0xfffffe0008857d0c` sz `0x6c4` | `0xfffffe0008891f4c` sz `0x6b0` |

Same `__func__`-free string set, same six distinct callees with identical sizes. So the
defect is **not** in parsing the bitstream; 27.2 rejects the bad values *before* the
parser's output is consumed, or bounds the consumption itself.

## Interpretation, and what is still unknown

* Proven: the bounds checks exist in 27.2 and not in 27.0.1, they cover HEVC VPS/SPS
  layer-set and sub-layer counts, and the parser that fills those fields is unchanged.
* Suspected, unproven: some consumer in 27.0.1 indexes a fixed-size (16- or 64-entry)
  array with an unbounded `vps_num_layer_sets_minus1` / sub-layer count taken from the
  caller's parameter sets. Locating that consumer needs the *consumers* of the descriptor
  fields, which the current displacement scans do not isolate — the offsets are built
  with register arithmetic, not literal displacements.
* Not tested: whether a `CMVideoFormatDescription` built with
  `CMVideoFormatDescriptionCreateFromHEVCParameterSets` delivers those bytes into
  AppleAVE2 at all when passed to `VTCompressionSessionCreate`. Parallel work on this
  device measured the VideoToolbox-reachable AppleAVE2 defects as denial-of-service only
  (property-path fill loop, `this` pointer holding 1), which lowers the expected value of
  this lead.

## Next step

Encoder-side probe (`--ave`): build a format description from attacker-chosen Annex-B
VPS/SPS/PPS, create a `VTCompressionSession`, encode one frame, and report
session/encode status plus whether the emitted bitstream contains our parameter sets.
That settles reachability in one device run; only then is a trigger payload worth
designing. The decoder-side equivalent already exists as dead code
(`carrier/AGXProbe/HEVCProbe.swift` — present in the tree, referenced by neither the
Xcode project nor any launch-argument dispatch).
