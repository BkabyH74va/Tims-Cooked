# Member diff: separating address drift from real code edits

Date: 2026-11-16
Builds: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target),
`firmware/24B119/kernelcache.release.macho` (iOS 27.2)
Tooling added: `tools/kz-static-diff/kz_shape_diff.py`,
`kz_pair_shape_check.py`. Raw output:
`analysis/evidence/member-drift-vs-real-2026-11-16/`.
No device run. No fix-site claim.

## 1. Why this pass happened

The slot-27 census (same day) ran `kc_member_diff.py` over the nine
equal-function-count candidates listed in the 2026-11-15 inventory appendix.
It reported large "changed" counts — SCSI 253/734, Skywalk 108/2166,
Biometric 65/509 — which would normally rank those members as the top
remaining fix-site candidates. Before spending analysis time on them, two
failure modes had to be excluded:

1. **Index-pair misalignment.** Equal function *counts* do not prove alignment:
   one added plus one removed function cancels the count delta and shifts every
   later pair.
2. **Data-segment drift.** When a member's data moves between builds, every
   ADRP-derived literal inside otherwise identical code changes, so
   instruction-fingerprint comparison reports untouched functions as rewritten.

## 2. Method

`kz_newfunc_align.py` pairs functions across builds by relocation-normalised
instruction fingerprint, then `difflib.SequenceMatcher` alignment. Its output
replace-blocks are re-checked by `kz_pair_shape_check.py`, which compares each
block using only instruction **shape** — mnemonic, register operands, and
memory-base register — with all immediates and displacements masked. A block
whose shape sequence is identical is address-only drift; a block whose shape
differs is a genuine edit.

## 3. Results

| member | replace blocks | address-only drift | real shape edits |
|---|---:|---:|---:|
| `com.apple.iokit.IOSkywalkFamily` | 154 | **138** | **16** |
| `com.apple.iokit.IOBiometricFamily` | 79 | **64** | **15** |

So roughly **90 % of what the fingerprint pass flagged is layout drift**, not
code change. The coarse inventory numbers (Skywalk 108, Biometric 65) should
not be used as "changed function" counts.

### 3.1 Real edit sets (reconnaissance only)

> **Correction (later same day).** The `A@… sz …` values in this section are
> *replace-block* coordinates from `kz_newfunc_align.py`, not function extents:
> the size is the sum over every function inside the block. Mapping the blocks
> onto `LC_FUNCTION_STARTS` shows the Skywalk blocks span 3–46 functions each
> (e.g. `0xfffffe000a2ea33c` is 8 functions; the first alone is only `0x134`
> bytes, not `0x618`). The "large core routines" reading below is therefore
> wrong about granularity. See
> `analysis/krw-leads/skywalk-bit8-dispatch-flag-2026-11-16.md` for the corrected
> attribution and for what the dominant delta actually is.

* **IOSkywalkFamily, 16 blocks**: large core routines (`0x618`–`0x3450` bytes),
  growing by `+0 .. +60` bytes, with **no diagnostic strings** anywhere in the
  set. Representative starts: `0xfffffe000a2ea33c`, `0xfffffe000a2ec578`
  (`0x2750`), `0xfffffe000a2f315c` (`0x3450`), `0xfffffe000a2f6e74`.
* **IOBiometricFamily, 15 blocks**: mostly **shrinking**, deltas `-4 .. -124`
  bytes with many exactly `-0x14`. A uniform shrink of that size is consistent
  with removal of a repeated construct (log/assert expansion), but that is an
  observation, not a finding. Starts include `0xfffffe0009f9c91c` (`-36`),
  `0xfffffe0009f9fd84` (`-124`), `0xfffffe0009fa11d0` (`-52`).

Neither set was traced to a caller, a user-client selector, or a vendor
advisory entry. **Nothing here is a vulnerability claim.**

### 3.2 Other members

* `AppleJPEGDriver`: 1807 starts in both builds, **0 changed** — no fix landed
  there in 27.2, so its reachability work remains a candidate with no diff
  signal.
* `IOSCSIArchitectureModelFamily`: 253 index-paired differences, but they form
  one contiguous run from idx ≈ 428 with alternating `0x10`/`0xc` sizes — the
  classic signature of a single add/remove shifting the whole tail. Not a
  semantic result; needs boundary-free alignment before it means anything.

## 4. Consequence for ranking

The inventory's member-size table is a *starting list*, not a priority order:
most of its signal is pairing and layout drift. The verified post-drift edit
sets are small (16 and 15 functions). Any future fix-site hunt should run
`kz_pair_shape_check.py` first and only then look at semantics.

Recorded as bounded reconnaissance. Next step if resumed: identify the callee
set of the 16 Skywalk blocks to see whether any sits under an app-reachable
socket path (PF_ROUTE was measured reachable read-only), or whether the
biometric shrink is a removed check by inspecting the deleted instructions.
