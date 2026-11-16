# Slot-27 dispatch census: no caller exists in the 24A446 image

Date: 2026-11-16
Builds: `firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target),
`firmware/24B119/kernelcache.release.macho` (iOS 27.2)
Tooling added: `tools/kz-static-diff/kz_slotscan.py`, `kz_blscan.py`,
`kz_slotscan_all.py`, `kz_blscan_all.py`. Raw output:
`analysis/evidence/iopl-slot27-census-2026-11-16/`.
No device run. No vulnerability claim.

## 1. Why this pass happened

The previous checkpoint resolved *what* the `iopl_valid_data` caller is (arm64e
auth-pointer vtable slot 28) and left one open question: **who dispatches slot
27** — the adjacent slot whose 27.2 prologue newly rejects `(arg & 0xc0) == 0xc0`
with `kIOReturnBadArgument`. It deprioritised that lead pending "a real IOMD
caller". This pass answers the caller question for the whole image instead of
searching for one.

## 2. Vtable mapping re-verified

Arm64e auth-pointer table entries decode as `0xfffffe0007004000 + low32`.

| slot | entry @ `0x7ebd5e0+8i` | target |
|---|---|---|
| 18 | `0x7ebd670` | `0xfffffe000b34967c` (has `_dmaReferences overflow`) |
| 27 | `0x7ebd6b8` | **`0xfffffe000b348450`** (sz `0x254`) |
| 28 | `0x7ebd6c0` | `0xfffffe000b347a08` (calls `iopl_valid_data`, `"complete() while dma active"`) |
| 32 | `0x7ebd6e0` | `0xfffffe000b347928` |

Same mapping holds for the sibling tables `0x7ebd7b8`, `0x7ef4fc8`,
`0x7ef51d0`, so slot 27 is a shared implementation inherited by four
IOMemoryDescriptor-family classes.

## 3. Method identity — strong inference, not proven

Slot 27 = `prepare(IODirection)` remains an inference from public LP64
declaration order plus behaviour (callee carries `"IOMemoryDescriptor 0x%zx
prepared read only"`). Target-matched iOS 27 kernel headers are unavailable;
the reference used is the macOS 27.x SDK
(`Kernel.framework/Headers/IOKit/IOMemoryDescriptor.h`), which is a
**cross-build reference**. Two consequences worth recording:

* In the *prepare* context the reference header defines `0x40` =
  `kIODirectionPrepareShareSK` and `0x80` = `kIODirectionPrepareRetypeSK`; in
  the *complete* context the same bits mean `CompleteWithError` /
  `CompleteWithDataValid`. The prior checkpoint's "complete-only bits"
  reading is therefore **not established** — either interpretation yields the
  same rejection rule (`both bits set`).
* The 24A446 body reads its first argument only through `w1 & 0x600` and bit 8
  (`0x100`). Bits 6/7 (`0xc0`) are never consumed, so `prepare(0xc0)` follows
  exactly the same path as `prepare(0)` in 27.0.1. Any security effect would
  have to come from the value being *stored* and consumed elsewhere, which was
  not demonstrated.

## 4. Census method

`ldr xT, [xN, #(slot*8)]` with an unsigned immediate encodes the slot as a
constant, so a raw word scan with

```
(word & 0xFFFFFC00) == 0xF9400000 | (slot << 10)
```

enumerates every plain-offset load of one slot without disassembling the
image. A hit is counted as a dispatch only if (a) the same register is
branched within the next 8 instructions, and (b) that register was loaded
from memory shortly before. Hits are bracketed with each member's
`LC_FUNCTION_STARTS`.

## 5. Results

### 5.1 Slot 27 — almost nothing dispatches it

| scope | raw loads | confirmed dispatches |
|---|---:|---:|
| `com.apple.kernel` | 482 | **4** |
| all 301 members | 5,398 | **6** |

The 4 kernel-core sites are all unrelated to IOMemoryDescriptor:

| site | containing function | what it actually is |
|---|---|---|
| `0xb175908` | `0xb1757ec` sz `0x440` | BSD socket code (`'local datagram sockets'`); dispatches through `[x0+0x18]+0x40` |
| `0xb1f2738` | `0xb1f26fc` sz `0xb4` | lock-and-forward wrapper called only by `if_utun.c` and `if_ipsec.c` disconnect handlers |
| `0xb40f588` | `0xb40f524` sz `0x1f4` | adjacent function pair; base register `x10` |
| `0xb40f688` | `0xb40f524` | same |

The two extra image-wide sites are APFS sealed-volume crypto:

| site | containing function | strings |
|---|---|---|
| `0xaa3a5f0` | `0xaa3a530` sz `0x1a4` | `'aks_map_sdv_udv'`, `'map_sdv_to_udv'`, `'apfs_crypto.c'` |
| `0xaa3dd00` | `0xaa3dc94` sz `0x144` | `'aks_unmap_sdv_udv'`, `'ks_rewrap_ekwk'` |

### 5.2 No direct caller either

`kz_blscan_all.py` linear-swept every member: **0 direct `BL`/`B` to
`0xfffffe000b348450`** (kernel core separately: 0). The implementation is
referenced only by the four vtable entries.

### 5.3 The filter is sensitive (controls)

| slot | raw | confirmed | note |
|---|---:|---:|---|
| 0 | 424,665 | **40,828** | destructors: proves the pattern catches real virtual calls at scale |
| 28 | 3,253 | 10 | `AppleThunderboltNHI` ×3, `com.apple.filesystems.apfs` ×1, `com.apple.kernel` ×4, `AppleImage4` ×1, `Image4` ×1 |

So the near-zero result for slot 27 is a property of the image, not of a
broken detector.

### 5.4 Bounds of this negative

Only plain unsigned-offset `LDR Xt,[Xn,#imm*8]` is scanned. Pre/post-index
forms (e.g. `ldr x8,[x16,#0x88]!`, which does occur in this code) and `LDRAA`
would be missed, as would a virtual call whose vptr load sits more than 64
bytes before the slot load or whose branch is farther than 8 instructions
after it. Given the 40,828-site control, these forms are evidently rare for a
single method call, but they are not excluded.

## 6. Verdict

**Bounded negative / hardening.** Across the entire 24A446 image, nothing calls
the slot-27 implementation directly and nothing dispatches vtable slot 27 on an
IOMemoryDescriptor-family object. The 27.2 input-rejection guard is therefore
not reachable from any kernel path found, and no memory-safety effect of
`prepare(0xc0)` in 27.0.1 is demonstrated. Combined with §3 (27.0.1 ignores
bits 6/7), the delta reads as defensive input validation, not a fix for a
reachable defect.

Re-open only if a future build shows an app-reachable path to those four
classes' `prepare`, or if a different cross-build delta appears on this slot.

## 7. Secondary reconnaissance — per-member diff candidates

`kc_member_diff.py` (index-paired) over the inventory candidates with equal
function counts. These are **counts, not semantic diffs**:

| member | funcs | changed pairs |
|---|---:|---:|
| `IOSCSIArchitectureModelFamily` | 734 | 253 |
| `IOBiometricFamily` | 509 | 65 |
| `AppleARMPlatform` | 2238 | 36 |
| `AppleUSBEthernetHost` | 109 | 34 |
| `IOPCIFamily` | 723 | 23 |
| `IOStorageFamily` | 563 | 19 |
| `UDIFDiskImage` | 191 | 11 |
| `IOSkywalkFamily` | 2166 | 108 |
| `IOUSBHostFamily` | 1977 | 98 |
| `AppleJPEGDriver` | 1807 | **0** |

Two cautions recorded rather than chased:

* Equal *counts* do not prove index alignment — one added plus one removed
  function still cancels the count delta and misaligns every later pair. The
  SCSI run (nearly every pair from idx ≈ 428 onward flagged, alternating
  0x10/0xc sizes) has exactly that signature and should be treated as
  **misalignment**, not as 253 changed functions. Any member here needs
  boundary-free alignment (`kz_newfunc_align.py`) before a semantic claim.
* `AppleJPEGDriver` is byte-stable in this comparison (1807 starts both builds,
  zero differences): **no fix landed there between 27.0.1 and 27.2**, so its
  reachability work stays a candidate without a diff signal.
