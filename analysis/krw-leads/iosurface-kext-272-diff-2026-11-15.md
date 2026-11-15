# IOSurface kext 24A446 vs 24B119 — complete function-level diff

Date: 2026-11-15
Method: `tools/opencode-temp/kc_member_diff.py` and `tools/opencode-temp/kc_str_refs.py`
(both numpy-free; capstone from `tools/pylibs`). Per-fileset-member
`LC_FUNCTION_STARTS` boundaries, pairwise by index, instruction streams normalised
with `kc_norm_diff.norm_func`, then string references resolved per function.

## Scope and result

`com.apple.iokit.IOSurface` has **1330 function starts in both builds**
(24A446 `__TEXT_EXEC` `0xfffffe000a3257c0+0x34f5c`; 24B119
`0xfffffe000a373b90+0x34f74`). Pairwise comparison: **9 functions differ**.

| idx | 24A446 | 24B119 | kind | what changed |
|---|---|---|---|---|
| 799 | `0xa3460f0` sz `0x104` | `0xa3944c0` sz `0x114` | SIZE +0x10 | **added `ldrb w8,[x21,#0xf1]` / `tbz w8,#0` / error return `w20 = 0xe00002bd+0x1b` (`0xE00002D8`)** — refuse registration when the client carries the dead flag |
| 802 | `0xa346364` sz `0xe4` | `0xa394744` sz `0xec` | SIZE +0x8 | **added `mov w8,#1` / `strb w8,[x20,#0xf1]`** — set the dead flag on client teardown |
| 843 | `0xa3486b8` sz `0x110` | `0xa396aa0` | CODE | assertion only: line number `#0xcfd`→`#0xd09`, string offsets; instruction stream otherwise identical |
| 945 | `0xa34b2dc` sz `0xf4` | `0xa3996c4` | CODE | no string refs; metadata/relocation only |
| 1314 | `0xa359aac` sz `0x3c` | `0xa3a7e94` | CODE | assertion helper, line `#0x…` shifted only |
| 1315 | `0xa359ae8` sz `0x30` | `0xa3a7ed0` | CODE | assertion helper (`"unexpected client map mismatch"`), line `#0xd38`→`#0xd44` only |
| 1316 | `0xa359b18` sz `0x30` | `0xa3a7f00` | CODE | assertion helper (`"user client not found in map"`) |
| 1317 | `0xa359b48` sz `0x30` | `0xa3a7f30` | CODE | assertion helper (`"Bad IOSurfaceClient"`), line `#0x4a5`→`#0x4a6` only |
| 1318 | `0xa359b78` sz `0x5c` | `0xa3a7f60` | CODE | assertion helper (`set_surface_handle asked to set handle %08x that was not free`) |

The two size-changing functions are exactly the fix predicted in
`analysis/iosurface-notify-uaf-CVE-2026-112477.md` and implemented by
`carrier/AGXProbe/IOSurfaceNotifyProbe.c`: iOS 27.2 sets a dead flag at
`IOSurfaceClient+0xf1` during teardown and refuses to register a notification on a
client carrying it, returning `0xE00002D8` (`kIOReturnNotAttached`). Everything else
in the kext is assertion text/line-number drift caused by the moved string table.

## Consequence for the external-object lead

**No function in the IOSurface kext changed in the memory-entry, pager, prefetch,
surface-backing-store, or teardown-of-pages paths between 24A446 and 24B119.** The
stale-page physical alias measured on device
(`analysis/krw-leads/iosurface-stale-page-race-2026-11-15.md`) is therefore **not**
among the fixes Apple shipped in 27.2 — it remains an open, unpatched defect class as
far as this binary evidence goes. Conversely, the 27.2 change is additive
(a refusal on a flag), so nothing there would invalidate the earlier steps of the
chain either.

## Reproduction

```sh
python tools/opencode-temp/kc_member_diff.py com.apple.iokit.IOSurface
python tools/opencode-temp/kc_str_refs.py 24A446 com.apple.iokit.IOSurface \
    0xfffffe000a3460f0 0x104
```

## Pitfalls hit while building this

* `capstone.arm64.reg_name` does not exist; use `instruction.reg_name(reg)`
  (`md.reg_name` also works). Calling the module attribute raises `AttributeError`,
  which a broad `try/except` silently swallows — a scan wrapped that way reports zero
  references everywhere and looks like "no caller".
* `md.skipdata = True` is mandatory inside kernelcache functions; without it the
  disassembly truncates at literal pools.
* Mask every capstone immediate with `& (2**64 - 1)` before comparing against VAs;
  ADRP/branch immediates above `0x8000…` come back signed.
