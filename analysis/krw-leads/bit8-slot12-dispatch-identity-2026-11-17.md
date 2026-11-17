# The bit-8 change is in `IOUserClient::Dispatch` (DriverKit RPC ingress), not `externalMethod`

Date: 2026-11-17
Builds: `firmware/24B119/kernelcache.release.macho` (iOS 27.2),
`firmware/24A446/kernelcache.release.macho` (iOS 27.0.1, target)
Tooling added: `tools/kz-static-diff/kz_slotctx.py`.
Raw output: `analysis/evidence/bit8-slot12-2026-11-17/slot12-dispatch-identity-verify.txt`
No device run. No vulnerability claim.

## 1. Why this pass happened

The previous checkpoint (`bit8-slot12-identity-2026-11-17.md`) closed the
"is slot 12 `externalMethod`?" question with a negative and left one gate open:
the provenance of `[args+0x18]` / `[args+0x00]`. This pass identifies the
virtual instead, and that identification dissolves the provenance gate rather
than resolving it.

## 2. Result: slot 12 is `IOUserClient::Dispatch(const IORPC rpc)`

The evidence is structural and mutually independent:

* **ABI.** The thunk at `0xfffffe000b31e208` (size `0x2c`) is exactly the
  compiler wrapper for a by-value argument larger than two registers:

  ```
  ldp q0, q1, [x1]      ; copy 0x20 bytes
  stp q0, q1, [sp]
  mov x1, sp
  bl  0xfffffe000b31e234   ; _Dispatch(self, &rpc)
  ```

* **Layout match.** Public `iokit/DriverKit/IORPC.h`:

  ```c
  struct IORPC {
      IORPCMessageMach * message;        // +0x00
      IORPCMessageMach * reply;          // +0x08
      uint32_t           sendSize;       // +0x10
      uint32_t           replySize;      // +0x14
      IORPCMessage     * kernelContent;  // +0x18  (KERNEL only)
  };                                     // 0x20 bytes total
  ```

  and `#pragma pack(4) struct IORPCMessage { uint64 msgid; uint64 flags;
  uint64 objectRefs; OSObjectRef objects[]; }`.

* **Field usage in the dispatcher** (`0xfffffe000b31e234`, dump in §5):

  | code | reading |
  |---|---|
  | `ldr x21,[x1,#0x18]; ldr x8,[x21]` | `x21 = rpc.kernelContent`; `x8 = msgid` compared against four baked 64-bit IDs |
  | `ldr x11,[x21,#0x10]; cmp #1 / #2` | `objectRefs` required to be 1 or 2 |
  | `ldr w10,[x1,#0x10]; cmp #0x26c/#0x104` | `sendSize` thresholds |
  | `ldr w9,[x1,#0x14]; cmp #0x54/#0x3c` | `replySize` thresholds |
  | `ldr x12,[x21,#8]; and #~0x100; str` | **`flags` bit 8 cleared before dispatch** |

* **Base-class default.** `OSObject`'s slot-12 entry (`0xfffffe0007f075c8`
  table, entry `0xfffffe000b316068`) is a three-instruction stub returning
  `0xe00002c7` (`kIOReturnUnsupported`). So slot 12 is a root-level virtual
  that `IOUserClient` overrides — consistent with a `Dispatch` declared on
  `OSMetaClassBase`/`OSObject` and overridden per class.

* **Exactly one subclass override.** Census of all 260 `IOUserClient` /
  `IOUserClient2022` descendants: 254 carry `0xfffffe000b31e208` unchanged
  (including all five IOHIDFamily user clients); the sole override is
  **`IOUserServer`** — vtable `0xfffffe0007ed8660`, slot-12 entry
  `0xfffffe0007ed86c0 -> 0xfffffe000b328138`, the same by-value wrapper calling
  its own dispatcher `0xfffffe000b328164` with its own msgid cookies and the
  same `and ...,#~0x100` clear at `0xfffffe000b3281dc`.

* **Corroborating strings.** `'DK: %s-0x%qx: %s::Dispatch kernel 0x%qx'` at
  `0xfffffe00070c84d8` is referenced from `0xfffffe000b3fa908` — one of the
  containing functions of our dispatch sites — and `'DK:
  %s::Dispatch(trap) kernel 0x%qx'` from `0xfffffe000b3fb294`. No function
  embeds an assert/signature string naming the thunk or dispatcher, so this is
  structural identification, not a symbol lookup.

**Correction carried forward:** the earlier AppleSmartIO hint
(`AppleSmartIOUserClient::externalMethod(uint32_t,
IOExternalMethodArgumentsOpaque *)`) does **not** make slot 12
`externalMethod`. An anchored method→slot map places `externalMethod` at slot
168, and `AppleSmartIOUserClient`'s vtable carries the `Dispatch` thunk at slot
12 like everyone else.

## 3. The provenance gate from the previous checkpoint dissolves

The previous run found one glue path (`0xfffffe000b3fb294`) that "writes a
status code at `+0x00` and a stack buffer at `+0x18`" and read that as
contradicting "`[args+0x18]` is an object". Under the `IORPC` reading there is
no contradiction: `+0x00`/`+0x08` are the `message`/`reply` Mach-message
pointers, `+0x10`/`+0x14` are the two sizes, and `+0x18` is `kernelContent`,
a pointer the **kernel** filled when it decoded the incoming RPC. It is
necessarily kernel-built, and the dispatcher reads it as an object (msgid,
objectRefs, flags).

Observed marshalling across the 11 sites is uniform in size but not in origin —
some build the `IORPC` inline, some copy 32 bytes from a source buffer, one
copies the caller's `x1` and dispatches on `[x0+0x18]`:

```
; site 0xb3fb4fc (func 0xb3fb294) — inline build
stp x25, x20, [sp, #0x40]
stp w28, w19, [sp, #0x50]
str x22, [sp, #0x58]
ldr x16,[x23]; autda; ldr x8,[x16,#0x60]! ; add x1, sp, #0x40; blraa

; site 0xb3fab20 (func 0xb3fa908) — wholesale 32-byte copy
ldp q0, q1, [x25]; stp q0, q1, [sp, #0x30]
ldr x16,[x19]; autda; ldr x8,[x16,#0x60]! ; add x1, sp, #0x30; blraa

; site 0xb3e8ee0 (func 0xb3e8ea0) — copies caller's x1, dispatches on [x0+0x18]
ldp q0, q1, [x1]; stp q0, q1, [sp]
ldr x0, [x0, #0x18]; ... ldr x8,[x16,#0x60]! ; mov x1, sp; blraa
```

So "who builds `kernelContent`" is now the relevant question, not "object or
copied input".

## 4. The 27.2 delta re-read

The four clears are on `IORPCMessage.flags` bit 8 (0x100). That bit is **not**
in the public flag enum:

```c
enum{ kIORPCMessageRemote=1, kIORPCMessageLocalHost=2, kIORPCMessageKernel=4,
      kIORPCMessageOneway=8, kIORPCMessageObjectRefs=0x10,
      kIORPCMessageOnqueue=0x20, kIORPCMessageError=0x40,
      kIORPCMessageSimpleReply=0x80 };
```

so it is a private/reserved flag. In 27.0.1 the bit survives into the four
msgid-specific branches; in 27.2 it is cleared first. That is a fix-shaped
change on the target build (Apple changed code = something was live), but what
the bit gates, and whether user space can set it, are both unknown.

## 5. Reachability: unresolved, and structurally gated

Direct `BL` callers of the two engine entry points were scanned word-level
across every member:

| engine entry | direct callers |
|---|---|
| `0xfffffe000b3fa908` | `0xfffffe000b3fb070` inside `0xfffffe000b3fad34` (sz `0x4e8`) |
| `0xfffffe000b3fb294` | `0xfffffe000b3d9bfc` inside `0xfffffe000b3d9ac8` (sz `0x310`) |

Neither caller set contains MIG glue (`is_io_connect_method` and friends).
The dispatch engine sits behind `IOUserServer`-style DriverKit machinery, which
is not driven by `IOServiceOpen` + `IOConnectCallMethod` on iOS. The five
IOHIDFamily user clients inherit the base implementation, but inheritance of a
virtual says nothing about whether any caller invokes it for them.

**Verdict: bounded reconnaissance, no vulnerability claim.** A named fix site
(`IOUserClient::Dispatch`, `IORPCMessage.flags` bit 8) whose app reachability is
unproven and currently looks gated by DriverKit RPC ingress. Do not spend a
device cycle on this until an app-facing ingress exists.

### 5.1 Follow-up: both engine entries are invoked indirectly

Raw word scan for each engine entry's rebase offset finds **exactly one**
arm64e pointer slot apiece, both in outer `__DATA_CONST`:

| target | slot VA | stored qword |
|---|---|---|
| `0xfffffe000b3d9ac8` | `0xfffffe0007e8c980` | `0x8010307a043d5ac8` |
| `0xfffffe000b3e8ea0` | `0xfffffe0007ed74f0` | `0x80119209043e4ea0` |

Neither has any `BL`/`B` caller in the image and neither appears in the chained
fixups; controls (`0xb3fa908`, `0xb3fb294`) have zero pointer slots and only
`BL` callers, so the detector is not returning noise. The `0x7ed74f0` table
carries the same shared base-class virtual bodies as slots +2..+11 of the
`IOUserClient` base vtable, with the class-specific entries at slot 7
(`0xb3e8f00`) and **slot 12 (`0xb3e8ea0`)** — i.e. a *second* slot-12 override
besides `IOUserServer`'s, missed by the census. `0xb3e8ea0` (sz `0x60`) copies
the incoming `IORPC` and tail-dispatches slot 12 on `[this+0x18]`. Full dumps:
`analysis/evidence/bit8-slot12-2026-11-17/slot12-reach-followup.txt`.

## 6. Next step (bounded, static)

1. Name the owning class of the `0x7ed74f0` table (find the stored vptr /
   adjacent `OSMetaClass` constructor) and characterise the `0x7e8c980` array;
   that converts "invoked via data table" into a concrete ingress path or a
   hard negative.
2. Cheap secondary: find what private `flags` bit 8 means — search `iokit`
   sources for a `kIORPCMessage...` name in the `0x100` range, and check whether
   any 24A446 function *sets* it.
3. If neither table resolves to an app-visible message path, close the bit-8
   cluster as reconnaissance-only and return the effort to the VM/VFS and
   external-object leads.
