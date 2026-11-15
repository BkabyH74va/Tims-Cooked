
### 12.6 Descriptor-family ABI (recovered) and the probe results

Recovered from the dispatch table + handler prologues
(`tools/opencode-temp/abi.py` dumps the thunk and the first instructions of the
real function for any selector).

**The external-method argument blob** (as the kext sees it):

| offset | meaning |
|---|---|
| `+0x20` | scalar input array pointer (`+0x28` = count) |
| `+0x30` | structure input pointer (`+0x38` = size) |
| `+0x40` | a **user pointer that the kernel dereferences** (`+0x48` = scalar output) |
| `+0x58` | structure output pointer (`+0x60` = size) |

**Per-selector findings:**

* `0x1e` - `ldrb w8,[x0,#0x122]; tbz w8,#0,...` : the method is gated on a
  **client capability bit** (`client+0x122` bit 0) that an unprivileged
  type-0 client does not have, so this path is entitlement-gated.
* `0x22` - takes `scalarIn[0]` + a structure output and immediately dispatches an
  IPC; it answers `0xe00002bf` for every client-shared id 0..256, i.e. the
  shared-region table is empty on a fresh connection.
* `0x1a` - `x23=[args+0x30]` (structure in), `w25=[args+0x38]` (size),
  `x0=[args+0x40]` (a **user pointer**, dereferenced as an object),
  `x24=[args+0x58]` (structure out), `w27=[args+0x60]` (size). The kext's own
  field names for this family are *Descriptor address*, *Pool Id*, *Components*,
  and per component *Length* / *Options* - so the structure is a
  `{u64 descriptorAddress; u32 poolId; u32 componentCount; ...}` plus a component
  array read through the user pointer. **This is the one place where a
  userspace pointer and a userspace count meet a kernel walk** - the shape that
  yields an OOB - so it is the best remaining candidate inside IOSurface.
* `0x06` (`create_surface_fast_path`) - the 32-byte structure is
  `{u64 pointer; u32 values[6]}`; the first slot is a user pointer that the
  handler tests with `ldr x0,[x23]; cbz` and, when non-NULL, allocates 0x40
  bytes and calls the object with the `IOSurfaceAddress` key. Tried three ways
  (count-as-u32, a real 0x40-byte user pointer, the six keys in order) - all
  `BadArgument`: the fast path reuses the client's stored properties, so a bare
  structure is never enough.

**Descriptor-family probe** (`0x1a`, `0x13`, `0x18`, `0x2e`, `0x36`, `0x2f`,
`0x30`, `0x32` x {componentCount 0,1,2,8,64,1024} x {poolId 0,1} x a real
0x4000-byte user buffer): **every** combination returns `BadArgument`. The
structures need their real layout - the component array is probably an array of
kernel-side objects rather than a user array, and `0x1a`'s `+0x40` pointer may be
a *context object* rather than a plain user buffer.

**Next:** read the `0x1a` handler past the entry check to see how it uses
`x0` (`args+0x40`) and `w25` (the structure size) - that is where the user
pointer and the length meet.
