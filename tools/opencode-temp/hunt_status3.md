
### 12.5 Probe results for `0x06` / `0x22` (13 Pro and 17 Pro, identical)

```
sel0x22 client-shared-id sweep 0...256: 0xe00002bf=257
sel0x06 fast-path count sweep 0...64:  BadArgument=65
```

`0x06` was tried three ways, all rejected at the entry check:
1. struct = `{u32 count, u32 values[6]}` (count swept 0..64);
2. the same with `count` replaced by a real 0x40-byte **userspace pointer** in the
   first slot (the handler does `ldr x0,[x23]; cbz` and, when non-NULL,
   allocates 0x40 bytes and calls the object with the `IOSurfaceAddress` key);
3. the same with the six values in the order
   BytesPerRow / Width / Height / PixelFormat / AllocSize / Address.

So `0x06` needs more than a 32-byte structure - most likely the *client* must
first own a property set (the fast path reuses the client's stored properties
and the structure only supplies the six values), which is why
`create_surface_fast_path` was never reachable with a bare structure.

`0x22` answers IPCError for every client-shared id: the shared-region table is
empty on a fresh connection, so the "allocate client shared id" path needs a
prior allocation (probably `0x2f`/`0x30`/`0x32`, the variable-structure
methods) before `0x22` can be driven.

**Status of the hunt:** IOSurface is now characterised end to end and offers no
r/w path on 24A5390f / 24A446 (§11.6, §11.7, §12.5). The next candidate
surface is outside IOSurface: sandbox-reachable kexts with no entitlement gate
(the assessment's Lead #2), where a lifetime bug would give a real kernel write.
