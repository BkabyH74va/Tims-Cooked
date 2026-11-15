
### 12.3 Probe of the two deep paths (2026-11-12, later)

`--probe` on the 13 Pro:

```
sel0x22 client-shared-id sweep 0...256: 0xe00002bf=257
0x1e <name> s0/s1/s2 -> BadArgument   (IOSurfaceDescriptorContext,
   IOSurfaceMemoryPoolBunch, IOSurfaceDescriptorComponent, IOSurfaceShared,
   IOSurfaceRoot, IOSurfaceRootUserClient, IOSurfaceClient)
```

* `sel 0x22` answers `0xe00002bf` (IPCError) for **every** id 0..256 - the
  scalar is not a client-shared id (or the shared region table is empty, which
  is the expected state for a fresh client), so the "allocate a client shared
  id" path is not reachable from a fresh connection yet.
* `sel 0x1e` gets *worse* (BadArgument instead of BadMatching) once the struct
  carries a name, so the struct is not a plain C string - the name is probably
  an `OSString`/CF object pointer or the name lives in a different field.

Both need the exact ABI. The efficient way to get it: the handler for `0x1e`
and `0x22` can be read straight out of the dispatch table
(`tools/opencode-temp/methmap.py` -> handler -> thunk), then the *kext's own
string table* gives the key names the method expects (the strings around
`IOSurfaceDescriptorContext` / `IOSurfaceMemoryPoolBunch` /
`IOSurfaceDescriptorComponent` in
`firmware/24A446/kernelcache.release.macho` at
`0xfffffe0007a1bc91`+). Those two families - the descriptor context and the
memory-pool bunch - are the newest code in the kext and the only place left in
IOSurface where a userspace-controlled length meets a kernel allocation.

The other IOSurface lead worth one more shot is `sel 0x06`
(`create_surface_fast_path`): its 32-byte struct is `{u32 count, values...}`
and the kernel allocates `count * 0x40` bytes and copies the values onto six
fixed keys. `count` is user-controlled and the copy reads `count` u32s out of a
32-byte struct - i.e. it reads past the end of the kernel's copy of the
structure when `count > 8`. That is an out-of-bounds *read* of the kernel's
method buffer (an info leak, not a write) and needs `count` to be accepted:
the fast path rejected our attempts with `NoMemory`/`BadArgument`, so the
struct's remaining fields still have to be filled in.

### 12.4 Order of work from here

1. Read the `0x1e` / `0x22` handlers from the dispatch table and reconstruct
   their input ABI; re-probe with the exact shape.
2. Fill in the `0x06` fast-path struct (all eight u32s) so `count` is
   accepted, then sweep `count` (1..64) for the OOB read.
3. Move outside IOSurface: the assessment's Lead #2 (kext lifetime / UAF over
   sandbox-reachable, non-entitlement-gated kexts) is still unexamined and is
   where a real kernel *write* is most likely to live.
