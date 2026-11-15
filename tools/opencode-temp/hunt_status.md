
---

## 12. Fresh-bug hunt status (2026-11-12)

Tooling built today, reusable for the hunt:

* `tools/opencode-temp/ContentView-v122.swift` - the AGXProbe harness with four
  modes: `--geom` (the IOSurfaceRoot create + control matrix), `--metal`
  (Metal compute cross-object test), `--fuzz` (IOSurfaceRoot method sweep) and
  the older race mode.
* The IOSurfaceRootUserClient dispatch table is decoded (60 selectors, with
  scalar-input counts and structure sizes), so every method can be called with
  the shape the kernel expects - `tools/opencode-temp/methmap.py` /
  `selmap3.py` rebuild it from the kernelcache.
* Metal works end to end now: the Metal toolchain component is installed and
  `probe.metal` is compiled by Xcode into the app's `default.metallib`
  (a hand-built metallib is rejected by the device with
  `MTLLibraryErrorDomain Code=1 "Invalid library file"` - it has to come from
  the app bundle).

### 12.1 IOSurfaceRoot method sweep (`--fuzz`), both devices

Sweep of the methods that take a caller-sized structure, using each method's
real scalar count and structure size from the decoded table, with hostile
lengths and contents (zeros / all-ones / 0x41 pattern / 0x7fff... / an
offset-like value).

| outcome | 13 Pro (24A5390f) | 17 Pro (24A446) |
|---|---|---|
| `BadArgument` (0xe00002c2) | 719 | 719 |
| `BadMatching` (0xe00002c1) | 5 | 5 |
| `0xe00002bf` (IPCError) | 5 | 5 |
| `NoMemory` (0xe00002bd) | 1 | 1 |

**The two kernels behave identically** - no differential, and no crash or
panic on either device.  The three calls that get past the argument check are:

| call | result | note |
|---|---|---|
| `sel 0x06, 32-byte struct of zeros` | `NoMemory` | `0x06` = `create_surface_fast_path`; the struct is `{u32 count, values...}` and the kernel maps the values onto six fixed keys (`IOSurfaceBytesPerRow`, `IOSurfaceWidth`, `IOSurfaceHeight`, `IOSurfacePixelFormat`, `IOSurfaceAllocSize`, `IOSurfaceAddress`) |
| `sel 0x1e, 1 scalar, no struct` | `BadMatching` | a name/service lookup |
| `sel 0x22, 1 scalar, no struct` | `0xe00002bf` | dispatches an IPC - this is the `IOSurfaceShared` / "client shared id" family (`IOSurfaceRootUserClient: asked to allocate client shared id %08x not known by IOSurfaceRoot`) |

Everything else is rejected at the entry check, so a length-handling bug in
those paths needs the *exact* shape first, then hostile contents.

### 12.2 What is established about the two IOSurface leads

| lead | status on 24A5390f / 24A446 |
|---|---|
| per-slice 32-bit overflow (IOSurface plane parser) | reachable unprivileged, control-verified (§11.1), **inert** - the values are stored but never consumed, and the descriptor does not carry them (§11.6/§11.7) |
| notify UAF (CVE-2026-112477) | reliable dangling nodes (hundreds per run), but PAC-authenticated: read-or-panic, no write |
| F1 GPU cross-object write | does not reproduce here: the surface is not importable as a texture, the descriptor lacks the per-slice values, the OOB GPU write is masked, and the transcript's own addresses are 32-bit-truncated (§11.8) |

Neither can carry a jailbreak, so the hunt continues on new surfaces:
the `IOSurfaceShared` / "client shared" IPC path (`0x22`), the memory-pool and
descriptor-family methods (`0x1a`, `0x2e`, `0x36`, `0x0a`), and - beyond
IOSurface - the sandbox-reachable kexts with no entitlement gate, where a
lifetime bug would give a real kernel write.
