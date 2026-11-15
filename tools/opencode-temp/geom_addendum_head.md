# IOSurface geometry-acceptance probes on t8150 / iOS 27.0.1 — 2026-11-08

> **UPDATE 2026-11-12 — the direct route is OPEN, not closed.**
> §9 concluded that driving the `IOSurfaceRoot` user client directly was closed
> because every shape returned `0xe00002c2`.  That conclusion was wrong: the
> **scalar input must be `0`**.  With `scalarIn[0] = 0` the call succeeds on
> **both** target devices (13 Pro / 24A5390f and 17 Pro / 24A446), the per-slice
> validation block in the kernel **is** reached and **is** live, and the
> 32-bit `(data + header) * sliceCount` overflow is reachable unprivileged.
> See the Addendum at the end of this file.

**Device:** iPhone18,1 / iPhone 17 Pro / t8150 — iOS 27.0.1 (24A446), UDID `REDACTED_DEVICE_ID`
**Harness:** `~/agx-probe-project` (Xcode 27.2), app `com.nianticlabs.pokemongo.4L9HF29JJU`
**Safety:** every probe below is read-only — no Metal, no GPU submission, no writes to
any surface, no cross-object attempt. Surfaces are created, inspected, released.
