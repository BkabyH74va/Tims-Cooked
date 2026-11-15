
### 12.7 Reordering the chain: sandbox escape first, then the kernel bug

The reference tool's transcript does exactly this, and the order matters:

```
Preparing system services... / Preparing execservice...
Escaping sandbox...                 <- stage 1: user space
Execution returned.
Preparing kernel access...          <- stage 2: kernel
Preparing privileged execution... proc/task/map/pmap
```

**Why the escape must come first.** The IOSurfaceRootUserClient capability bit
that gates the interesting methods (`client+0x122` bit 0, checked by selector
`0x1e`) is enforced by the *sandbox*, not by the kernel: a client opened
from our sandboxed app never gets it. Escaping the sandbox (or moving the
exploit into a process whose sandbox profile is broader) is what makes the
gated IOSurfaceRoot paths - the descriptor / memory-pool family, where a
userspace pointer and a userspace length meet a kernel walk - reachable at all.

**What we have for stage 1:**

| primitive | state |
|---|---|
| CVE-2026-111497 (Brotli `ProcessCommandsInternal` OOB write) | verified on both devices; **silent** heap corruption (no fault), with the 23,068,693-byte stage 1 + 127-byte stage 2 reproducer and the "runaway output" signature (`analysis/brotli-CVE-2026-111497-repro.md`) |
| reachability | any process decoding `Content-Encoding: br` - CFNetwork / `nsurlsessiond` / the WebKit **Networking** process. The WebKit networking service is a *system* XPC service, so a `WKWebView` in our app is enough to make it decode our bytes |
| open foothold | the Terminal-app SSH server on the 13 Pro (`python3 ~/Documents/sshd.py`, port 2222) runs as `mobile` outside our app's sandbox; it is **currently down** |
| dev platform | the iPhone 6s+ (198.51.100.1, iOS 15.8.8, Dopamine) has SSH up on 22 and 2222 - a free place to develop and debug the stage-1 chain (heap grooming in a foreign process) before porting it to 24A5390f |

**Stage 1 plan** (the part that is not done yet):

1. Serve the Brotli payload (stage 1 + stage 2, `Content-Encoding: br`) from
   the Mac and make a system WebKit process decode it - a `WKWebView` in our
   app is enough, no user interaction.
2. Turn the silent corruption into controlled writes: the wild `memmove16`
   has an attacker-controlled source and length, so with heap grooming it can
   hit a chosen object (an Objective-C instance pointer, a block's
   `isa`/function pointer).
3. From the hijacked system process, re-open `IOSurfaceRoot` and compare
   `client+0x122` with what our sandboxed app gets. If the capability bit is
   set, the gated descriptors/pool methods become callable - that is the
   "better vision" the escape buys, and it is exactly the surface where a
   userspace-controlled length reaches a kernel allocation.
4. Only then drive the kernel bug from that process (where the entitlement
   lets us reach the gated paths), get r/w, and patch for Sileo.

**Needed from the user:** start the Terminal-app SSH server on the 13 Pro
(`python3 ~/Documents/sshd.py`) so we have an out-of-sandbox foothold on the
target for step 3's comparison, and so the stage-1 chain can be developed
against the device rather than only on the 6s+.
