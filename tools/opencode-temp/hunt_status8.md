
### 12.10 Stage 1 executed: the trigger reached the WebKit networking daemon

Built on the Mac (from `tools/opencode-temp/brotlirepro.swift`, `-DBROTLI_CLI`):

```
[br] stage1=23068693 B stage2=127 B chunk=65536
[br] VERDICT: CORRUPTED STATE REACHED (runaway output 16777216 B from 127 B input)
shasum -a 256 /tmp/stage1.bin
  87a88ee96e68f6d17a17e1ea01857326b30689cf23337dfbb319424b2a761fcf   (matches the
  documented value)
```

`/tmp/brtest` = stage1 ‖ stage2 (23,068,820 B), served by
`tools/opencode-temp/brserver.py` with `Content-Encoding: br`; the server aborts
the connection immediately after the body so the decoding daemon never buffers
the runaway output.

Fired from the 13 Pro with the app's `--web` mode (a `WKWebView`):

```
REQ GET /brtest ua='Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)
                   AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'
```

The 23 MB Brotli body was fetched and decoded **by the WebKit networking
process** - a system daemon - twice in a row ✓.

**No crash and no jetsam of the daemon**, which is exactly what the Brotli
repro predicts: the wild `memmove16` lands in mapped heap, so the corruption is
**silent** (`analysis/brotli-CVE-2026-111497-repro.md`: "silent heap corruption,
not a reliable crash").  A crash is therefore the wrong detector; the reliable
detectors are (a) the runaway output (the daemon balloons) and (b) a controlled
write landing on a chosen object.

**So stage 1 is: reachability ✓, delivery ✓, corruption very likely ✓, and the
remaining work is the hard part - turning a silent, wild `memmove16` with
attacker-controlled source and length into a chosen write inside a foreign
system daemon.**  Concretely:

1. Find the wild write's destination control.  `memmove16` uses
   `dst = ringbuffer + pos`, where `pos` is the corrupted output position.  The
   parameters are `d15=d19=d23=0x7fffffff`, `b7=8` - so the *length* is
   attacker-influenced and the *source* is attacker-controlled, but `pos` is
   derived from the output position.  Sweeping `d15/d19/d23` and `b7` changes
   where the write lands; find a combination that lands on a heap object we can
   groom (an Objective-C instance pointer, a block's `isa`, a C++ vtable).
2. Groom the daemon's heap: the trigger body is 23 MB of decoder output, which
   gives plenty of allocation churn to place a chosen object right after the
   ring buffer.
3. Detect RCE in the daemon from outside (the page runs in the *WebContent*
   process, so the daemon's state has to be observed indirectly - e.g. the daemon
   stops servicing requests, or a marker shows up in a later response).
4. From RCE in the networking daemon: open `IOSurfaceRoot` (it has the
   entitlement) and read `client+0x122` bit 0 - if set, the gated
   descriptor/memory-pool methods unlock, which is where the kernel OOB and
   ultimately r/w live.  Then patch and install Sileo.

The iPhone 6s+ (198.51.100.1, iOS 15.8.8, Dopamine, SSH on 22 and 2222) is
the right place to develop steps 1-3: a known WebKit build, a jailbroken
device for debugging, and no risk to the research device.
