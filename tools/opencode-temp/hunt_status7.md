
### 12.9 Stage 1 reachability: CONFIRMED (WebKit networking process)

`--web` mode in `tools/opencode-temp/ContentView-v122.swift` puts a `WKWebView`
in the app; the Mac serves on `:8777` (`tools/opencode-temp/brserver.py`, logs
every request with its User-Agent).  Run on the 13 Pro:

```
REQ GET /brtest ua='Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)
                   AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'
```

The request came from **WebKit**, i.e. from the WebKit *networking* XPC service -
a **system daemon**, separate from our app, which (a) decodes `Content-Encoding: br`
and (b) legitimately uses IOSurface and therefore holds the IOKit entitlements that
set the `client+0x122` capability bit the gated IOSurfaceRoot methods need.

**This is the whole point of doing the escape first**: the same trigger that is
useless inside our own app runs in a daemon that can open `IOSurfaceRoot` with a
privileged client, which is what unlocks selectors `0x1e` and the
descriptor/memory-pool family.

**Next, concretely:**

1. Generate the trigger payload on the Mac with the existing Swift CLI
   (`tools/opencode-temp/brotlirepro.swift`, `-DBROTLI_CLI`): stage1
   (23,068,693 B) followed by stage2 (127 B) into one file, served as
   `Content-Encoding: br` from `/trigger`.
   *Safety:* the decoder's corrupted state produces unbounded output (127 B in ->
   gigabytes out), so the server must **abort the connection** right after
   stage2 - the heap corruption has already happened at that point, and the
   runaway output never gets buffered.
2. Watch the 13 Pro: the WebKit networking process should die (or misbehave) -
   that is the trigger firing in a system daemon.
3. Turn the corruption into control there: the wild `memmove16` has an
   attacker-controlled source and length, so heap grooming can aim it at a chosen
   object (an Objective-C instance pointer, a block's `isa`, a `__block` pointer).
4. From the hijacked daemon, open `IOSurfaceRoot`, read `client+0x122` bit 0, and
   if it is set, drive the descriptor/pool methods to the kernel OOB; then r/w,
   patch, Sileo.

The iPhone 6s+ (198.51.100.1, iOS 15.8.8, Dopamine, SSH on 22 and 2222) is
available to develop steps 1-3 without risking the research device.

Note: the Mac's `libcompression` has **no Brotli encoder** (decode only - an
encode call segfaults), so the payload must be produced by our own generator, not
by compressing on the Mac.
