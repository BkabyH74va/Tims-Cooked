
### 12.8 The out-of-sandbox foothold, and the key inversion it exposed

The Terminal-app SSH server on the 13 Pro (a-Shell's `ios_system()` engine, no
fork/exec) gives an out-of-app-sandbox context:

```
uid=501(mobile) gid=501(mobile)
Darwin localhost 27.0.0 Darwin Kernel Version 27.0.0 ... RELEASE_ARM64_T8110 iPhone14,2
python3 -c "print(6*7)"   ->  42        # python3 works via the subprocess path
ls /var/mobile            ->  Operation not permitted
```

Commands must be piped over the SSH channel (the session is an interactive
a-Shell, not an exec channel), and the working directory is `~/Documents`
(`/tmp` is not writable).  Files are transferred by serving them from the Mac
and fetching with `urllib.request` - that avoids the quoting problems of
pushing a long base64 blob through the shell.

**The inversion.**  From this context, `IOSurfaceRoot` cannot be opened **at
all**:

```
IOSurfaceRoot service = 0xa703
IOServiceOpen(IOSurfaceRoot, type=0..7) -> BadArgument (all eight)
match IOSurfaceRootUserClient -> 0x0      # does not exist
match IOSurfaceUserClient     -> 0x0
```

while our **sandboxed app** opens `IOSurfaceRoot` with type 0 without complaint
(the free-provisioned profile grants it).  So the Terminal/`mobile` context is
*more* restricted for IOKit than the app - the opposite of "better vision".

**Consequence for the chain.**  A generic sandbox escape is *not* enough: the
escape has to land in a **system daemon** that already holds the IOKit
entitlements - the WebKit **Networking** process is the natural target, because
it (a) decodes `Content-Encoding: br` and (b) legitimately uses IOSurface.
WebKit's networking service is a separate system XPC process, so a `WKWebView`
in our app is enough to make it decode our Brotli payload - no user interaction
and no Safari needed.

**Revised stage 1 (the part that is not done):**

1. Serve the Brotli stage1+stage2 payload (23,068,693 + 127 bytes,
   `Content-Encoding: br`) from the Mac; make a `WKWebView` in our app fetch it.
2. Turn the silent corruption into a controlled write: the wild `memmove16` has an
   attacker-controlled source and length, so heap grooming can aim it at a chosen
   object (an Objective-C instance pointer, a block's `isa`).
3. From the hijacked WebKit networking process, open `IOSurfaceRoot` and read
   `client+0x122` bit 0 - WebKit's entitlements should set it, which is exactly
   what selector `0x1e` and the descriptor/pool family require.
4. Drive those gated paths to the kernel OOB, get r/w, patch, install Sileo.

The iPhone 6s+ (198.51.100.1, iOS 15.8.8, Dopamine, SSH on 22 and 2222) is
available as a free place to develop and debug steps 1-2 before porting to
24A5390f.
