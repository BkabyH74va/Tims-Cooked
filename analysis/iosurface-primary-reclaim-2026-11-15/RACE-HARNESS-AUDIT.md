# CVE-2026-112477 race-harness evidence limits

Read-only review of `ContentView-v115.swift`, plus ABI cross-checks against `ContentView-v116.swift`, `ContentView-v20.swift`, the 24A446 IOSurface disassembly, and the public XNU argument layout; no source or device changes.

## Confirmed from the harness

- `RaceCtx` fields (`ops`, `okSet`, `errSet`, `lateOK`, `afterOK`, `closing`, `closed`, `stop`) and the per-thread `flags` are ordinary Swift integers. Multiple worker threads write/read them and the main thread polls them without atomics or locks (lines 87-106, 894-920, 987-1015). The aggregate counters therefore are not a reliable concurrent measurement.
- `afterOK` increments when a `setWrap` call returns and observes `closed == 1` (lines 1000-1012). `closed` is set after `IOServiceClose` returns (lines 894-900). The harness does not record call-start time or the actual insertion/unlink ordering, so `after=556` does not prove registration occurred after `unlinkByObject` ran; an operation can execute during teardown and return later.
- The receive helper counts every message without checking message ID or payload (lines 238-255). The race passes the same port as the call's third argument and as the first qword of the notify input (lines 998-1004). Before treating any receive as a stale notification, distinguish it from any async completion message; whether the target method emits such completions is not established here.

## ABI/source cross-check

`SetWrapFn` has 13 parameters (lines 72-85), and its calls follow the shape of `IOConnectCallAsyncMethod`. The iOS 27.2 SDK header gives that API's ordered parameters: connection, selector, wake port, reference pointer/count, scalar input/count, structure input/size, scalar output/count, structure output/size. Apple’s public `IOKitUser` implementation forwards this call to `io_connect_async_method`; public XNU `IOUserClient.cpp` then calls `client->callExternalMethod` and returns that result. This is reference-source evidence, not proof of the exact 24A446 implementation. It supports treating a successful API return as stronger than mere client-side enqueue, but it still does not identify when the handler inserted its node relative to teardown.

## Assessment / next validation bar

The source demonstrates concurrent calls around `IOServiceClose`; it does not by itself prove the claimed post-unlink dangling-node state. The recorded device runs had no victim-port notification or kernel panic. Before calling the race “won,” use atomic synchronization and per-call begin/end accounting, filter Mach message IDs, and require an independent stale-node observable. Do not rerun the panic-capable path just to increase counters.

## Additional detector-setup inconsistency

`ContentView-v115.swift` says selector `0x24` fills the notify table (lines 424-427, 863-879), but the existing analysis note says `0x24` only attaches a client to a global slot and returns a handle; it does not create the notify-table entry needed by `notifyOne` (`iosurface-notify-uaf-CVE-2026-112477.md`, lines 442-480). The v115 code also sets `shapeOK = true` from the `rcA`/`rcB` calls at lines 520-527 without setting `workingProbeIdx`; downstream setup is gated on both `shapeOK` and `workingProbeIdx >= 0` (lines 798, 868). Therefore a successful shape probe alone can still skip table setup. Unless newer runtime evidence resolves this mismatch, zero victim notifications are an inconclusive detector result, not evidence that no dangling node exists.

The next safe step is to resolve the `0x24` behavior and the actual table-populating selector/structure statically, then instrument a benign delivery control before any teardown race is considered again.

## Selector 0x04 ABI direction: corrected

The 24A446 thunk at `0xfffffe000a34932c` loads the first scalar from `arguments+0x20` and passes `x2 = [arguments+0x58]` to handler `0xfffffe000a34beb0`. In the public `IOExternalMethodArguments` layout, `+0x58` is `structureOutput`, not `structureInput`; the handler passes that pointer to `0xfffffe000a33ca2c`, which writes fields into it. That helper treats `output+0xc68` as the end of its variable region, consistent with a `0xc68` output buffer. The exact dispatch size check and complete output schema remain unverified.

The handler's branch also matters: `0xfffffe000a34f8cc` returns 1 for a valid occupied client-table slot, and the `0x04` handler routes that case to the `0xe00002c2` (`BadArgument`) return. Otherwise it resolves through the root with `0xfffffe000a3442ec`, obtains a client entry, stores that entry at the resolved global slot through `0xfffffe000a34fb38`, and serializes it to the output. So this is not merely a buffer-shape probe; it can mutate the client's table when its preconditions succeed. The v116 comment describing `lookup()` as resolving the client's local slot is misleading: the occupied-slot case is rejected, while a miss continues into the root resolver.

A separate allocator cross-reference narrows the scalar's role. Resolver `0xfffffe000a343de8` indexes the root array with the scalar and verifies the returned object's `+0x10` field equals it. Allocator-shaped function `0xfffffe000a346460` scans the root's allocation bitmap and writes the chosen slot through its output pointer; caller `0xfffffe000a32b260` passes the candidate object's `+0x10` field. This statically links the selector scalar to a generated root-slot field. It does not yet prove that the same field is exactly the public `IOSurfaceID` returned by the create path.

The available 27.2 shared-cache `_IOSurfaceGetID` entry (`0x1c2845360`) loads a per-image offset, dereferences a pointer from the public wrapper object, and branches to `_IOSurfaceClientGetID` (`0x1c28456d0`), which returns the 32-bit field at `+0x88`. This identifies the user-space accessor field, but not how creation copies the kernel root slot (`+0x10`) into it; the local 27.2 image is reference-build evidence only.

The same 27.2 image's `_IOSurfaceClientSetSurfaceNotify` (`0x1c284a6e8`) constructs a 24-byte structure from its first two arguments plus a zero third word, then invokes selector `0x11`. That layout matches v116's `{1, id, 0}` input. On 24A446, the target thunk forwards `structureInput` to the registration routine, which stores its third qword as `node+0x50`; a zero there cannot serve as the nonzero index required by the target lookup. This is useful ABI corroboration, not proof that the 27.2 wrapper and 24A446 kernel pair have identical behavior.

The v116 `0..15` loop reuses the same `connC` for all candidates, and the source later reuses `connC` for a notification test. Because a successful `0x04` call inserts a table entry, this is stateful, not a set of independent/read-only shape probes; per-index success and any mutation were not preserved in a run log. Validate one candidate on a fresh connection with a confirmed root index before interpreting subsequent calls.

The Mac build-host `IOSurfaceNotifyProbe.c` v14 has now been run on both phones using a temporary CLI dispatch in an isolated project copy; the C probe source was unchanged. Both complete 400 release/recreate iterations and phase-A/B runs finished without a crash or new crash report. On each device, the first of 48 sprayed surfaces received the just-released surface's public ID; a subsequent set returned `0xe00002c9`, remove returned 0, and the next set returned 0. This establishes registration state remained findable across surface release and public-ID reuse, not that a dangling client pointer was dereferenced. The target request's `+0x58` is the notifier `IOSurfaceRootUserClient` pointer; v14 releases `IOSurface` objects and does not close a private root user-client connection. Therefore, despite its name, v14 does not exercise the candidate user-client teardown race. Full limitations and device-specific evidence are in `analysis/iosurface-notify-run-2026-11-15/RESULT.md`; raw logs remain local.

 Its 13-argument `SetWrapFn` shape matches `IOConnectCallAsyncMethod`[1]; under that mapping, `outS` is `structureInput`. The target thunk at `0xfffffe000a3498f4` forwards `arguments+0x30` (the `structureInput` field in public XNU `IOUserClient.h`[2]) to register `0xfffffe000a3460f0`, which stores `structureInput+0x10` in `node+0x50`. In v116's `connC` test, `outS` is `{1, id, 0}`, so the index is 0 under this mapping and the target lookup rejects it. The 27.2 reference framework's `_IOSurfaceClientSetSurfaceNotify` also constructs a 24-byte input from two arguments plus a zero third word before calling selector `0x11`; this supports the decoded structure layout, but does not prove the 24A446 framework wrapper is identical. The separate v116 5a path tries third-word candidates 1, 2, 3, and the first `ocp` value, but no result establishes one as a valid root slot; it is also gated on `workingProbeIdx`. No saved run output confirms the heuristic stub address or runtime behavior. Thus there is no validated benign notification oracle yet.


`ContentView-v116.swift` remains source-only: its selector `0x04` call has `inputStruct = nil` and a `0xc68` output buffer, but no saved run log confirms the result. The earlier zeroed-buffer watchdog report still lacks exact arguments and direction. The v14 run above exercised the separate private-framework `SetSurfaceNotify`/`RemoveSurfaceNotify` harness; it did not test v116's `0x04` call or validate a delivered notification.

`ContentView-v20.swift` also uses `OUT_SIZE = 0xC68` for selector 0's output buffer, but matching size does not prove the two output structures have the same schema.

A static read of the iOS 27.2 `IOSurface` image shows notifier initialization preparing selector `0x11` (address `0x1c284a74c`). This is only a 27.2 reference, not target-build proof for iOS 27.0.1.

References:

- Target thunk and handler: `tools/opencode-temp/iosurface.disasm.txt` (24A446)
- XNU `IOExternalMethodArguments`: https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/iokit/IOKit/IOUserClient.h
- v116 probe source: `tools/opencode-temp/ContentView-v116.swift`
- v20 output buffer: `tools/opencode-temp/ContentView-v20.swift`
- 27.2 shared-cache image: `tools/opencode-temp/f1-iosurface/dsc/IOSurface`
- v115 harness: `tools/opencode-temp/ContentView-v115.swift`
- Existing analysis: `analysis/iosurface-notify-uaf-CVE-2026-112477.md`
- SDK `IOKitLib.h`: iPhoneOS 27.2 SDK, `System/Library/Frameworks/IOKit.framework/Headers/IOKitLib.h`
- Public IOKitUser: https://github.com/apple-oss-distributions/IOKitUser/blob/main/IOKitLib.c
- Public XNU user-client reference: https://github.com/apple-oss-distributions/xnu/blob/main/iokit/Kernel/IOUserClient.cpp

## Sources

[1] https://developer.apple.com/documentation/iokit/iokit_functions — IOKit Functions — Apple Developer Documentation
[2] https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/iokit/IOKit/IOUserClient.h — IOUserClient.h — Apple XNU source
