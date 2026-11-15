# AGXProbe — AppleJPEGDriver JPEG-probe status (2026-11-08, build 24A446 / t8150)

## What was added

`tools/opencode-temp/ReachProbe.swift` was extended (build `24A446` / t8150):

* New button: `Run JPEG probe` (`vm.runJPEGProbe()`).
* `ReachViewModel.runJPEGProbe()`:
  * finds the `AppleJPEGDriver` service via
    `IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("AppleJPEGDriver"), …)`;
  * `IOServiceOpen(s, mach_task_self_, 0, &conn)` per matching service;
  * for selectors `[1, 3]`: builds `IOExternalMethodArguments` (version, selector,
    scalarInputCount=0, structureInputSize=88, structureInput=zeroed 88B buffer,
    structureOutputSize=88, structureOutput=zeroed 88B buffer) plus a single
    `IOExternalMethodDispatch` entry (`jpegEntry`, checkScalarInput=0,
    checkStructureInput=88, checkScalarOutput=0, checkStructureOutput=88) and calls
    `IOConnectMethod(conn, sel, &args, &dispatch, 1, 0)`.
* `autoRunIfRequested()` now honours `--autorun`, `--autorun-jpeg`, and
  (default) runs the JPEG probe.

## Verification

* Swift compile: **BUILD_RC=0** (build11 with `runJPEGProbe`, build12 with
  `--autorun-jpeg` wiring, build13 with default-JPEG wiring).
* Device: install OK, launch OK, log pull OK.
* The `--autorun` launch produced a fresh, complete v8 sweep log
  (`=== AGXProbe v8 — user-client reachability === … services=1483 matched=20
  reported=10`) → the autorun plumbing and log capture work.
* `--autorun-jpeg` / default launches did not produce a new log; the on-device
  `Documents/reach.log` retains the last v8 content.

## Open item

Get a clean `runJPEGProbe` capture (v9 header, then per-selector
`IOConnectMethod … kr=…` lines, then `=== done === jpeg_calls=…`).

## Next step (research)

Drive selector 1 (`startDecoder`) with the 88-byte zeroed structure and capture
the IOReturn / crash behaviour. That is the first controlled codec call.
