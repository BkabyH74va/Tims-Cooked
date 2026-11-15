# Apple Neural Engine user-client reachability (CVE-2026-112696 / CVE-2026-84494)

Date: 2026-11-14
Target: iPhone18,1 / t8150, iOS 27.0.1 (24A446); pre-flight on iPhone14,2, iOS 27.0 (24A5390f)
Advisories (iOS 27.2, **Apple Neural Engine**):

* CVE-2026-112696 — *"An app may be able to cause unexpected system termination or corrupt
  kernel memory. An out-of-bounds write issue was addressed with improved bounds checking."*
* CVE-2026-84494 — *"An app may be able to cause unexpected system termination or write kernel
  memory."*

Both fixed in 27.2, therefore live on 27.0/27.0.1.

Status: **bounded negative for direct user-client access.** The ANE engine service refuses
every open type we tried; only an unrelated load-balancer client opens. No payload was sent.

## 1. Static: the fix sites exist and match the advisories

The `com.apple.driver.AppleH16ANEInterface` kext is the most-changed kext between 24A446
and 24B119 (255 changed functions by mnemonic profile). A scan of strings **added** in
27.2 with code references (`analysis/kernelcache-added-diagnostics-2026-11-14.md`) found a
cluster of new bounds checks whose text is exactly the advisory class:

| added string | ref site in 24B119 |
|---|---|
| `[ERROR] %s: %s: Procedure %u input symbol index %u out of range, totInputBuffers: %u` | `0xfffffe0008ccaecc` |
| `[ERROR] %s: %s: Procedure %u output symbol index %u out of range, totOutputBuffers: %u` | `0xfffffe0008ccb584` |
| `[ERROR] %s: %s: Procedure %u IO counts out of range - numInputs: %u numOutputs: %u max: %u` | `0xfffffe0008d49468` |
| `[ERROR] %s: %s: Number of procedures(%u) in the program exceeds max number(%u) supported` | `0xfffffe0008d4ea68` |
| `%s: %s: mutable kernel procedure_id (%d) out of range, totProcedures: %u` | `0xfffffe0008d37134` |
| `[ERROR] %s: %s: Invalid procedureId: %u. Total procedures for program: %u` | `0xfffffe0008cc5cb8` |

These are absent from 24A446: the 27.0.1 driver does not check them before indexing its
procedure/symbol tables. This matches the existing `carrier/AGXProbe/ANEExploit.c`, which
declares `totInputBuffers = 200` and fills 200 indices "to force the overflow".

## 2. Device measurement — carrier `--ane` (open-only, no payload)

Probe: `carrier/AGXProbe/ANEExploit.c` (`ane_probe()`), launched as `--ane`; enumerates all
services and tries `IOServiceOpen` on every name/class containing "ANE", types 0..12.
The trigger payload is gated behind a separate `--anetrigger` flag and was **not** sent.

```
ane: candidate class=AppleARMIODevice name=ane            all types -> 0xe00002c7
ane: candidate class=AppleARMIODevice name=dart-ane       all types -> 0xe00002c7
ane: candidate class=H1xANELoadBalancer name=ANEDriverRoot
     open(type 1) -> 0x0 (OPEN)
ane: candidate class=ANEClientHints name=ANEClientHints   all types -> 0xe00002c7
ane: candidate class=IODARTMapperNub name=mapper-ane      all types -> 0xe00002c7
ane: candidate class=H11ANEIn name=H11ANE                 all types -> 0xe00002c7
ane: candidates=6 opened=1 triggered=0
```

`0xE00002C7` is `kIOReturnUnsupported`. Note this is **not** `NotPrivileged` (`0xE00002C1`)
or `NotPermitted` (`0xE00002E2`), so the ANE engine service simply does not create a user
client for us at any open type — a hard gate, distinct from the entitlement denials seen on
other services.

## 3. Verdict

* The ANE driver's missing bounds checks are confirmed statically and correspond to two
  advisory CVEs, so the bug class is real on our build.
* Direct exploitation from the app sandbox is blocked at `newUserClient`: `H11ANEIn`
  answers every type with `kIOReturnUnsupported`.
* The one openable client (`H1xANELoadBalancer`, type 1) is a power/load-management nub;
  it is explicitly excluded from triggering by the probe. Do not send the ANE request to it.
* Re-open if a different ANE-adjacent user client appears (enumerate again after any iOS
  build change), or via the CoreML/public path: a crafted model that drives the driver into
  the unchecked path would still be app-carried even though the direct client is closed.
  That is a much larger task (model compiler + format work) and is not started here.

## 4. Probe state

`ane_probe(trigger)` in `carrier/AGXProbe/ANEExploit.c`:
* `trigger == 0`: enumerate + open-only + per-type IOReturn logging (this run).
* `trigger == 1`: additionally submits the malformed request (selectors 2 then 33), but only
  on a service whose class starts with `H` and contains `ANEIn`. Currently unreachable.
