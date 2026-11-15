# AppleAVE2 HEVC VPS reachability — app-supplied parameter sets do not reach the encoder

Date: 2026-11-15
Devices: secondary iPhone14,2 (iOS 27.0, 24A5390f) and primary iPhone18,1
(iOS 27.0.1, 24A446), both driven from the macOS build host over USB.
Carrier mode: `--ave` (`carrier/AGXProbe/ContentView.swift`, `runAVEMode`).
Static companion: `analysis/krw-leads/ave-vps-validation-cluster-2026-11-15.md`.

## Question

The 27.2 fix cluster `AVE_HEVC_CheckVPSExtBounds` plus five callers validates
HEVC VPS layer-set / sub-layer counts. Those counts live in the driver's embedded
VPS descriptor. Does an app-supplied `CMVideoFormatDescription` (VPS/SPS/PPS via
`CMVideoFormatDescriptionCreateFromHEVCParameterSets`) deliver attacker-chosen
values into that descriptor when passed to `VTCompressionSessionCreate`?

## Method

One baseline hardware encode first (to obtain real SPS/PPS), then per vector:

1. splice a crafted Annex-B VPS into the baseline parameter sets;
2. build a format description with `nalUnitHeaderLength = 4`;
3. create a `VTCompressionSession` from that description (64x64, one frame);
4. **positive detector**: search the encoder's own output bitstream for the
   crafted VPS body verbatim. If the driver consumed our parameter set, its
   bytes appear in what it emits.

Vectors: `base`, `vpsid15` (control that must fail if the VPS is honoured),
`sets17c` (layer sets 17; 27.2 caps at 15), `sub7` (max sub layers 7; 27.2 caps
at 6), `lays63`; the extreme `sets64c/255c/1023c` are gated behind `--avetrig`.

## Result (identical on both builds)

```
---- ave base:     format description accepted (#0 t32 25B 40010c01ffff ...)
[*] ave base:      session -> 0   encode rc=0 cb=0 dataLen=2576
                   outFD=[#0 t32 24B 40010c01ffff ...] vpsInOutput=false
---- ave vpsid15:  format description accepted (#0 t32 25B 4001fc01ffff ...)
[*] ave vpsid15:   session -> 0   encode rc=0 cb=0 dataLen=2576
                   outFD=[#0 t32 24B 40010c01ffff ...] vpsInOutput=false
---- ave sets17c:  format description accepted (#0 t32 28B 40010c01ffff ...)
[*] ave sets17c:   session -> 0   encode rc=0 cb=0 dataLen=2576
                   outFD=[#0 t32 24B 40010c01ffff ...] vpsInOutput=false
---- ave sub7:     CoreMedia rejected the parameter sets
---- ave lays63:   format description accepted (#0 t32 33B 40010ff1ffff ...)
[*] ave lays63:    session -> 0   encode rc=0 cb=0 dataLen=2576
                   outFD=[#0 t32 24B 40010c01ffff ...] vpsInOutput=false
```

* Every vector that CoreMedia accepted produced a working encode
  (`rc=0`, callback status 0, ~2.6 kB sample).
* The output format description is the **same** in every case: VPS 24 bytes
  starting `40010c01ffff`, SPS 30 bytes `420101016000`. That is the encoder's own
  VPS, one byte shorter than the supplied one and with `vps_video_parameter_set_id = 0`
  even when we supplied id 15.
* The crafted VPS never appears in the output stream (`vpsInOutput=false`), and
  no observable effect — no rejection, no crash, no panic — tracks any input.
* `sub7` is rejected by CoreMedia itself before VideoToolbox sees it, so that
  vector never reaches the driver at all.

## Verdict

**Bounded negative.** App-supplied HEVC parameter sets do not flow into AppleAVE2
through `VTCompressionSessionCreate`: the compression path ignores the caller's
VPS and emits one it composes itself. The 27.2 VPS bounds checks are therefore
not reachable by crafting parameter sets through the public compression API.

Two consequences worth recording:

1. Any trigger for the missing layer-set/sub-layer checks must come from
   **session configuration**, not from a bitstream — i.e. from the property
   surface (`NumberOfTemporalLayers` and friends), which parallel work already
   measured on this device and found to be denial-of-service only.
2. The `vpsid15` control behaved as expected for an ignored input (the encode
   succeeded regardless), so the negative result is not a broken detector: the
   same code path demonstrably copies SPS/PPS sizes/types into the output FD.

## Device safety

No app crash, no kernel panic, no reboot on either device. Crash-report pull
before and after each run: the secondary gained one OS-generated
`DiagnosticRequest_com.apple.autobugcapture_Performance` entry (bug_type 312,
recurring housekeeping that predates the run), the primary gained nothing.
