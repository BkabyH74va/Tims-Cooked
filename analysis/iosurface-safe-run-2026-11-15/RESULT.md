# Bounded IOSurface control run — 2026-11-15

## Scope

The installed `com.bench27.agxprobe` carrier was launched on both connected test devices from the MacBook with `--iosurfrace`. This is the bounded IOSurface memory-entry/alias control, not the panic-capable selector-0x11 teardown race. No source or signing changes were made for this run.

## Devices

- iPhone 13 Pro — iOS 27.0 / build 24A5390f
- iPhone 17 Pro — iOS 27.0.1 / build 24A446

Both devices were connected before and after the run.

## Observed output

Both devices returned the expected completion marker:

```text
[*] iosurfrace start (entry over a surface; alias dropped before release)
iosurfrace rc=0 recycleCtl=1 markerWrote=1 entryKR=0 alias1=1 baseReused=1 verdict=2
=== iosurfrace done ===
```

The detailed logs showed, on both devices, a surviving memory-entry alias following the newly allocated IOSurface backing storage. The discriminator write through the reclaimed IOSurface was visible through the alias. This remains app-level IOSurface backing-store reuse; it does not establish kernel-object reuse, kernel read/write, or CVE reproduction.

## Safety checks

- Launch exit status: 0 on both devices.
- Pre/post crash-report filename sets: identical on both devices; no new `.ips` report appeared.
- Both devices remained enumerated and connected after the run.
- No reboot, respring, reset, reinstall, or data wipe occurred.

## Deliberately not run

The selector-0x11 teardown race remains blocked. Its current harness lacks a validated live root-slot index and an independent notification ID/payload oracle; running it would make a crash or clean result uninterpretable. The bounded control above verifies only the existing alias path and does not validate the race trigger.
