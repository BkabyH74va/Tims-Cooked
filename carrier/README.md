# Tims Cooked — carrier

A SwiftUI app used as an on-device research harness. It runs without entitlements in an
ordinary app sandbox. Reachability is only one part of a security result; it does not establish
memory corruption or exploitability.

`AGXProbe/ContentView.swift` is the main entry point and contains the experimental socket-race
variants. Keep local changes in sync with the reviewed repository copy, and do not commit
signing credentials or device-specific configuration.

## Modes

| Argument | Mode |
|---|---|
| `--sockuaf` | CVE-2026-112514 socket-UAF harness — variants A–E round-robin |
| `--sockprec` | Variant E only: gated one-shot send per sender plus peer-delivery oracle |
| `--sockool` | Variant F: cross-zone reclaim with an out-of-line `mach_msg` spray |
| `--sockxz` | Variant G: free a whole socket page block, then OOL spray |
| `--sockgc` | Variant H: batch-free past the zone's page-return delay, then OOL spray |
| `--web`, `--webscan` | WebKit probing |
| `--probe` | IOSurface probe sweep |
| `--autorun` | Prints a banner only |

## Build and install

From this directory, on macOS with Xcode:

```sh
DEV=<device-udid> ./build_race.sh
xcrun devicectl device install app --device $DEV \
    .build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device process launch --device $DEV --console --terminate-existing \
    <your-bundle-id> --sockprec
```

`build_race.sh` requires `DEV` to name the connected device. It resolves the project directory
relative to the script, so it works from a checkout without a machine-specific path.

The app writes its log into its own container (`Documents/`), and also echoes it to the
console when launched with `--console`. `devicectl device copy from --domain-type
appDataContainer` retrieves the file if needed.

Signing is environment-specific (bundle identifier, team, provisioning profile); those
details are deliberately not documented here. Nothing else in this project depends on them.

## Tests

Everything checkable without touching the screen lives in `carrier/tests/`:

```sh
swiftc -O fixcheck.swift -o /tmp/fixcheck && /tmp/fixcheck
swiftc -O logcheck.swift -o /tmp/logcheck && /tmp/logcheck
```

See `carrier/tests/README.md` for coverage.

## Notes

- `ContentView` and its helpers are deliberately `nonisolated`: the race loop must not run on
  the main actor, or SpringBoard kills the app with a scene-creation watchdog at ~20 seconds.
- The bridging header exposes IOKit C APIs, since iOS ships no Swift module for
  `IOKit.framework`.
- Long-running probes are CPU-intensive. Respect iOS watchdog limits, stop after a crash or
  unexpected reboot, and preserve logs before attempting another run.
