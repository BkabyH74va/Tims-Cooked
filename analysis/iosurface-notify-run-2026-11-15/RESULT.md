# IOSurface notify probe v14 — bounded device run

Date: 2026-11-15. Raw logs and hashes are in `evidence/`; do not publish raw logs.

## Method

Ran the Mac build-host `IOSurfaceNotifyProbe.c` v14 logic on the two connected iPhones. To invoke the existing UI-only probe without tapping, built an isolated copy of the project with a temporary `--notifyrace` launch-argument dispatch. At build/run time, the C source was unchanged (SHA-256 `52a31e10a6880f57d04fb8ca0ac8947e2a5890c67995cd004a2ad235c3ea02e0`). After the run, only C comments/log wording were corrected to distinguish surface release from closing the bound user-client; executable probe logic was not changed. The temporary Swift dispatch only called `run_iosurface_notify_probe()` and logged start/completion. App data containers were backed up before reinstalling the instrumented build.

The C harness ran its full fixed sequence: stable set/remove controls; 400 release/recreate iterations with concurrent set/remove threads; then phase A registration and surface release, 48-surface spray, and phase B reused-ID set/remove/set. This was the named v14 `IOSurfaceNotifyProbe.c` run, but it did not actually close the notifier's `IOSurfaceRootUserClient` connection.

## Results

| Device | OS build | Launch | Run | Crash reports |
|---|---|---:|---|---|
| iPhone 13 Pro | iOS 27.0, 24A5390f | 0 | Completed; no panic | 407 before / 407 after; identical filename sets |
| iPhone 17 Pro | iOS 27.0.1, 24A446 | 0 | Completed; no panic | 528 before / 528 after; identical filename sets |

On both devices:

- Stable control: `set(type=1, id)` and `remove(id)` returned 0; five sequential pairs also returned 0/0.
- The concurrent phase logged the expected duplicate-registration (`0xe00002c9`) and bad-argument (`0xe00002c2`) returns. These unsynchronized worker results do not prove operation ordering or a race win.
- Phase A registered a surface, released it without removing the notification, then created 48 new surfaces. The first sprayed surface received the same public IOSurface ID as the released surface.
- Phase B against that ID returned `set=0xe00002c9`, `remove=0`, then `set=0`. Thus registration state remained findable across release and immediate public-ID reuse, and explicit removal cleared it.
- The phone stayed connected. No reboot, respring, app-data reset, or data wipe occurred.

## Local evidence

- `evidence/13pro-session.raw.log` — SHA-256 `b5abed28042efc1de3b24facafa7d88e9f8c1b96b9d81c68bd3c8165b73d09ce`
- `evidence/13pro-reach.raw.log` — SHA-256 `d51c0f0c702bdd650dc4b32bdb509aea16c1adf98a72bda9fb0441e255d72fa1`
- `evidence/17pro-session.raw.log` — SHA-256 `c1ef848c178e1372c0e45609dc843474bc66d805697096bb863bf1056aceab01`
- `evidence/17pro-reach.raw.log` — SHA-256 `d51c0f0c702bdd650dc4b32bdb509aea16c1adf98a72bda9fb0441e255d72fa1`

The session logs are retained only in the local research workspace; the public GitHub result will contain this sanitized summary, not raw device logs.

## Interpretation and limits

This is repeatable dynamic evidence on both builds that notification registration state can remain present after surface release and public-ID reuse. It is **not** evidence that the notifier client was destroyed: the v14 C source calls the private framework's set/remove functions and releases IOSurface objects, but contains no `IOServiceClose` of a private `IOSurfaceRootUserClient` connection. The 27.2 reference framework wrapper internally uses a shared connection; target 24A446 wrapper identity is not independently verified. In the target kernel model, request `+0x58` points to the notifier client, not the IOSurface whose ID is the request key. So v14 does not test the candidate client-teardown/UAF sequence.

The run also does **not** establish a dangling kernel pointer, that the notifier-client allocation was freed/reused, a notification delivery, kernel-memory read/write, or reproduction of CVE-2026-112477. The harness did not receive or validate notification IDs/payloads. Its shared `volatile` state is not atomic, and its timing counters cannot establish kernel mutation order. The no-panic completion is not proof that the race was won.

Keep this result scoped to the exact v14 harness and these two OS builds. Do not describe it as UAF or kernel corruption without an independent stale-object/notification oracle.
