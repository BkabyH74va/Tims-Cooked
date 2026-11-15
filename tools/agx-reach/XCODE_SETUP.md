# AGXProbe — Xcode project setup notes

## Prerequisites
- macOS with Xcode (free Apple ID works — 7-day signing cert)
- Secondary iPhone (iPhone18,1 / V53AP / t8150 / iOS 27.0.1 24A446) on same Wi-Fi as PC
- **Never test on your daily phone**

## Steps

1. Open Xcode → Create New Project → App (SwiftUI)
2. Product Name: `AGXProbe`
3. Replace `ContentView.swift` with `AGXProbe.swift` from this folder
4. Add `IOKit.framework` to the project (Build Phases → Link Binary With Libraries)
5. Add `com.apple.private.iokit-agdg` entitlement if needed (try without first)
6. Sign with your free Apple ID / personal team
7. Connect the secondary iPhone via USB
8. Select the device as run target → Run

## What the probe does

- Looks up `AGXDeviceUserClient` (and fallback channel service names)
- Calls `IOServiceOpen` to get a connect handle
- Iterates `IOConnectCallMethod` selectors 0..15 × index 0..255
- Logs any non-success return codes
- Watch for: app crash, SpringBoard respring, device reboot

## After testing

Pull crash logs from the PC:

```powershell
.\tools\ipsw\ipsw.exe idev crash ls
.\tools\ipsw\ipsw.exe idev crash pull -o analysis\ios\crashes
```

Look in `analysis/ios/crashes/` for `.ips` files mentioning `AGXG18P`, `IOUserClient`, or kernel panic.

## Safety

- Wrong index → wild kernel dereference → kernel panic → reboot
- The bug is an OOB **read** (~2KB past array) + wild pointer dereference
- Not a direct kernel write; low-bandwidth oracle at best
- A crash alone is not a jailbreak
