import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

t = t.replace("import IOSurface\n", "import IOSurface\nimport WebKit\n")

wrapper = '''
// A WKWebView whose only job is to make the *WebKit networking process*
// (a separate system XPC service) fetch a URL for us.  That service decodes
// Content-Encoding: br, so it is a system daemon we can aim the Brotli trigger
// at.  Whether the request really came from WebKit is visible in the
// User-Agent the server logs.
struct WebProbe: UIViewRepresentable {
    let url: String
    func makeUIView(context: Context) -> WKWebView {
        let w = WKWebView(frame: .zero)
        w.load(URLRequest(url: URL(string: url) ?? URL(string: "about:blank")!))
        return w
    }
    func updateUIView(_ uiView: WKWebView, context: Context) {}
}

'''

anchor = "@MainActor\nfinal class ReachViewModel: ObservableObject {"
assert anchor in t
t = t.replace(anchor, wrapper + anchor)

mode = '''
    // ---- stage 1: make the WebKit networking process decode our bytes -------
    func runWebMode() async {
        isRunning = true; status = "Web probe..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        let target = webTarget.isEmpty ? "http://198.51.100.1:8777/brtest" : webTarget
        webProbeURL = target
        emit("loading \\(target) in a WKWebView; the WebKit networking process decodes it")
        try? await Task.sleep(nanoseconds: 15_000_000_000)
        emit("web probe done")
        status = "Complete"; isRunning = false
    }
'''

old = "    // ---- the Metal half -----------------------------------------------------"
assert old in t
t = t.replace(old, mode + "\n" + old)

old2 = """    private var didAutoRun = false"""
new2 = """    private var didAutoRun = false
    @Published var webProbeURL: String = ""
    @Published var webTarget: String = \"\""""
assert old2 in t
t = t.replace(old2, new2)

old3 = """        if args.contains("--probe") { await runProbeMode(); return }"""
new3 = """        if args.contains("--probe") { await runProbeMode(); return }
        if args.contains("--web") { await runWebMode(); return }"""
assert old3 in t
t = t.replace(old3, new3)

old4 = """            Text("Status: \\(vm.status)").font(.caption2).foregroundColor(.secondary)"""
new4 = """            if !vm.webProbeURL.isEmpty {
                WebProbe(url: vm.webProbeURL).frame(height: 2)
            }
            Text("Status: \\(vm.status)").font(.caption2).foregroundColor(.secondary)"""
assert old4 in t
t = t.replace(old4, new4)

p.write_text(t)
print("patched: --web mode with WKWebView")
