import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

old = """    func runWebMode() async {
        isRunning = true; status = "Web probe..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        let target = webTarget.isEmpty ? "http://198.51.100.1:8777/brtest" : webTarget
        webProbeURL = target
        emit("loading \\(target) in a WKWebView; the WebKit networking process decodes it")
        try? await Task.sleep(nanoseconds: 15_000_000_000)
        emit("web probe done")
        status = "Complete"; isRunning = false
    }"""

new = """    func runWebMode() async {
        isRunning = true; status = "Web probe..."; log = ""
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
        let target = webTarget.isEmpty ? "http://198.51.100.1:8777/brtest" : webTarget
        webProbeURL = target
        emit("loading \\(target) in a WKWebView; the WebKit networking process decodes it")
        let wv = WKWebView(frame: CGRect(x: 0, y: 0, width: 1, height: 1))
        wv.load(URLRequest(url: URL(string: target) ?? URL(string: "about:blank")!))
        try? await Task.sleep(nanoseconds: 20_000_000_000)
        // The daemon's *decoded* output is what it serves back to us, so the
        // wild copy's bytes (and their offset) are visible in the page.
        let js = "(document.documentElement?document.documentElement.outerHTML:'').slice(0,3000)"
        var body = ""
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            wv.evaluateJavaScript(js) { res, err in
                body = (res as? String) ?? ("err " + (err?.localizedDescription ?? "?"))
                cont.resume()
            }
        }
        emit("page bytes = \\(body.count)")
        let printable = body.filter { $0.isASCII && !$0.isWhitespace }
        emit("page printable[0..240] = \\(String(printable.prefix(240)))")
        let marks = ["AAAA", "ZZZZ", "MARK", "4343", "4141"]
        for m in marks {
            if body.contains(m) { emit("*** MARKER \\(m) PRESENT in the served body ***") }
        }
        emit("web probe done")
        status = "Complete"; isRunning = false
    }"""

assert old in t
t = t.replace(old, new)
p.write_text(t)
print("patched: --web reads the served (decoded) body back out of the page")
