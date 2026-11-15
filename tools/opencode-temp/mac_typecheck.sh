#!/bin/sh
cd ~/agx-probe-project/AGXProbe || exit 1
echo "=== typecheck as iOS ==="
xcrun --sdk iphoneos swiftc -typecheck -target arm64-apple-ios15.0 brotlirepro.swift 2>&1 | head -20
echo "=== probe condition ==="
cat > /tmp/cond.swift <<'EOF'
#if os(macOS)
let which = "macOS"
#elseif os(iOS)
let which = "iOS"
#else
let which = "other"
#endif
func f() -> String { return which }
EOF
xcrun --sdk iphoneos swiftc -typecheck -target arm64-apple-ios15.0 /tmp/cond.swift 2>&1 | head -5
echo "cond_done"
