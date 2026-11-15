#!/bin/sh
cat > /tmp/cond2.swift <<'EOF'
func real() -> Int { return 1 }
#if os(macOS)
print("top-level statement in inactive branch")
#endif
EOF
echo "=== iOS typecheck with statement in inactive #if os(macOS) ==="
xcrun --sdk iphoneos swiftc -typecheck -target arm64-apple-ios15.0 /tmp/cond2.swift 2>&1 | head -10
echo "rc=$?"
