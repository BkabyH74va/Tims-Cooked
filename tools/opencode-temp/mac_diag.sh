#!/bin/sh
cd /tmp || exit 1
cat > t.swift <<'EOF'
#if os(macOS)
print("os_macos=true")
#else
print("os_macos=false")
#endif
#if canImport(UIKit)
print("canImport_uikit=true")
#else
print("canImport_uikit=false")
#endif
print("done")
EOF
swiftc -O t.swift -o t 2>&1
echo "rc=$?"
./t
echo "---"
./br > /tmp/bro.out 2>&1
echo "br_rc=$?"
wc -c /tmp/bro.out
cat /tmp/bro.out
