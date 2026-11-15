#!/bin/bash
set -e
K=$HOME/iosurface-kext
ls -la $K 2>/dev/null || true
echo "=== sha256 ==="
shasum -a 256 $K/com.apple.iokit.IOSurface 2>/dev/null || echo "not copied"
echo "=== file ==="
file $K/com.apple.iokit.IOSurface
echo "=== headers ==="
xcrun llvm-objdump --macho --private-headers $K/com.apple.iokit.IOSurface 2>&1 | head -80
