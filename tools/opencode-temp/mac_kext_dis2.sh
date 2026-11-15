#!/bin/bash
K=$HOME/iosurface-kext
B=$K/com.apple.iokit.IOSurface
xcrun llvm-objdump -d --no-show-raw-insn "$B" > $K/dis.txt 2>$K/dis.err || true
echo "dis lines=$(wc -l < $K/dis.txt)"
head -3 $K/dis.err
echo "=== page refs to 0xfffffe0007a1a ==="
grep -n "fffffe0007a1a" $K/dis.txt | head -30
echo "=== page refs to 0xfffffe0007a1d ==="
grep -n "fffffe0007a1d" $K/dis.txt | head -40
echo "=== direct refs to 0x7a1db81 / 0x7a1dbcf / 0x7a1dc2b ==="
grep -nE "7a1db81|7a1dbcf|7a1dc2b|7a1a033" $K/dis.txt | head -20
