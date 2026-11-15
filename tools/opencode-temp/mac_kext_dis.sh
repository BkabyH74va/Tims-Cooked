#!/bin/bash
K=$HOME/iosurface-kext
B=$K/com.apple.iokit.IOSurface
echo "=== strings at known offsets ==="
for o in 0x18a3 0x53f1 0x543f 0x549b; do
  off=$((o))
  printf "%s : " "$o"
  dd if=$B bs=1 skip=$off count=64 2>/dev/null | tr -d '\0' | head -c 64
  echo
done
echo "=== disassemble ==="
xcrun llvm-objdump -d --no-show-raw-insn --arch-name=arm64e "$B" > $K/dis.txt 2>$K/dis.err || true
echo "exit=$? lines=$(wc -l < $K/dis.txt)"
head -5 $K/dis.err
echo "=== page refs to 0xfffffe0007a1a (string @0x18a3) ==="
grep -n "fffffe0007a1a" $K/dis.txt | head -20
echo "=== page refs to 0xfffffe0007a1d (strings @0x53f1/0x543f/0x549b) ==="
grep -n "fffffe0007a1d" $K/dis.txt | head -30
