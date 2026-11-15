#!/bin/bash
for f in "$@"; do
  echo "=== $f ==="
  xcrun swiftc -parse "/tmp/$f.swift" 2>&1 | head -12
done
