#!/bin/sh
SDK=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk
H=$SDK/usr/include/compression.h
echo "header: $H"
grep -n "COMPRESSION_" "$H" | grep -i -E "algorithm|brotli|0x" | head -40
echo "--- enum block ---"
sed -n '/compression_algorithm/,/} compression_algorithm/p' "$H" | head -60
echo "--- brotli mentions in whole SDK headers ---"
grep -rn "BROTLI\|brotli" "$SDK/usr/include" 2>/dev/null | head -20
echo "--- done ---"
