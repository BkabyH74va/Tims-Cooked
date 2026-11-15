#!/bin/sh
SDK=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk
TBD=$SDK/usr/lib/libcompression.tbd
echo "tbd: $TBD"
ls -l "$TBD" 2>&1
echo "--- exported Brotli* in libcompression.tbd ---"
grep -a -o "Brotli[A-Za-z_0-9]*" "$TBD" 2>/dev/null | sort -u
echo "--- exported brotli_* in libcompression.tbd ---"
grep -a -o "brotli_[A-Za-z_0-9]*" "$TBD" 2>/dev/null | sort -u
echo "--- compression_* symbols ---"
grep -a -o "compression_[A-Za-z_0-9]*" "$TBD" 2>/dev/null | sort -u
echo "--- any tbd in usr/lib exporting BrotliDecoderDecompress ---"
grep -rla "BrotliDecoderDecompress" "$SDK/usr/lib" 2>/dev/null
echo "--- done ---"
