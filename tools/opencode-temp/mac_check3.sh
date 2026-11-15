#!/bin/bash
H=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.2.sdk/System/Library/Frameworks/IOSurface.framework/Headers
echo "=== release-ish ==="
grep -nE 'Release|Release|Retain|CFRelease' $H/*.h
echo "=== getbaseaddress ==="
grep -nE 'IOSurfaceGetBaseAddress|IOSurfaceGetAllocSize|IOSurfaceGetPixelFormat|IOSurfaceCopyValue|IOSurfaceSetValue' $H/IOSurfaceRef.h
echo "=== includes ==="
head -30 $H/IOSurfaceRef.h
