#!/bin/bash
H=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.2.sdk/System/Library/Frameworks/IOSurface.framework/Headers
echo "=== plane keys ==="
grep -nE 'kIOSurfacePlane' $H/IOSurfaceRef.h
echo "=== comments around plane info ==="
grep -n -B12 'kIOSurfacePlaneInfo' $H/IOSurfaceRef.h | head -60
