#!/bin/bash
H=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.2.sdk/System/Library/Frameworks/IOSurface.framework/Headers
sed -n '170,320p' $H/IOSurfaceRef.h
