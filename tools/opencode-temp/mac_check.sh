H=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.2.sdk/System/Library/Frameworks/IOSurface.framework/Headers
echo "=== IOSurfaceTypes.h ==="
cat $H/IOSurfaceTypes.h
echo "=== function decls in IOSurfaceRef.h ==="
grep -nE 'IOSurfaceCreate|IOSurfaceGetBaseAddress|IOSurfaceGetAllocSize|IOSurfaceGetBytesPerRow|IOSurfaceGetHeight|IOSurfaceGetWidth|IOSurfaceCopyValue|IOSurfaceSetValue|IOSurfaceLookup|IOSurfaceGetPixelFormat' $H/IOSurfaceRef.h | head -40