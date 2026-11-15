#!/bin/zsh
cd ~/agx-probe-project/SKVLENT-build
SDK="/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.2.sdk"
MIN=16.0
APP="Bench27.app"
rm -rf "$APP" build
mkdir -p "$APP" build
echo "SDK: $SDK"

for f in app/Sources/ANEExploit.c app/Sources/DecmpfsLeak.c app/Sources/IOSurfaceNotifyProbe.c; do
  /usr/bin/xcrun --sdk iphoneos clang -target "arm64-apple-ios$MIN" -isysroot "$SDK" \
    -O2 -fPIC -c "$f" -o "build/$(basename "$f" .c).o" || echo "FAILED: $f"
done

/usr/bin/xcrun --sdk iphoneos clang -target "arm64-apple-ios$MIN" -isysroot "$SDK" \
  -O2 -fPIC -x objective-c -fobjc-arc -c app/Sources/WQProbe.m -o build/WQProbe.o || echo "FAILED: WQProbe.m"

/usr/bin/xcrun --sdk iphoneos swiftc \
  -parse-as-library -swift-version 5 -O \
  -target "arm64-apple-ios$MIN" -sdk "$SDK" \
  -import-objc-header app/Sources/Bridging-Header.h \
  -framework IOKit -framework Metal -framework VideoToolbox -framework CoreMedia \
  -framework CoreVideo -framework AVFoundation -framework UIKit \
  -framework Foundation \
  -o "$APP/Bench27" \
  build/*.o \
  app/Sources/AppDelegate.swift app/Sources/Theme.swift app/Sources/ViewController.swift app/Sources/Escape.swift \
  app/Sources/GestaltViewController.swift app/Sources/FilesViewController.swift app/Sources/PlacesViewController.swift app/Sources/ReachabilityProbe.swift app/Sources/SearchViewController.swift app/Sources/PlistEditorController.swift \
  app/Sources/HEVCProbe.swift app/Sources/DVPlayback.swift app/Sources/XPCProbe.swift || echo "FAILED: swiftc"

sed -e 's/$(EXECUTABLE_NAME)/Bench27/g' \
    -e 's/$(PRODUCT_BUNDLE_IDENTIFIER)/com.ilyas.aneexploit/g' \
    -e 's/$(PRODUCT_NAME)/Bench27/g' \
    app/Sources/Info.plist > "$APP/Info.plist"
printf 'APPL????' > "$APP/PkgInfo"
chmod 755 "$APP/Bench27"

plutil -lint "$APP/Info.plist"
ls -lh "$APP"
echo "BUILD DONE"
