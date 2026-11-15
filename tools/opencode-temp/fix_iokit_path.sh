#!/bin/bash
cd ~/agx-probe-project
# Replace $(SDKROOT) with full path in USER_HEADER_SEARCH_PATHS
SDKPATH="/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.2.sdk/System/Library/Frameworks/IOKit.framework/Headers"
sed -i '' "s|\$(SDKROOT)/System/Library/Frameworks/IOKit.framework/Headers|$SDKPATH|g" AGXProbe.xcodeproj/project.pbxproj
echo "Updated IOKit header path to full path"
