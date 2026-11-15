#!/bin/bash
cd ~/agx-probe-project
# Add IOKit header search path to both build configurations
sed -i '' 's/IPHONEOS_DEPLOYMENT_TARGET = 17.0;/&\n                USER_HEADER_SEARCH_PATHS = ("$(inherited)", "$(SDKROOT)\/System\/Library\/Frameworks\/IOKit.framework\/Headers");/' AGXProbe.xcodeproj/project.pbxproj
echo "Added IOKit header search path"
