#!/bin/bash
cd ~/agx-probe-project/SKVLENT-build
sed -i '' 's/IPHONEOS_DEPLOYMENT_TARGET = 17.0;$/&\n                INFOPLIST_FILE = "app\/Sources\/Info.plist";/' SKVLENT.xcodeproj/project.pbxproj
echo "Done"
