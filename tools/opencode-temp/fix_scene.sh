#!/bin/bash
cd ~/agx-probe-project
sed -i '' 's/UIApplicationSceneManifest_Generation = YES/UIApplicationSceneManifest_Generation = NO/' AGXProbe.xcodeproj/project.pbxproj
echo "Fixed scene manifest setting"
