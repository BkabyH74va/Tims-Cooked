#!/bin/bash
cd ~/agx-probe-project
sed -i '' 's/UIApplicationSceneManifest_Generation = NO/UIApplicationSceneManifest_Generation = YES/' AGXProbe.xcodeproj/project.pbxproj
rm -f ~/agx-probe-project/AGXProbe/AppDelegate.swift
echo "Fixed: SwiftUI mode, removed AppDelegate"
