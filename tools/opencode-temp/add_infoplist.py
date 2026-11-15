import os

pbxproj_path = os.path.expanduser("~/agx-probe-project/SKVLENT-build/SKVLENT.xcodeproj/project.pbxproj")

with open(pbxproj_path, 'r') as f:
    content = f.read()

# Add INFOPLIST_FILE to both build configurations (Debug and Release)
content = content.replace(
    'IPHONEOS_DEPLOYMENT_TARGET = 17.0;\n                LD_RUNPATH_SEARCH_PATHS',
    'IPHONEOS_DEPLOYMENT_TARGET = 17.0;\n                INFOPLIST_FILE = "app/Sources/Info.plist";\n                LD_RUNPATH_SEARCH_PATHS'
)

with open(pbxproj_path, 'w') as f:
    f.write(content)

print("Added INFOPLIST_FILE")
