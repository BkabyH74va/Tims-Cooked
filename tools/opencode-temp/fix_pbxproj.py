#!/usr/bin/env python3
import re
import os

pbxproj_path = os.path.expanduser("~/agx-probe-project/SKVLENT-build/SKVLENT.xcodeproj/project.pbxproj")

with open(pbxproj_path, 'r') as f:
    content = f.read()

# Remove GENERATE_INFOPLIST_FILE = YES from both build configurations
content = content.replace('GENERATE_INFOPLIST_FILE = YES;\n', '')

# Remove File System Synchronized Root Group reference from target
content = content.replace('''			fileSystemSynchronizedGroups = (
				A10000000000000000000006 /* Bench27 */,
			);''', '')

# Remove the PBXFileSystemSynchronizedRootGroup section
content = re.sub(r'/\* Begin PBXFileSystemSynchronizedRootGroup section \*/.*?/\* End PBXFileSystemSynchronizedRootGroup section \*/\n', '', content, flags=re.DOTALL)

# Remove the PBXFileReference for the root group  
content = content.replace('''		A10000000000000000000006 /* Bench27 */ = {isa = PBXFileSystemSynchronizedRootGroup;''', '')
content = content.replace('''			isa = PBXFileSystemSynchronizedRootGroup;
			explicitFileTypes = {
			};
			explicitFolders = (
			);
			path = ".";
			sourceTree = "<group>";
		};''', '')

# Remove root group from PBXGroup children
content = content.replace('''				A10000000000000000000006 /* Bench27 */,
''', '')

with open(pbxproj_path, 'w') as f:
    f.write(content)

print("Modified .pbxproj")
