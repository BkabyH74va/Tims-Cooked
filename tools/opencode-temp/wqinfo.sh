#!/bin/bash
set -u
echo "##### worse_query entitlements"
cat /tmp/worse_query/worse_query/worse_query.entitlements
echo "##### pbxproj bundle ids"
grep -n "PRODUCT_BUNDLE_IDENTIFIER\|CODE_SIGN_ENTITLEMENTS\|DEVELOPMENT_TEAM\|CODE_SIGN_STYLE" /tmp/worse_query/worse_query.xcodeproj/project.pbxproj | head -20
echo "##### schemes"
ls /tmp/worse_query/worse_query.xcodeproj/xcshareddata/xcschemes/ 2>/dev/null
