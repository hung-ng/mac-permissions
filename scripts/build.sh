#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
identity=${SIGNING_IDENTITY:--}
bundle_id=${BUNDLE_ID:-dev.macpermissions.helper}
app="build/Mac Permissions Helper.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" build/module-cache
xcrun clang -mmacosx-version-min=13.0 -O2 -c Sources/Native.c -o build/Native.o
xcrun swiftc -swift-version 5 -target "$(uname -m)-apple-macosx13.0" -module-cache-path build/module-cache -O \
    -import-objc-header Sources/Native.h Sources/Diagnostics.swift Sources/Execution.swift Sources/Core.swift Sources/HTTP.swift Sources/main.swift \
    build/Native.o -o "$app/Contents/MacOS/MacPermissionsHelper"
BUNDLE_ID="$bundle_id" /usr/bin/python3 - <<'PY'
import os,plistlib,pathlib
path=pathlib.Path('build/Mac Permissions Helper.app/Contents/Info.plist')
with path.open('wb') as file:
    plistlib.dump(dict(CFBundleIdentifier=os.environ['BUNDLE_ID'],CFBundleName='Mac Permissions Helper',
        CFBundleDisplayName='Mac Permissions Helper',CFBundleExecutable='MacPermissionsHelper',CFBundlePackageType='APPL',
        CFBundleShortVersionString='0.1.0',CFBundleVersion='1',LSMinimumSystemVersion='13.0',LSUIElement=True,
        NSPrincipalClass='NSApplication'),file)
PY
if [ "$identity" = - ]; then
    codesign --force --sign - --identifier "$bundle_id" "$app"
    echo "Ad-hoc build. Privacy grants may need repair after rebuilds."
else
    codesign --force --sign "$identity" --identifier "$bundle_id" --options runtime --timestamp "$app"
fi
codesign --verify --strict --verbose=2 "$app"
codesign -d -r- "$app" 2> build/signing-requirement.txt
echo "Built $app"
