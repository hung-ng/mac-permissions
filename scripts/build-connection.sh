#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
identity=${SIGNING_IDENTITY:--}
mkdir -p build/connection-module-cache
for component in Controller Bridge; do
    if [ "$component" = Controller ]; then
        name='Mac Permissions'
        minimum=13.0
        sources=(Connection/Shared.swift Connection/Controller/main.swift)
    else
        name='Mac Permissions Bridge'
        minimum=15.0
        sources=(Connection/Shared.swift Connection/HTTP.swift Connection/Bridge/main.swift)
    fi
    app="build/$name.app"
    mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
    for arch in arm64 x86_64; do
        xcrun swiftc -swift-version 5 -target "$arch-apple-macosx$minimum" -module-cache-path build/connection-module-cache -O \
            "${sources[@]}" -o "build/$component-$arch"
    done
    xcrun lipo -create "build/$component-arm64" "build/$component-x86_64" -output "$app/Contents/MacOS/$component"
    APP_NAME="$name" COMPONENT="$component" MINIMUM="$minimum" /usr/bin/python3 - <<'PY'
import os,pathlib,plistlib
name=os.environ['APP_NAME'];component=os.environ['COMPONENT']
info=dict(CFBundleIdentifier='dev.macpermissions.'+component.lower(),CFBundleName=name,CFBundleDisplayName=name,
    CFBundleExecutable=component,CFBundlePackageType='APPL',CFBundleShortVersionString='0.2.0',CFBundleVersion='2',
    LSMinimumSystemVersion=os.environ['MINIMUM'],NSPrincipalClass='NSApplication',
    NSLocalNetworkUsageDescription='Connect your MacBook to your own Mac mini to review permission problems and approve specific operations.')
if component=='Bridge':info['LSUIElement']=True
else:
    info['CFBundleDocumentTypes']=[dict(CFBundleTypeName='Mac Permissions connection',CFBundleTypeRole='Viewer',LSHandlerRank='Owner',LSItemContentTypes=['dev.macpermissions.connection'])]
    info['UTExportedTypeDeclarations']=[dict(UTTypeIdentifier='dev.macpermissions.connection',UTTypeConformsTo=['public.json'],UTTypeDescription='Private mini connection profile',UTTypeTagSpecification={'public.filename-extension':['macpermissions']})]
with pathlib.Path('build',name+'.app','Contents/Info.plist').open('wb') as file:plistlib.dump(info,file)
PY
    if [ "$component" = Controller ]; then cp client/controller.html "$app/Contents/Resources/controller.html"; fi
    if [ "$identity" = - ]; then codesign --force --sign - "$app"; else codesign --force --sign "$identity" --options runtime --timestamp "$app"; fi
    codesign --verify --strict --verbose=2 "$app"
done
echo 'Built native controller and TLS bridge. The FDA helper was not rebuilt.'
