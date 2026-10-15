#!/bin/bash
set -euo pipefail

# Run this on the MacBook after transferring the signed app and private profile.
APP=${MAC_PERMISSIONS_APP:-"$PWD/Mac Permissions.app"}
PROFILE=${1:-"$PWD/Mini Connection.macpermissions"}
CONTROLLER="$APP/Contents/MacOS/Controller"

if [[ ! -x "$CONTROLLER" ]]; then
    echo "Controller not found. Set MAC_PERMISSIONS_APP to the unpacked Mac Permissions.app." >&2
    exit 2
fi
if [[ ! -f "$PROFILE" ]]; then
    echo "Private connection profile not found: $PROFILE" >&2
    exit 2
fi

exec "$CONTROLLER" --self-test --profile "$PROFILE"
