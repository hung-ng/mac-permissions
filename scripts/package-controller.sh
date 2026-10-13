#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/releases
codesign --verify --strict 'build/Mac Permissions.app'
ditto -c -k --sequesterRsrc --keepParent 'build/Mac Permissions.app' 'build/releases/Mac-Permissions-MacBook.zip'
/usr/bin/shasum -a 256 'build/releases/Mac-Permissions-MacBook.zip' > build/releases/SHA256SUMS.txt
echo 'Packaged build/releases/Mac-Permissions-MacBook.zip. No connection file or private key is included.'
