#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/releases
codesign --verify --strict 'build/Mac Permissions.app'
staging=$(mktemp -d "${TMPDIR:-/tmp}/mac-permissions-release.XXXXXX")
trap 'rm -rf "$staging"' EXIT
ditto 'build/Mac Permissions.app' "$staging/Mac Permissions.app"
cp scripts/macbook-self-test.sh "$staging/macbook-self-test.sh"
chmod 755 "$staging/macbook-self-test.sh"
ditto -c -k --sequesterRsrc "$staging" 'build/releases/Mac-Permissions-MacBook.zip'
/usr/bin/shasum -a 256 'build/releases/Mac-Permissions-MacBook.zip' > build/releases/SHA256SUMS.txt
echo 'Packaged build/releases/Mac-Permissions-MacBook.zip. No connection file or private key is included.'
