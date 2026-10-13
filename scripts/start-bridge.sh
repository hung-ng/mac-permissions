#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
config=${1:-"$PWD/build/private-connection/bridge.json"}
open "build/Mac Permissions Bridge.app" --args --config "$config"
