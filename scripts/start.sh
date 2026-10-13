#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
open "build/Mac Permissions Helper.app" --args "$@"
