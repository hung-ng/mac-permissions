#!/bin/bash
set -euo pipefail

# Run this on the MacBook. It never opens an SSH listener and does not grant
# the mini access to the MacBook. T3 Serve publishes this server over Tailscale.
ROOT=${MAC_PERMISSIONS_ROOT:-$PWD}
T3_BIN=${T3_BIN:-$(command -v t3 || true)}
TAILSCALE_BIN=${TAILSCALE_BIN:-$(command -v tailscale || true)}
T3_PORT=${T3_PORT:-43190}
T3_SERVE_PORT=${T3_SERVE_PORT:-443}

[[ -n "$T3_BIN" && -x "$T3_BIN" ]] || { echo "Install T3 Code or set T3_BIN to its t3 CLI" >&2; exit 2; }
[[ -n "$TAILSCALE_BIN" && -x "$TAILSCALE_BIN" ]] || { echo "Connect Tailscale on the MacBook first" >&2; exit 2; }
[[ -d "$ROOT" ]] || { echo "Project directory not found: $ROOT" >&2; exit 2; }

HOST=$(${TAILSCALE_BIN} ip -4)
[[ "$HOST" =~ ^100\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Could not determine the MacBook Tailscale IPv4 address" >&2; exit 2; }

echo "Starting T3 for $ROOT on $HOST."
echo "The printed T3 Serve URL is the MacBook project entry point."
exec "$T3_BIN" serve "$ROOT" --mode web --host "$HOST" --port "$T3_PORT" \
    --no-browser --auto-bootstrap-project-from-cwd --tailscale-serve --tailscale-serve-port "$T3_SERVE_PORT"
