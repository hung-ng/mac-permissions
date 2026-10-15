#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
TAILSCALE=${TAILSCALE_BIN:-/usr/local/bin/tailscale}
MACBOOK_HOST=${MACBOOK_HOST:-hung-macbook-pro}
MACBOOK_USER=${MACBOOK_USER:-$(id -un)}
SSH_TARGET="${MACBOOK_USER}@${MACBOOK_HOST}"
MACBOOK_SSH_MODE=${MACBOOK_SSH_MODE:-openssh}
MACBOOK_SSH_KNOWN_HOSTS=${MACBOOK_SSH_KNOWN_HOSTS:-"$HOME/.ssh/known_hosts"}
ARCHIVE=${MACBOOK_ARCHIVE:-"$ROOT/build/releases/Mac-Permissions-MacBook.zip"}
PROFILE=${MACBOOK_PROFILE:-"$ROOT/build/private-connection/Mini Connection.macpermissions"}
STATE=${HELPER_STATE_DIR:-"$ROOT/build/runtime"}
HELPER_PORT=${HELPER_PORT:-43187}
REMOTE_TIMEOUT=${REMOTE_TIMEOUT:-10}

[[ -x "$TAILSCALE" ]] || { echo "Tailscale CLI not found at $TAILSCALE" >&2; exit 2; }
[[ -f "$ARCHIVE" && -f "$PROFILE" ]] || { echo "Build the MacBook package and private profile first" >&2; exit 2; }
[[ -f "$STATE/owner.token" ]] || { echo "Owner token not found at $STATE/owner.token" >&2; exit 2; }

RUN_ID="$(date +%s)-$$"
REMOTE_ROOT="/tmp/mac-permissions-tailscale-test-$RUN_ID"
REMOTE_ARCHIVE="$REMOTE_ROOT/controller.zip"
REMOTE_PROFILE="$REMOTE_ROOT/connection.macpermissions"
REMOTE_APP="$REMOTE_ROOT/MacPermissions.app"
REMOTE_CONTROLLER="$REMOTE_APP/Contents/MacOS/Controller"
REMOTE_READY=0

quote() {
    local value=$1
    value=${value//\'/\'\\\'\'}
    printf "'%s'" "$value"
}

remote() {
    if [[ "$MACBOOK_SSH_MODE" == "tailscale" ]]; then
        /usr/bin/perl -e '$seconds=shift @ARGV; $SIG{ALRM}=sub{exit 124}; alarm $seconds; exec @ARGV' "$REMOTE_TIMEOUT" "$TAILSCALE" ssh "$SSH_TARGET" "$@"
    elif [[ "$MACBOOK_SSH_MODE" == "openssh" ]]; then
        /usr/bin/perl -e '$seconds=shift @ARGV; $SIG{ALRM}=sub{exit 124}; alarm $seconds; exec @ARGV' "$REMOTE_TIMEOUT" /usr/bin/ssh \
            -o ConnectTimeout="$REMOTE_TIMEOUT" -o BatchMode=yes -o StrictHostKeyChecking=yes \
            -o UserKnownHostsFile="$MACBOOK_SSH_KNOWN_HOSTS" "$SSH_TARGET" "$@"
    else
        echo "MACBOOK_SSH_MODE must be openssh or tailscale" >&2
        return 2
    fi
}

remote_sh() {
    remote "$1"
}

cleanup() {
    [[ "$REMOTE_READY" == 1 ]] || return 0
    remote_sh "$(quote /bin/rm) -rf $(quote "$REMOTE_ROOT")" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Checking Tailscale reachability to $MACBOOK_HOST..."
"$TAILSCALE" ping --c 1 --timeout 5s "$MACBOOK_HOST" >/dev/null
if ! remote /usr/bin/true >/dev/null 2>&1; then
    cat >&2 <<EOF
The MacBook is reachable over Tailscale, but its automation channel is not ready.
The default channel is standard macOS Remote Login carried over Tailscale. On the MacBook,
enable System Settings → General → Sharing → Remote Login for $MACBOOK_USER.

Then, once from the mini, accept the MacBook host key and verify key-based access:

    ssh -o StrictHostKeyChecking=accept-new $SSH_TARGET /usr/bin/true

If that first command asks for a password because the mini's public key is not installed,
add ~/.ssh/id_ed25519.pub to the MacBook account's ~/.ssh/authorized_keys, then run it again.
The unattended harness deliberately uses BatchMode and never stores or prompts for a password.

Then run this script again. The native controller's actual application connection remains
TLS 1.3 over Tailscale; SSH is used only to stage and run the disposable MacBook test.
Set MACBOOK_SSH_MODE=tailscale only if the MacBook uses a non-sandboxed Tailscale build
that provides its own SSH server.
EOF
    exit 3
fi
REMOTE_READY=1

remote_sh "$(quote /bin/mkdir) -m 700 -p $(quote "$REMOTE_ROOT")"
echo "Transferring the signed controller and private profile over SSH carried by Tailscale..."
/usr/bin/base64 < "$ARCHIVE" | remote_sh "$(quote /usr/bin/base64) -D -o $(quote "$REMOTE_ARCHIVE")"
/usr/bin/base64 < "$PROFILE" | remote_sh "$(quote /usr/bin/base64) -D -o $(quote "$REMOTE_PROFILE")"
remote_sh "$(quote /bin/chmod) 600 $(quote "$REMOTE_PROFILE")"
remote_sh "$(quote /usr/bin/ditto) -x -k $(quote "$REMOTE_ARCHIVE") $(quote "$REMOTE_ROOT")"
remote_sh "$(quote /bin/mv) $(quote "$REMOTE_ROOT/Mac Permissions.app") $(quote "$REMOTE_APP")"
remote_sh "$(quote /bin/chmod) 700 $(quote "$REMOTE_APP")"

echo "Running the native MacBook client check..."
CHECK_JSON=$(remote_sh "$(quote "$REMOTE_CONTROLLER") --check --profile $(quote "$REMOTE_PROFILE")")

REQUEST_JSON=$(/usr/bin/python3 - "$STATE" "$HELPER_PORT" <<'PY'
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path.cwd() / "client"))
from api import Client
state, port = pathlib.Path(sys.argv[1]), int(sys.argv[2])
owner = Client("http://127.0.0.1:" + str(port), str(state / "owner.token"))
status = owner.call("GET", "/v1/status")
request = owner.call("POST", "/v1/requests", {"operation": "probe", "path": status["suggestedProbePath"]})
print(json.dumps(request, separators=(",", ":")))
PY
)
REQUEST_ID=$(/usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$REQUEST_JSON")

echo "Approving probe $REQUEST_ID through the remote native client..."
APPROVAL_JSON=$(remote_sh "$(quote "$REMOTE_CONTROLLER") --profile $(quote "$REMOTE_PROFILE") --approve-test-request $(quote "$REQUEST_ID")")

FINAL_JSON=$(/usr/bin/python3 - "$STATE" "$HELPER_PORT" "$REQUEST_ID" <<'PY'
import json, pathlib, sys, time
sys.path.insert(0, str(pathlib.Path.cwd() / "client"))
from api import Client
state, port, request_id = pathlib.Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
owner = Client("http://127.0.0.1:" + str(port), str(state / "owner.token"))
deadline = time.monotonic() + 15
while True:
    value = owner.call("GET", "/v1/requests/" + request_id)
    if value.get("state") != "pending":
        if value.get("state") != "succeeded" or value.get("result", {}).get("errno") != 0:
            print(json.dumps(value, separators=(",", ":")))
            raise SystemExit(1)
        print(json.dumps(value, separators=(",", ":")))
        break
    if time.monotonic() > deadline:
        raise SystemExit("Timed out waiting for the remote approval")
    time.sleep(.1)
PY
)

/usr/bin/python3 - "$ROOT" "$MACBOOK_HOST" "$REQUEST_ID" "$CHECK_JSON" "$APPROVAL_JSON" "$FINAL_JSON" <<'PY'
import json, pathlib, sys, time, os
root, host, request_id, check, approval, final = sys.argv[1:]
evidence = {
    "testedAt": time.time(),
    "transport": "OpenSSH carried by Tailscale to native TLS controller",
    "macbook": host,
    "requestID": request_id,
    "check": json.loads(check),
    "remoteApproval": json.loads(approval),
    "miniObservation": json.loads(final),
    "result": "succeeded",
}
path = pathlib.Path(root) / "build/evidence/macbook-tailscale-test.json"
path.write_text(json.dumps(evidence, indent=2) + "\n")
os.chmod(path, 0o600)
print(json.dumps({"result": evidence["result"], "requestID": request_id, "evidence": str(path)}, indent=2))
PY

echo "MacBook-to-mini Tailscale test passed. The remote operation returned errno 0."
