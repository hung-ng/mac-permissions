# Session integration API

Use `client/api.py` or HTTP/1.1 JSON requests to the remote helper's loopback endpoint. Bearer tokens contain 256 bits of randomness. The owner token can approve operations; the launcher token can request operations, report errors, and drive sessions. Invalid authentication returns 401. Rejected operations return 409 with an `error` string.

Transport must be authenticated and encrypted between computers. The helper's HTTP listener itself is loopback only. The Python client refuses non-loopback plain HTTP, environment proxies, and redirects, and uses normal HTTPS certificate verification. The helper rejects browser Origin headers and non-loopback Host headers. A remote HTTPS proxy must rewrite Host when connecting to the loopback backend.

## Submit a tool launch

```python
from client.api import Client

client = Client("http://127.0.0.1:43187", "/private/path/launcher.token")
request = client.submit(
    executable="/absolute/path/to/tool",
    args=["argument with spaces", ""],
    cwd="/absolute/workspace",
    env={"PATH": "/usr/bin:/bin"},
    tty=False,
    argv0="tool",
    context={"launcherPID": 1234},
)
```

This calls `POST /v1/requests`. The helper resolves the executable and cwd, hashes the executable, captures signing information, and freezes the normalized specification. The response has an `id`, `fingerprint`, `spec`, and `state`. Arguments are a JSON array, never a shell command string. The supplied environment replaces the child's environment. The CLI sends the session service's full environment.

The owner sees the command, environment, identity, claimed launcher context, and observed launcher ancestry. Future interactive input is part of the approved session's scope. Approving an interpreter also permits that interpreter to execute the supplied code or script. Imported modules, scripts, plugins, and other dependencies are not separately hashed.

`GET /v1/requests` lists requests for the owner. `GET /v1/requests/{id}` returns one request. The owner calls `POST /v1/requests/{id}/approve` with `{"fingerprint":"the displayed fingerprint"}`. Approvals expire after ten minutes, start once, and cannot be replayed for another operation. The helper rechecks the requested executable path and hash immediately before launch. A changed target gets `tool-changed` and needs a fresh submission.

The current release is not designed to defend against a hostile process changing files or reading credentials as the same remote user. Install binaries in an owner-controlled location and approve trusted tools. Different users cannot read the private state and token files under normal Unix permissions.

## Drive a running session

The request ID is also the session ID.

- `POST /v1/requests/{id}/input` accepts `{"data":"base64 bytes","eof":false}`. Frames are at most 64 KiB. Pipe EOF closes stdin. PTY EOF sends EOT.
- `GET /v1/requests/{id}/events?after=0` returns sequenced base64 stdout/stderr chunks and the next cursor. Start at 0 and pass the returned `next` value on the following poll. That acknowledges earlier chunks. There is one output consumer per session.
- `POST /v1/requests/{id}/resize` accepts `{"rows":40,"cols":120}` for a PTY.
- `POST /v1/requests/{id}/cancel` cancels pending requests or sends SIGTERM to the tool's process group, followed by SIGKILL after two seconds if needed.

Completion includes the child's `exitCode`. A signal exit uses 128 plus the signal number. Pipe mode preserves separate streams; PTY mode merges them. The native PTY has a controlling terminal, and the helper records the target's observed ancestry at launch.

The output buffer holds at most 16 MiB of unacknowledged output. Overflow cancels the session and reports incomplete output. The helper retains at most 500 requests until restart. Descendants that deliberately detach from the process group are outside cancellation guarantees. Detaching a process is also outside the tested permission path.

## Report a real permission block

`POST /v1/reports` accepts a positive `pid`, absolute `path`, failing `errno`, and an operation description. The helper records currently observable process ancestry. The controller labels the error as reported and the cause as uncertain. It does not mistake supplied evidence for an independently reproduced TCC failure.

`GET /v1/status` returns helper signing identity, ancestry, app location, and the most recent live permission-operation evidence. There is no boolean that claims universal FDA or App Management access.

## Protected operations and repair

`POST /v1/requests` also accepts these operation specifications:

```json
{"operation":"probe","path":"/Users/owner/Library/Mail"}
```

This performs a read-only open without reading contents. `EPERM` confirms denial but leaves the cause uncertain. `EACCES` directs attention to Unix permissions and ACLs. An absent path is unverified. A successful open proves only that operation in the helper's current context.

`read-fixture` reads at most 256 bytes from an owned `probe.txt` in a `MacPermissionsFixture-` directory. `app-management-fixture` accepts a disposable app created by `scripts/create-fixture.py app` and changes its fixed resource marker from v1 to v2. Both require owner approval. The app update returns actual write evidence while leaving the global grant unverified.

For a blocked protected operation, the owner repairs macOS access on the remote desktop, then calls `POST /v1/requests/{id}/retry` with the original fingerprint. The helper performs the real operation again. Only success changes the result to `succeeded`. `deny` is owner-only and applies to pending or blocked requests.

Requests and sessions live in memory. Credential files survive a restart; approvals do not. `mpctl read-fixture` reconnects and submits the same harmless read for fresh approval. Native commands do not replay after a disconnect. The session service must deliberately relaunch them using its own retry or native session-resume arguments. A helper restart is not a transparent live process migration.

The audit file records request IDs, fingerprints, timestamps, and decisions. It excludes arguments, environment values, input, output, and credentials. The local browser uses a separate session key, same-origin checks, a loopback Host check, and no CORS access. Request text renders with `textContent`.
