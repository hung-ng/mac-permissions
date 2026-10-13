# Mac Permissions

An experimental macOS helper for launching tools with explicit owner approval. The helper checks the executable hash, arguments, working directory, environment, and terminal mode before starting an operation. A local browser controller, native controller, and CLI connect existing session services to the helper.

Approving an operation uses permissions the helper already has. Initial macOS privacy grants still require the owner to use System Settings.

## Requirements

Building requires Xcode Command Line Tools and Python 3.9 or later. The helper and native controller target macOS 13 or later. The TLS bridge requires macOS 15 or later. Native controller builds support Intel and Apple Silicon.

## Build and start the helper

```sh
make build
bash scripts/start.sh --state-dir "$PWD/build/runtime"
bin/mpctl --token-file "$PWD/build/runtime/launcher.token" status
```

Start the app through `scripts/start.sh`, which uses LaunchServices. Launch context affects macOS permission behavior.

For Full Disk Access, open System Settings, then Privacy & Security, then Full Disk Access. Add `build/Mac Permissions Helper.app` and enable access. macOS may stop the app when access changes; restart the same app afterward.

## Open the local controller

```sh
python3 client/controller.py \
  --endpoint http://127.0.0.1:43187 \
  --token-file build/runtime/owner.token --open
```

The helper listens only on loopback. The controller displays pending operations and their exact specifications. Keep `owner.token` private and give the session launcher only `launcher.token`.

## Launch a tool

```sh
bin/mpctl --token-file build/runtime/launcher.token run \
  --cwd /absolute/workspace -- /absolute/path/to/tool argument
```

The CLI waits for approval and passes input and output to the approved tool. Pipe mode preserves separate stdout and stderr. `--tty` creates a controlling terminal with resize and interactive input; output streams merge in terminal mode.

An existing process cannot be moved into the helper. Relaunch it through the helper using the session service's normal retry or resume operation.

## Connect from another Mac

On the Mac hosting the helper:

```sh
make connection-build
python3 scripts/prepare-connection.py --tailscale
bash scripts/start-bridge.sh
bash scripts/package-controller.sh
```

Use a private authenticated network such as Tailscale. The bridge uses TLS 1.3, and the controller pins both the certificate and the expected helper binary.

Transfer the app archive under `build/releases/` and the generated `.macpermissions` profile under `build/private-connection/` through a private channel. The archive contains the controller and a connection-check script. The profile contains the owner credential and must stay private.

Open the controller on the other Mac and choose **Open connection file**. The controller checks the certificate and helper identity before enabling approvals. A changed certificate or helper binary requires reviewing the change and generating a new profile.

For a Python controller on another computer, forward the helper's loopback port through an authenticated encrypted connection and pass the local endpoint and owner token file to `client/controller.py`. Keep the helper's plain HTTP listener off the public network.

## Signing and updates

The default build is ad hoc signed. Rebuilding a binary can require repairing its macOS privacy grant. To use an installed signing identity:

```sh
SIGNING_IDENTITY='Apple Development: Your Name (TEAMID)' make build
```

For distribution, use a Developer ID Application identity and an appropriate notarization process. Keep the bundle ID, signing identity, and installation path consistent across updates. Check effective access after an update.

## Tests

```sh
make test
make connection-build
make connection-test
```

These commands build development apps and run local integration tests. `make test` rebuilds the helper, so run it separately from an installation whose current binary must retain an existing privacy grant.

## Security and scope

The helper assumes trusted tools and processes under the owner's account. Private token files do not isolate credentials from a hostile process running as that same user. Approving an interpreter permits it to execute the supplied code and load its dependencies.

Approvals authorize an exact operation and expire. Replacing the executable or retargeting its symlink requires a fresh approval. Requests and sessions live in memory; approvals do not survive a helper restart. Native commands are not replayed automatically.

Permission checks report actual operation results. A successful operation does not establish universal Full Disk Access or App Management permission.

See [API integration](docs/api.md) for the protocol, role boundaries, output limits, and session behavior.
