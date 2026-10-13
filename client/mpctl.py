#!/usr/bin/env python3
import argparse
import base64
import json
import os
import pathlib
import shutil
import signal
import sys
import threading
import time
import termios
import tty

from api import APIError, Unavailable, Client, default_token


def read_fixture(client, path):
    request = None
    last_state = None
    try:
        while True:
            try:
                if request is None:
                    request = client.call("POST", "/v1/requests", dict(operation="read-fixture", path=path))
                    print("Waiting for owner approval of request " + request["id"], file=sys.stderr)
                value = client.call("GET", "/v1/requests/" + request["id"])
                state = value["state"]
                if state == "succeeded":
                    sys.stdout.buffer.write(base64.b64decode(value["result"]["data"])); sys.stdout.buffer.flush()
                    return
                if state not in ("pending", "blocked"):
                    raise APIError("Read did not succeed: " + state)
                if state == "blocked" and last_state != state:
                    print("The real read is blocked. Repair macOS access and retry in the controller.", file=sys.stderr)
                last_state = state
            except Unavailable:
                if last_state != "disconnected":
                    print("Helper disconnected. Waiting for the same read operation to reconnect.", file=sys.stderr)
                last_state = "disconnected"
            except APIError as error:
                if error.status == 409 and str(error) == "Unknown route or request":
                    request = None
                    print("Helper restarted. The same read needs fresh owner approval.", file=sys.stderr)
                else:
                    raise
            time.sleep(.2)
    except BaseException:
        if request:
            try:
                client.call("POST", "/v1/requests/" + request["id"] + "/cancel", {})
            except APIError:
                pass
        raise


def dump(value):
    print(json.dumps(value, indent=2, sort_keys=True))


def wait_request(client, request):
    request_id = request["id"]
    print("Waiting for owner approval of request " + request_id, file=sys.stderr)
    deadline = time.monotonic() + 610
    while True:
        value = client.call("GET", "/v1/requests/" + request_id)
        state = value["state"]
        if state != "pending":
            return value
        if time.monotonic() > deadline:
            client.call("POST", "/v1/requests/" + request_id + "/cancel", {})
            raise APIError("Approval expired")
        time.sleep(.15)


def run(client, options):
    command = options.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise APIError("Supply a command after --")
    executable = shutil.which(command[0]) if not os.path.isabs(command[0]) else command[0]
    if not executable:
        raise APIError("Executable not found")
    terminal = options.tty or (not options.no_tty and sys.stdin.isatty() and sys.stdout.isatty())
    size = shutil.get_terminal_size((80, 24))
    extra = dict(argv0=command[0], rows=size.lines, cols=size.columns, context=dict(launcherPID=os.getpid(), launcherPPID=os.getppid()))
    if options.failure_json:
        extra["failure"] = json.loads(pathlib.Path(options.failure_json).read_text())
    request = client.submit(os.path.abspath(executable), command[1:], os.path.abspath(options.cwd), dict(os.environ), terminal, **extra)
    request_id = request["id"]
    route = "/v1/requests/" + request_id
    interrupted = threading.Event()
    previous = {}

    def cancel(signum, _frame):
        interrupted.set()
        try:
            client.call("POST", route + "/cancel", {})
        except APIError:
            pass

    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[number] = signal.signal(number, cancel)
    saved_terminal = None
    input_stop = threading.Event()
    try:
        value = wait_request(client, request)
        if value["state"] != "running":
            raise APIError("Launch did not start: " + value["state"])
        if terminal and sys.stdin.isatty():
            saved_terminal = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())
        def resize(_signum=None, _frame=None):
            size = shutil.get_terminal_size((80, 24))
            try:
                client.call("POST", route + "/resize", dict(rows=size.lines, cols=size.columns))
            except APIError:
                pass
        if terminal:
            previous[signal.SIGWINCH] = signal.signal(signal.SIGWINCH, resize)
        def feed():
            try:
                while not input_stop.is_set():
                    data = os.read(sys.stdin.fileno(), 32768)
                    client.call("POST", route + "/input", dict(data=base64.b64encode(data).decode(), eof=not data))
                    if not data:
                        break
            except (APIError, OSError):
                pass
        threading.Thread(target=feed, daemon=True).start()
        cursor = 0
        while True:
            result = client.call("GET", route + "/events?after=" + str(cursor))
            for event in result["events"]:
                output = sys.stderr.buffer if event["stream"] == "stderr" else sys.stdout.buffer
                output.write(base64.b64decode(event["data"])); output.flush()
            cursor = result["next"]
            if result.get("complete"):
                if result.get("problem"):
                    print(result["problem"], file=sys.stderr)
                    return 74
                return result["exitCode"]
            time.sleep(.03)
    except BaseException:
        try:
            client.call("POST", route + "/cancel", {})
        except APIError:
            pass
        raise
    finally:
        input_stop.set()
        if saved_terminal:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, saved_terminal)
        for number, handler in previous.items():
            signal.signal(number, handler)


def main():
    parser = argparse.ArgumentParser(description="Integrate a native session launcher with Mac Permissions")
    parser.add_argument("--endpoint", default=os.environ.get("MAC_PERMISSIONS_ENDPOINT", "http://127.0.0.1:43187"))
    parser.add_argument("--token-file", default=os.environ.get("MAC_PERMISSIONS_TOKEN_FILE"))
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("status")
    sub.add_parser("requests")
    launch = sub.add_parser("run")
    launch.add_argument("--cwd", default=os.getcwd())
    launch.add_argument("--tty", action="store_true")
    launch.add_argument("--no-tty", action="store_true")
    launch.add_argument("--failure-json")
    launch.add_argument("command", nargs=argparse.REMAINDER)
    for action in ("approve", "deny", "retry", "cancel", "get"):
        command = sub.add_parser(action)
        command.add_argument("id")
    check = sub.add_parser("probe")
    check.add_argument("path")
    check.add_argument("--fixture-read", action="store_true")
    check.add_argument("--wait", action="store_true")
    read = sub.add_parser("read-fixture")
    read.add_argument("path")
    app_update = sub.add_parser("app-fixture-update")
    app_update.add_argument("path")
    diagnostic = sub.add_parser("diagnose")
    diagnostic.add_argument("path")
    diagnostic.add_argument("--pid", type=int, default=os.getpid())
    report = sub.add_parser("report")
    report.add_argument("--pid", type=int, required=True)
    report.add_argument("--path", required=True)
    report.add_argument("--errno", type=int, required=True)
    report.add_argument("--operation", default="unknown")
    options = parser.parse_args()
    owner = options.action in ("requests", "approve", "deny", "retry")
    client = Client(options.endpoint, options.token_file or default_token("owner" if owner else "launcher"))
    if options.action == "run":
        return run(client, options)
    if options.action == "report":
        dump(client.call("POST", "/v1/reports", dict(pid=options.pid,path=os.path.abspath(options.path),errno=options.errno,operation=options.operation)))
        return 0
    if options.action == "app-fixture-update":
        dump(client.call("POST", "/v1/requests", dict(operation="app-management-fixture",path=os.path.abspath(options.path))))
        return 0
    if options.action == "read-fixture":
        read_fixture(client, os.path.abspath(options.path))
        return 0
    if options.action in ("status", "requests"):
        dump(client.call("GET", "/v1/" + options.action))
    elif options.action in ("probe", "diagnose"):
        if options.action == "diagnose":
            try:
                fd = os.open(options.path, os.O_RDONLY | os.O_NOFOLLOW)
                os.close(fd); error = 0
            except OSError as failure:
                error = failure.errno
            dump(dict(context="CLI process; supplied PID does not change where the probe runs", pid=os.getpid(), reportedPID=options.pid,
                path=options.path, operation="open-readonly-no-content", errno=error, cause="uncertain", helper=client.call("GET", "/v1/status")))
        else:
            operation = "read-fixture" if options.fixture_read else "probe"
            request = client.call("POST", "/v1/requests", dict(operation=operation, path=os.path.abspath(options.path)))
            dump(wait_request(client, request) if options.wait else request)
    elif options.action in ("get", "cancel"):
        dump(client.call("GET" if options.action == "get" else "POST", "/v1/requests/" + options.id + ("/cancel" if options.action == "cancel" else ""), {} if options.action == "cancel" else None))
    else:
        request = client.call("GET", "/v1/requests/" + options.id)
        dump(client.call("POST", "/v1/requests/" + options.id + "/" + options.action, dict(fingerprint=request["fingerprint"])))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (APIError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(69)
