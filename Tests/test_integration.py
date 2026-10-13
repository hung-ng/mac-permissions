import base64
import concurrent.futures
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
from api import APIError, Client


def eventually(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(.03)
    raise AssertionError("Timed out waiting for expected state")


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="mac-permissions-tests-")
        cls.state = pathlib.Path(cls.temp.name) / "state"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); cls.port = sock.getsockname()[1]
        cls.endpoint = "http://127.0.0.1:" + str(cls.port)
        cls.log = open(pathlib.Path(cls.temp.name) / "helper.log", "wb")
        cls.helper = subprocess.Popen([str(ROOT / "build/Mac Permissions Helper.app/Contents/MacOS/MacPermissionsHelper"),
            "--headless", "--port", str(cls.port), "--state-dir", str(cls.state)], stdout=cls.log, stderr=cls.log)
        eventually(lambda: (cls.state / "owner.token").exists())
        cls.owner = Client(cls.endpoint, str(cls.state / "owner.token"))
        cls.launcher = Client(cls.endpoint, str(cls.state / "launcher.token"))
        def ready():
            try:
                return cls.owner.call("GET", "/v1/status")
            except APIError:
                if cls.helper.poll() is not None:
                    raise AssertionError("Helper exited during startup")
        eventually(ready)

    @classmethod
    def tearDownClass(cls):
        cls.helper.terminate()
        try:
            cls.helper.wait(5)
        except subprocess.TimeoutExpired:
            cls.helper.kill(); cls.helper.wait()
        cls.log.close(); cls.temp.cleanup()

    def submit(self, args, executable="/usr/bin/python3", tty=False, cwd=None, env=None, **extra):
        return self.launcher.submit(executable, args, cwd or self.temp.name, env or {"PATH": "/usr/bin:/bin"}, tty, **extra)

    def approve(self, request):
        return self.owner.call("POST", "/v1/requests/" + request["id"] + "/approve", dict(fingerprint=request["fingerprint"]))

    def output(self, request, timeout=10):
        route = "/v1/requests/" + request["id"]
        stdout, stderr, cursor = bytearray(), bytearray(), 0
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.launcher.call("GET", route + "/events?after=" + str(cursor))
            for event in value["events"]:
                (stderr if event["stream"] == "stderr" else stdout).extend(base64.b64decode(event["data"]))
            cursor = value["next"]
            if value.get("complete"):
                return bytes(stdout), bytes(stderr), value
            time.sleep(.01)
        self.launcher.call("POST", route + "/cancel", {})
        self.fail("Target did not complete")

    def test_01_roles_and_fingerprint(self):
        request = self.submit(["-c", "print('approved')"])
        for action in ("approve", "retry", "deny"):
            with self.assertRaises(APIError):
                self.launcher.call("POST", "/v1/requests/" + request["id"] + "/" + action, dict(fingerprint=request["fingerprint"]))
        with self.assertRaises(APIError):
            self.launcher.call("GET", "/v1/requests")
        with self.assertRaises(APIError):
            self.owner.call("POST", "/v1/requests/" + request["id"] + "/approve", dict(fingerprint="wrong"))
        self.assertEqual("pending", self.launcher.call("GET", "/v1/requests/" + request["id"])["state"])
        self.approve(request)
        with self.assertRaises(APIError):
            self.approve(request)
        out, err, result = self.output(request)
        self.assertEqual((b"approved\n", b"", 0), (out, err, result["exitCode"]))

    def test_02_exact_args_cwd_env_binary_input_and_exit(self):
        script = "import sys,os,json; data=sys.stdin.buffer.read(); print(json.dumps(dict(args=sys.argv[1:],cwd=os.getcwd(),value=os.environ['MP_TEST']))); sys.stdout.flush(); sys.stdout.buffer.write(data); sys.stderr.buffer.write(b'err\\x00\\xff'); sys.exit(7)"
        args = ["a b", "", "'quoted'", "$(do-not-execute)", "café", "line\nbreak"]
        request = self.submit(["-c", script] + args, env={"MP_TEST": "literal\nvalue"})
        self.approve(request)
        data = bytes(range(256)) * 16
        self.launcher.call("POST", "/v1/requests/" + request["id"] + "/input", dict(data=base64.b64encode(data).decode(), eof=True))
        out, err, result = self.output(request)
        line, binary = out.split(b"\n", 1)
        metadata = json.loads(line)
        self.assertEqual(args, metadata["args"])
        self.assertEqual(os.path.realpath(self.temp.name), metadata["cwd"])
        self.assertEqual("literal\nvalue", metadata["value"])
        self.assertEqual(data, binary); self.assertEqual(b"err\x00\xff", err)
        self.assertEqual(7, result["exitCode"])
        self.assertIn("cause-uncertain", result["diagnostic"]["classification"])

    def test_03_pty_controlling_terminal_resize_input(self):
        script = "import os,sys,fcntl,termios,struct,time; print('TTY='+str(os.isatty(0))+',CONTROL='+str(os.tcgetpgrp(0)==os.getpgrp()),flush=True); print(input(),flush=True); time.sleep(.2); print('SIZE='+str(struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,b'\\0'*8))[:2]),flush=True)"
        request = self.submit(["-c", script], tty=True, rows=25, cols=90)
        self.approve(request)
        route = "/v1/requests/" + request["id"]
        self.launcher.call("POST", route + "/resize", dict(rows=40, cols=120))
        self.launcher.call("POST", route + "/input", dict(data=base64.b64encode(b"hello terminal\n").decode(), eof=False))
        out, err, result = self.output(request)
        self.assertIn(b"TTY=True,CONTROL=True", out)
        self.assertIn(b"hello terminal", out)
        self.assertIn(b"SIZE=(40, 120)", out)
        self.assertEqual(b"", err); self.assertEqual(0, result["exitCode"])
        self.assertEqual(result["ancestry"][0]["ppid"], self.helper.pid)

    def test_04_cancel_process_group(self):
        request = self.submit(["-c", "import subprocess,time; subprocess.Popen(['/bin/sleep','60']); time.sleep(60)"])
        self.approve(request)
        time.sleep(.1)
        self.launcher.call("POST", "/v1/requests/" + request["id"] + "/cancel", {})
        _out, _err, result = self.output(request)
        self.assertEqual(143, result["exitCode"])

    def test_05_tool_replaced_after_submission(self):
        target = pathlib.Path(self.temp.name) / "updated-tool"
        source = target.with_suffix(".c")
        source.write_text("int main(void) { return 0; }\n")
        subprocess.run(["xcrun", "clang", str(source), "-o", str(target)],check=True)
        request = self.submit(["before update"], executable=str(target))
        replacement = target.with_suffix(".new")
        source.write_text("int main(void) { return 1; }\n")
        subprocess.run(["xcrun", "clang", str(source), "-o", str(replacement)],check=True); replacement.replace(target)
        with self.assertRaisesRegex(APIError, "changed"):
            self.approve(request)
        self.assertEqual("tool-changed", self.launcher.call("GET", "/v1/requests/" + request["id"])["state"])
        updated = self.submit([], executable=str(target)); self.approve(updated)
        self.assertEqual(1, self.output(updated)[2]["exitCode"])

    def test_06_symlink_retargeted_requires_new_approval(self):
        link = pathlib.Path(self.temp.name) / "tool-link"
        link.symlink_to("/bin/echo")
        request = self.submit(["pinned"], executable=str(link))
        link.unlink(); link.symlink_to("/usr/bin/false")
        with self.assertRaisesRegex(APIError, "changed"):
            self.approve(request)

    def test_07_missing_path_is_not_confirmed_privacy_denial(self):
        request = self.launcher.call("POST", "/v1/requests", dict(operation="probe", path=self.temp.name + "/missing"))
        value = self.approve(request)
        self.assertEqual("unverified", value["result"]["classification"])
        self.assertEqual(2, value["result"]["errno"])
        self.assertEqual("unverified", self.owner.call("GET", "/v1/status")["permissions"]["appManagement"])

    def test_08_cli_streaming(self):
        command = [sys.executable, str(ROOT / "client/mpctl.py"), "--endpoint", self.endpoint, "--token-file", str(self.state / "launcher.token"),
            "run", "--no-tty", "--cwd", self.temp.name, "--", "/usr/bin/python3", "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stderr.write('separate'); sys.exit(9)"]
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def pending():
            values = self.owner.call("GET", "/v1/requests")["requests"]
            return next((r for r in values if r["state"] == "pending" and r["spec"].get("args", [])[-1:] == command[-1:]), None)
        self.approve(eventually(pending))
        data = b"\0literal\xff" * 8192
        out, err = process.communicate(data, timeout=15)
        self.assertEqual(data, out); self.assertIn(b"separate", err); self.assertEqual(9, process.returncode)

    def test_09_loopback_http_auth_and_browser_boundary(self):
        for headers, expected in [({},401), ({"Authorization":"Bearer " + self.owner.token,"Origin":"https://attacker.invalid"},403),
                ({"Authorization":"Bearer " + self.owner.token,"Host":"attacker.invalid"},403)]:
            request = urllib.request.Request(self.endpoint + "/v1/status",headers=headers)
            with self.assertRaises(urllib.error.HTTPError) as failure:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(expected, failure.exception.code)

    def test_10_report_preserves_uncertainty(self):
        result = self.launcher.call("POST", "/v1/reports", dict(pid=os.getpid(), path=self.temp.name, errno=1, operation="read"))
        self.assertEqual("reported", result["state"])
        self.assertEqual("reported-failure-cause-uncertain", result["spec"]["classification"])
        self.assertEqual(os.getpid(), result["spec"]["observedAncestry"][0]["pid"])

    def test_11_live_protected_directory_probe_records_ancestry(self):
        path = str(pathlib.Path.home() / "Library/Mail")
        request = self.launcher.call("POST", "/v1/requests", dict(operation="probe", path=path))
        result = self.approve(request)["result"]
        self.assertEqual(self.helper.pid, result["ancestry"][0]["pid"])
        if result["errno"] in (1,13):
            self.assertEqual("confirmed-denial-cause-uncertain", result["classification"])
        elif result["errno"] == 0:
            self.assertEqual("operation-succeeded", result["classification"])
        else:
            self.assertEqual("unverified", result["classification"])
        evidence = ROOT / "build/evidence/integration-protected-directory.json"
        evidence.parent.mkdir(parents=True,exist_ok=True); evidence.write_text(json.dumps(result,indent=2))

    def test_12_argv0_is_preserved(self):
        target = pathlib.Path(self.temp.name) / "argv0-tool"
        source = target.with_suffix('.c')
        source.write_text('#include <stdio.h>\nint main(int argc, char **argv) { puts(argv[0]); return 0; }\n')
        subprocess.run(['xcrun','clang',str(source),'-o',str(target)],check=True)
        request = self.submit([],executable=str(target),argv0='custom argv zero')
        self.approve(request)
        self.assertEqual(b'custom argv zero\n',self.output(request)[0])

    def test_13_disposable_app_update_is_an_actual_write(self):
        app = pathlib.Path(self.temp.name) / 'MacPermissionsFixture-test.app'
        (app/'Contents/Resources').mkdir(parents=True)
        import plistlib
        with (app/'Contents/Info.plist').open('wb') as file:
            plistlib.dump(dict(CFBundleIdentifier='dev.macpermissions.fixture.test'),file)
        marker=app/'Contents/Resources/mac-permissions-marker'
        marker.write_text('mac-permissions app fixture v1\n')
        request=self.launcher.call('POST','/v1/requests',dict(operation='app-management-fixture',path=str(app)))
        result=self.approve(request)
        self.assertEqual('succeeded',result['state'])
        self.assertEqual('mac-permissions app fixture v2\n',marker.read_text())
        self.assertEqual('operation-succeeded-permission-unverified',result['result']['classification'])
        self.assertEqual('grant-unverified',self.owner.call('GET','/v1/status')['permissions']['appManagement']['status'])

    def test_14_blocked_fixture_read_resumes_after_real_filesystem_repair(self):
        folder=pathlib.Path(self.temp.name)/'MacPermissionsFixture-resume';folder.mkdir()
        marker=folder/'probe.txt';marker.write_bytes(b'mac-permissions disposable fixture\n');marker.chmod(0)
        process=subprocess.Popen([sys.executable,str(ROOT/'client/mpctl.py'),'--endpoint',self.endpoint,'--token-file',str(self.state/'launcher.token'),
            'read-fixture',str(marker)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            def pending():
                return next((r for r in self.owner.call('GET','/v1/requests')['requests'] if r['state']=='pending' and r['spec'].get('path')==str(marker)),None)
            request=eventually(pending);result=self.approve(request)
            self.assertEqual('blocked',result['state']);self.assertEqual(13,result['result']['errno'])
            self.assertIsNone(process.poll())
            marker.chmod(0o600)
            self.owner.call('POST','/v1/requests/'+request['id']+'/retry',dict(fingerprint=request['fingerprint']))
            out,err=process.communicate(timeout=10)
            self.assertEqual(marker.read_bytes(),out);self.assertEqual(0,process.returncode)
        finally:
            if process.poll() is None:process.kill();process.wait()

    def test_15_read_reconnects_after_helper_restart_with_fresh_approval(self):
        folder=pathlib.Path(self.temp.name)/'MacPermissionsFixture-reconnect';folder.mkdir()
        marker=folder/'probe.txt';marker.write_bytes(b'mac-permissions disposable fixture\n');marker.chmod(0)
        process=subprocess.Popen([sys.executable,str(ROOT/'client/mpctl.py'),'--endpoint',self.endpoint,'--token-file',str(self.state/'launcher.token'),
            'read-fixture',str(marker)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            def pending():
                return next((r for r in self.owner.call('GET','/v1/requests')['requests'] if r['state']=='pending' and r['spec'].get('path')==str(marker)),None)
            first=eventually(pending);self.assertEqual('blocked',self.approve(first)['state'])
            self.helper.terminate();self.helper.wait(6);time.sleep(.3)
            self.assertIsNone(process.poll())
            type(self).helper=subprocess.Popen([str(ROOT/'build/Mac Permissions Helper.app/Contents/MacOS/MacPermissionsHelper'),'--headless','--port',str(self.port),'--state-dir',str(self.state)],stdout=self.log,stderr=self.log)
            def restarted():
                try:return self.owner.call('GET','/v1/status')
                except APIError:return None
            eventually(restarted)
            second=eventually(pending);self.assertNotEqual(first['id'],second['id'])
            marker.chmod(0o600);self.approve(second)
            out,err=process.communicate(timeout=10)
            self.assertEqual(marker.read_bytes(),out);self.assertEqual(0,process.returncode)
            self.assertIn(b'fresh owner approval',err)
        finally:
            if process.poll() is None:process.kill();process.wait()


if __name__ == "__main__":
    unittest.main(verbosity=2)
