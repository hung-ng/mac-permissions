import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
from api import APIError, Client


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(callback):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        value = callback()
        if value:
            return value
        time.sleep(.03)
    raise AssertionError("Timed out")


@unittest.skipUnless((ROOT / "build/Mac Permissions.app/Contents/MacOS/Controller").exists(), "Build native connection apps first")
class NativeConnection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="mac-permissions-tls-")
        cls.folder = pathlib.Path(cls.temp.name)
        cls.state = cls.folder / "state"
        cls.helper_port, cls.bridge_port = port(), port()
        cls.log = (cls.folder / "process.log").open("wb")
        cls.helper = subprocess.Popen([str(ROOT / "build/Mac Permissions Helper.app/Contents/MacOS/MacPermissionsHelper"),
            "--headless", "--state-dir", str(cls.state), "--port", str(cls.helper_port)], stdout=cls.log, stderr=cls.log)
        wait_for(lambda: (cls.state / "owner.token").exists())
        cls.owner = Client("http://127.0.0.1:" + str(cls.helper_port), str(cls.state / "owner.token"))
        def ready():
            try:
                return cls.owner.call("GET", "/v1/status")
            except APIError:
                return None
        wait_for(ready)
        spec = importlib.util.spec_from_file_location("prepare", ROOT / "scripts/prepare-connection.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        cls.config, cls.profile, _ = module.prepare(cls.folder / "connection", cls.state, "127.0.0.1", [], "Test mini", cls.bridge_port, cls.helper_port)
        cls.profile_value = json.loads(cls.profile.read_text())
        value = json.loads(cls.config.read_text()); value["hosts"].append("localhost"); cls.config.write_text(json.dumps(value)); cls.config.chmod(0o600)
        cls.controller = str(ROOT / "build/Mac Permissions.app/Contents/MacOS/Controller")
        cls.bridge_command = [str(ROOT / "build/Mac Permissions Bridge.app/Contents/MacOS/Bridge"), "--headless", "--config", str(cls.config)]
        cls.bridge = subprocess.Popen(cls.bridge_command, stdout=cls.log, stderr=cls.log)
        def listening():
            try:
                with socket.create_connection(("127.0.0.1", cls.bridge_port), timeout=.2):
                    return True
            except OSError:
                return False
        wait_for(listening)

    @classmethod
    def tearDownClass(cls):
        for process in (cls.bridge, cls.helper):
            process.terminate()
            try:
                process.wait(6)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        cls.log.close(); cls.temp.cleanup()

    def changed_profile(self, **changes):
        value = dict(self.profile_value, **changes)
        path = self.folder / (str(time.monotonic_ns()) + ".macpermissions")
        path.write_text(json.dumps(value)); path.chmod(0o600)
        return path

    def check(self, profile=None):
        return subprocess.run([self.controller, "--check", "--profile", str(profile or self.profile)], capture_output=True, text=True, timeout=20)

    def request(self, method, path, body=None, authorization=None, host=None, origin=None):
        data = b"" if body is None else json.dumps(body).encode()
        token = self.profile_value["ownerToken"] if authorization is None else authorization
        headers = [method + " " + path + " HTTP/1.1", "Host: " + (host or "127.0.0.1:" + str(self.bridge_port)),
            "Content-Length: " + str(len(data)), "Content-Type: application/json", "Connection: close"]
        if token:
            headers.append("Authorization: Bearer " + token)
        if origin:
            headers.append("Origin: " + origin)
        # Apple's bundled Python links an older TLS library. Use the system TLS 1.3 client.
        result = subprocess.run(["/usr/bin/openssl","s_client","-connect","127.0.0.1:"+str(self.bridge_port),"-tls1_3", "-quiet",
            "-CAfile",str(self.folder/"connection/server.pem"),"-verify_return_error"],
            input="\r\n".join(headers).encode()+b"\r\n\r\n"+data,capture_output=True,timeout=8)
        self.assertIn(b"HTTP/1.1",result.stdout,result.stderr.decode(errors="replace"))
        head, payload = result.stdout.split(b"\r\n\r\n", 1)
        return int(head.split(b" ")[1]), json.loads(payload)

    def test_01_native_pinned_tls_authenticates_helper(self):
        result = self.check()
        self.assertEqual(0, result.returncode, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value["connected"])
        self.assertEqual(self.profile_value["helperSHA256"], value["helper"]["helper"]["sha256"])

    def test_02_no_auth_wrong_auth_origin_and_host_are_rejected(self):
        for extra, expected in [({"authorization": ""},401), ({"authorization": "0"*64},401),
                ({"origin":"https://attacker.invalid"},403), ({"host":"attacker.invalid:"+str(self.bridge_port)},403)]:
            self.assertEqual(expected, self.request("GET","/v1/status",**extra)[0])

    def test_03_real_request_fingerprint_and_role_are_enforced_over_tls(self):
        status, request = self.request("POST","/v1/requests",dict(operation="probe",path=self.temp.name))
        self.assertEqual(200,status)
        route="/v1/requests/"+request["id"]+"/approve"
        launcher=(self.state/"launcher.token").read_text().strip()
        self.assertEqual(409,self.request("POST",route,dict(fingerprint=request["fingerprint"]),authorization=launcher)[0])
        self.assertEqual(409,self.request("POST",route,dict(fingerprint="wrong"))[0])
        code,result=self.request("POST",route,dict(fingerprint=request["fingerprint"]))
        self.assertEqual(200,code);self.assertEqual("succeeded",result["state"])
        self.assertEqual(0,result["result"]["errno"])

    def test_04_wrong_certificate_is_not_trusted(self):
        spec=importlib.util.spec_from_file_location("prepare",ROOT/"scripts/prepare-connection.py")
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        _config,path,_pin=module.prepare(self.folder/"other-certificate",self.state,"127.0.0.1",[],"Other mini",self.bridge_port,self.helper_port)
        value=json.loads(path.read_text())
        changed=self.changed_profile(certificateDER=value["certificateDER"],certificateSHA256=value["certificateSHA256"])
        result=self.check(changed)
        self.assertNotEqual(0,result.returncode)
        self.assertIn("Connection failed",result.stderr)

    def test_05_wrong_helper_binary_blocks_pairing(self):
        result=self.check(self.changed_profile(helperSHA256="0"*64))
        self.assertNotEqual(0,result.returncode)
        self.assertIn("helper binary changed",result.stderr)

    def test_06_launcher_token_cannot_be_used_as_owner_profile(self):
        result=self.check(self.changed_profile(ownerToken=(self.state/"launcher.token").read_text().strip()))
        self.assertNotEqual(0,result.returncode)
        self.assertIn("Owner view unavailable",result.stderr)

    def test_07_native_ui_handles_profile_before_window_initialization(self):
        image=self.folder/"native-ui.png"
        result=subprocess.run([self.controller,"--smoke","--profile",str(self.profile),"--snapshot",str(image)],capture_output=True,text=True,timeout=15)
        self.assertEqual(0,result.returncode,result.stderr+result.stdout)
        self.assertIn('"connected":"Connected to remote helper"',result.stdout)
        self.assertEqual(b"\x89PNG\r\n\x1a\n",image.read_bytes()[:8])

    def test_08_native_client_checks_certificate_hostname(self):
        result=self.check(self.changed_profile(endpoint="https://localhost:"+str(self.bridge_port)))
        self.assertNotEqual(0,result.returncode)
        self.assertIn("Connection failed",result.stderr)

    def test_09_native_ui_approval_performs_the_real_operation(self):
        request=self.owner.call("POST","/v1/requests",dict(operation="probe",path=self.temp.name))
        result=subprocess.run([self.controller,"--smoke","--profile",str(self.profile),"--approve-test-request",request["id"]],capture_output=True,text=True,timeout=15)
        self.assertEqual(0,result.returncode,result.stderr+result.stdout)
        actual=self.owner.call("GET","/v1/requests/"+request["id"])
        self.assertEqual("succeeded",actual["state"]);self.assertEqual(0,actual["result"]["errno"])

    def test_10_headless_native_approval_performs_the_real_operation(self):
        request=self.owner.call("POST","/v1/requests",dict(operation="probe",path=self.temp.name))
        result=subprocess.run([self.controller,"--profile",str(self.profile),"--approve-test-request",request["id"]],capture_output=True,text=True,timeout=15)
        self.assertEqual(0,result.returncode,result.stderr+result.stdout)
        value=json.loads(result.stdout)
        self.assertEqual("succeeded",value["state"]);self.assertEqual(0,value["result"]["errno"])
        actual=self.owner.call("GET","/v1/requests/"+request["id"])
        self.assertEqual("succeeded",actual["state"]);self.assertEqual(0,actual["result"]["errno"])

    def test_11_transport_does_not_proxy_arbitrary_urls(self):
        for target in ("https://attacker.invalid/", "//attacker.invalid/", "/outside-helper"):
            self.assertEqual(404,self.request("GET",target)[0])

    def test_12_world_readable_profile_is_rejected_by_cli(self):
        path=self.changed_profile();path.chmod(0o644)
        result=self.check(path)
        self.assertNotEqual(0,result.returncode)
        self.assertIn("mode 0600",result.stderr)

    def test_13_bridge_restart_recovers_without_new_trust_or_auto_approval(self):
        request=self.owner.call("POST","/v1/requests",dict(operation="probe",path=self.temp.name))
        type(self).bridge.terminate();type(self).bridge.wait(5)
        result=self.check();self.assertNotEqual(0,result.returncode)
        type(self).bridge=subprocess.Popen(self.bridge_command,stdout=self.log,stderr=self.log)
        def connected():
            result=self.check()
            return result if result.returncode==0 else None
        result=wait_for(connected);self.assertTrue(json.loads(result.stdout)["connected"])
        self.assertEqual("pending",self.owner.call("GET","/v1/requests/"+request["id"])["state"])

    def test_14_helper_restart_reports_unavailable_and_recovers_with_same_profile(self):
        type(self).helper.terminate();type(self).helper.wait(6)
        result=self.check();self.assertNotEqual(0,result.returncode)
        self.assertIn("mini helper is unavailable",result.stderr)
        type(self).helper=subprocess.Popen([str(ROOT/"build/Mac Permissions Helper.app/Contents/MacOS/MacPermissionsHelper"),"--headless", "--state-dir",str(self.state),"--port",str(self.helper_port)],stdout=self.log,stderr=self.log)
        def connected():
            result=self.check()
            return result if result.returncode==0 else None
        result=wait_for(connected)
        self.assertEqual(0,json.loads(result.stdout)["requestCount"])
