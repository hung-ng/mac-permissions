import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ControllerBoundary(unittest.TestCase):
    def test_private_browser_session_and_csrf(self):
        with tempfile.TemporaryDirectory() as tmp:
            token=pathlib.Path(tmp)/"owner.token"; token.write_text("a"*64); token.chmod(0o600)
            process=subprocess.Popen([sys.executable,str(ROOT/'client/controller.py'),'--token-file',str(token),'--port','0'],stdout=subprocess.PIPE,text=True)
            try:
                url=process.stdout.readline().strip().split('Controller: ')[1]
                origin,key=url.split('/#')
                page=urllib.request.urlopen(origin+'/').read().decode()
                self.assertNotIn(key,page)
                self.assertNotIn('a'*64,page)
                for headers,code in [({},401),({'Authorization':'Bearer '+key,'Origin':'https://attacker.invalid'},403),({'Authorization':'Bearer '+key,'Host':'attacker.invalid'},403)]:
                    request=urllib.request.Request(origin+'/api/status',headers=headers)
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(request,timeout=5)
                    self.assertEqual(code,error.exception.code)
            finally:
                process.terminate(); process.wait(5); process.stdout.close()


if __name__=='__main__':
    unittest.main(verbosity=2)
