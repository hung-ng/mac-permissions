"""Small client for session services. The helper owns execution and consent evidence."""
import json
import http.client
import os
import pathlib
import stat
import urllib.error
import urllib.parse
import urllib.request


class APIError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class Unavailable(APIError):
    pass


def credential(path):
    fd = os.open(os.path.expanduser(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise APIError("Credential must be a regular file owned by you, mode 0600")
        value = os.read(fd, 256).decode().strip()
        if len(value) != 64 or any(c not in "0123456789abcdefABCDEF" for c in value):
            raise APIError("Invalid credential")
        return value
    finally:
        os.close(fd)


class Client:
    def __init__(self, endpoint, token_file):
        parsed = urllib.parse.urlparse(endpoint)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/"):
            raise APIError("Endpoint must be an HTTP or HTTPS origin without credentials")
        if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost"):
            raise APIError("Plain HTTP is limited to loopback. Forward through an authenticated transport or use HTTPS")
        self.endpoint = endpoint.rstrip("/")
        self.token = credential(token_file)
        # No environment proxy can intercept bearer credentials or local helper traffic.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, path, body=None):
        if not path.startswith("/v1/"):
            raise APIError("Only version 1 API paths are supported")
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(self.endpoint + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            try:
                message = json.load(error).get("error", str(error))
            except (ValueError, OSError):
                message = str(error)
            raise APIError(message, error.code) from error
        except urllib.error.URLError as error:
            raise Unavailable(str(error.reason)) from error
        except (OSError, http.client.HTTPException) as error:
            raise Unavailable(str(error)) from error

    def submit(self, executable, args, cwd, env, tty=False, **extra):
        return self.call("POST", "/v1/requests", dict(operation="launch", executable=executable,
            args=args, cwd=cwd, env=env, tty=tty, **extra))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise APIError("Helper redirects are refused to protect credentials")


def default_token(role):
    return str(pathlib.Path.home() / "Library/Application Support/MacPermissions" / (role + ".token"))
