#!/usr/bin/env python3
"""Export a private pinned-TLS connection profile for the owner's MacBook."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
from api import Client, credential


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)


def tailscale_self():
    executable = shutil.which("tailscale") or "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
    result = subprocess.run([executable, "status", "--json"], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError("Tailscale status failed: " + result.stderr[:300])
    value = json.loads(result.stdout)
    if value.get("BackendState") != "Running":
        raise RuntimeError("Connect Tailscale on the mini before exporting a profile")
    own = value.get("Self", {})
    address = next((ip for ip in own.get("TailscaleIPs", []) if ":" not in ip), None)
    if not address:
        raise RuntimeError("The mini has no Tailscale IPv4 address")
    return address, own.get("DNSName", "").rstrip("."), own.get("HostName", "Mac mini")


def prepare(output, state, bind, hosts, name, port, helper_port, helper_sha=None, owner_token=None):
    ipaddress.IPv4Address(bind)
    if not 1024 < port <= 65535 or not 1024 < helper_port <= 65535:
        raise ValueError("Ports must be between 1025 and 65535")
    names = list(dict.fromkeys([bind] + hosts))
    for host in names:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", host):
                raise ValueError("Invalid certificate host")
    output = pathlib.Path(output).absolute()
    output.mkdir(parents=True, mode=0o700)
    info = output.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Output directory must be yours, mode 0700, and not a symlink")
    config_path = output / "bridge.json"
    if config_path.exists():
        raise ValueError("A connection already exists here. Reuse it, or choose a new private output directory to rotate identity.")
    if helper_sha is None:
        client = Client("http://127.0.0.1:" + str(helper_port), str(pathlib.Path(state) / "owner.token"))
        status = client.call("GET", "/v1/status")
        client.call("GET", "/v1/requests")
        helper_sha = status["helper"]["sha256"]
        owner_token = credential(str(pathlib.Path(state) / "owner.token"))
    os.umask(0o077)
    config = output / "certificate.conf"
    san = []
    for host in names:
        try:
            ipaddress.ip_address(host); san.append("IP:" + host)
        except ValueError:
            san.append("DNS:" + host)
    config.write_text("[req]\nprompt=no\ndistinguished_name=subject\nx509_extensions=extensions\n[subject]\nCN=" + bind +
        "\n[extensions]\nsubjectAltName=" + ",".join(san) + "\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n")
    key, certificate, der, identity = [output / name for name in ("server.key", "server.pem", "server.der", "identity.p12")]
    password = secrets.token_hex(24)
    password_file = output / "identity-password.txt"
    private_write(password_file, password.encode())
    try:
        subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "90", "-config", str(config),
            "-keyout", str(key), "-out", str(certificate)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["/usr/bin/openssl", "x509", "-in", str(certificate), "-outform", "DER", "-out", str(der)], check=True)
        subprocess.run(["/usr/bin/openssl", "pkcs12", "-export", "-inkey", str(key), "-in", str(certificate), "-out", str(identity),
            "-passout", "file:" + str(password_file)], check=True)
    finally:
        password_file.unlink(missing_ok=True)
        key.unlink(missing_ok=True)
        config.unlink(missing_ok=True)
    profile_id = str(uuid.uuid4())
    bridge = dict(version=1, bind=bind, hosts=names, port=port, helperPort=helper_port,
        identityPath=str(identity), identityPassword=password, profileID=profile_id)
    private_write(config_path, json.dumps(bridge, indent=2).encode())
    profile = dict(version=1, name=name, profileID=profile_id, endpoint="https://" + bind + ":" + str(port),
        ownerToken=owner_token, certificateDER=base64.b64encode(der.read_bytes()).decode(),
        certificateSHA256=hashlib.sha256(der.read_bytes()).hexdigest(), helperSHA256=helper_sha)
    profile_path = output / "Mini Connection.macpermissions"
    private_write(profile_path, json.dumps(profile, indent=2).encode())
    return config_path, profile_path, profile["certificateSHA256"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tailscale", action="store_true")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--host", action="append", default=[])
    parser.add_argument("--name", default="Mac mini")
    parser.add_argument("--port", type=int, default=43189)
    parser.add_argument("--helper-port", type=int, default=43187)
    parser.add_argument("--state-dir", type=pathlib.Path, default=ROOT / "build/runtime")
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "build/private-connection")
    args = parser.parse_args()
    if args.tailscale:
        args.bind, dns, args.name = tailscale_self()
        if dns:
            args.host.append(dns)
    config, profile, fingerprint = prepare(args.output, args.state_dir, args.bind, args.host, args.name, args.port, args.helper_port)
    print("Bridge configuration: " + str(config))
    print("Private MacBook connection file: " + str(profile))
    print("Certificate SHA-256: " + fingerprint)
    print("Transfer the connection file privately. It contains the owner credential; it is not an app download.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
