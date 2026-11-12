import getpass
import hashlib
import os
import re
import select
import shlex
import socket
import ssl
import subprocess
import sys
import termios
import time
from urllib.parse import urlsplit

from . import keychain

FIELDS = {"COOKIE", "HOST", "CONNECT_URL", "FINGERPRINT", "RESOLVE"}
FINGERPRINT = re.compile(
    r"(?:sha256:[0-9a-fA-F]{64}|sha1:[0-9a-fA-F]{40}|pin-sha256:[A-Za-z0-9+/]{43}=)\Z"
)


def parse_auth(text, gateway):
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in FIELDS or key in result:
            raise ValueError("Unexpected authentication output; secrets were not logged.")
        tokens = shlex.split(value)
        if len(tokens) != 1 or any(c in tokens[0] for c in "\r\n\x00"):
            raise ValueError("Invalid authentication output.")
        result[key] = tokens[0]
    if not result.get("COOKIE") or not FINGERPRINT.fullmatch(result.get("FINGERPRINT", "")):
        raise ValueError("Authentication did not return a cookie and full fingerprint.")
    connect_url = result.get("CONNECT_URL") or result.get("HOST", "")
    if "://" not in connect_url:
        connect_url = "https://" + connect_url
    configured, returned = urlsplit(gateway["url"]), urlsplit(connect_url)
    if (
        returned.scheme != "https"
        or returned.hostname != configured.hostname
        or (returned.port or 443) != (configured.port or 443)
        or returned.username
        or returned.password
    ):
        raise ValueError("Authentication redirected outside the configured gateway.")
    result["CONNECT_URL"] = connect_url
    if result.get("RESOLVE"):
        host, sep, address = result["RESOLVE"].partition(":")
        import ipaddress

        if not sep or host != configured.hostname:
            raise ValueError("Invalid gateway address mapping.")
        ipaddress.IPv4Address(address)
    return result


def presented_key(url):
    parsed = urlsplit(url)
    address = socket.gethostbyname(parsed.hostname)
    with socket.create_connection((address, parsed.port or 443), timeout=10) as sock:
        with ssl._create_unverified_context().wrap_socket(
            sock, server_hostname=parsed.hostname
        ) as tls:
            cert = tls.getpeercert(binary_form=True)
    pub = subprocess.run(
        ["/usr/bin/openssl", "x509", "-inform", "DER", "-pubkey", "-noout"],
        input=cert,
        capture_output=True,
        check=True,
    ).stdout
    der = subprocess.run(
        ["/usr/bin/openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pub,
        capture_output=True,
        check=True,
    ).stdout
    return "sha256:" + hashlib.sha256(der).hexdigest(), f"{parsed.hostname}:{address}"


def authenticate(binary, gateway):
    if not sys.stdin.isatty():
        raise RuntimeError(
            "Authentication requires a local interactive terminal. Run dvr up there."
        )
    gateway = dict(gateway)
    gateway["username"] = gateway.get("username") or input(f"{gateway['name']} username: ").strip()
    password = None
    if gateway.get("keychain", True):
        password = keychain.read(gateway)
        if password is None:
            password = getpass.getpass(
                f"{gateway['name']} password (stored after successful login): "
            )
    command = [
        binary,
        "--protocol=anyconnect",
        "--no-proxy",
        "--authenticate",
        "--user=" + gateway["username"],
        "--external-browser=/usr/bin/open",
    ]
    if gateway.get("trust", "system") == "presented":
        fingerprint, resolve = presented_key(gateway["url"])
        command.extend(["--servercert=" + fingerprint, "--resolve=" + resolve])
    if password is not None:
        command.append("--passwd-on-stdin")
    command.append(gateway["url"])
    print(f"Authenticating {gateway['name']}...", file=sys.stderr)
    # Captured stdout contains cookies. Relay only terminal input; never echo auth output.
    original = termios.tcgetattr(sys.stdin.fileno())
    hidden = list(original)
    hidden[3] &= ~termios.ECHO
    process = None
    output = bytearray()
    try:
        if password is None:
            process = subprocess.Popen(command, stdout=subprocess.PIPE)
        else:
            termios.tcsetattr(sys.stdin, termios.TCSANOW, hidden)
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            process.stdin.write(password.encode() + b"\n")
            process.stdin.flush()
        deadline = time.monotonic() + 600
        while True:
            if time.monotonic() > deadline:
                raise RuntimeError("Authentication timed out.")
            readers = [process.stdout]
            if password is not None:
                readers.append(sys.stdin)
            ready, _, _ = select.select(readers, [], [], 0.2)
            if process.stdout in ready:
                part = os.read(process.stdout.fileno(), 4096)
                if not part:
                    break
                output.extend(part)
                if len(output) > 1024 * 1024:
                    raise RuntimeError("Unexpectedly large authentication output.")
            if password is not None and sys.stdin in ready:
                part = os.read(sys.stdin.fileno(), 4096)
                if not part:
                    raise RuntimeError("Authentication terminal closed.")
                process.stdin.write(part)
                process.stdin.flush()
                print(file=sys.stderr)
        if process.wait(timeout=10):
            raise RuntimeError("Authentication failed. No cookie was saved.")
        result = parse_auth(output.decode(), gateway)
        if password is not None:
            keychain.write(gateway, password)
        return result
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSANOW, original)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
