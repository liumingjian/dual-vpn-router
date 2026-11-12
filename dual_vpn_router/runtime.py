import fcntl
import json
import os
import select
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from .config import validate
from .dns import Relay
from .network import Network, atomic_json


def runtime_dir(uid):
    return Path(f"/var/run/dual-vpn-router-{uid}")


def request(path, data, timeout=15):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(timeout)
        sock.connect(str(path))
        sock.sendall(json.dumps(data).encode() + b"\n")
        sock.shutdown(socket.SHUT_WR)
        response = bytearray()
        while part := sock.recv(65536):
            response.extend(part)
            if len(response) > 2 * 1024 * 1024:
                raise RuntimeError("Control response too large.")
        result = json.loads(response)
        if not result.get("ok"):
            raise RuntimeError(result.get("error", "Control operation failed."))
        return result


def process_signature(pid):
    result = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "lstart=", "-o", "comm="],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def stop_orphans(directory):
    path = Path(directory) / "processes.json"
    if not path.exists():
        return
    for entry in json.loads(path.read_text()):
        pid = entry["pid"]
        if entry["signature"] and process_signature(pid) == entry["signature"]:
            try:
                os.killpg(pid, signal.SIGTERM)
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline and process_signature(pid) == entry["signature"]:
                    time.sleep(0.1)
                if process_signature(pid) == entry["signature"]:
                    os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    atomic_json(path, [])


def restore_services(directory):
    path = Path(directory) / "original-services.json"
    if not path.exists():
        return []
    errors, pending = [], []
    for service in json.loads(path.read_text()):
        restored = subprocess.run(
            ["/usr/sbin/scutil", "--nc", "start", service], capture_output=True
        )
        deadline = time.monotonic() + 10
        connected = False
        while time.monotonic() < deadline and restored.returncode == 0:
            observed = subprocess.run(
                ["/usr/sbin/scutil", "--nc", "status", service],
                capture_output=True,
                text=True,
            ).stdout
            if observed.startswith("Connected"):
                connected = True
                break
            time.sleep(0.2)
        if not connected:
            pending.append(service)
            errors.append("Original VPN restoration requires user interaction in AnyConnect.")
    atomic_json(path, pending)
    return errors


def flush_dns():
    if os.geteuid() != 0:
        return
    subprocess.run(["/usr/bin/dscacheutil", "-flushcache"], capture_output=True, check=False)
    subprocess.run(["/usr/bin/killall", "-HUP", "mDNSResponder"], capture_output=True, check=False)


def hook(path, gateway):
    allowed = {
        "reason",
        "TUNDEV",
        "INTERNAL_IP4_ADDRESS",
        "INTERNAL_IP4_MTU",
        "INTERNAL_IP4_DNS",
        "CISCO_SPLIT_INC",
    }
    env = {
        k: v
        for k, v in os.environ.items()
        if k in allowed
        or (k.startswith("CISCO_SPLIT_INC_") and (k.endswith("_ADDR") or k.endswith("_MASK")))
    }
    request(path, {"op": "hook", "gateway": gateway, "env": env})


class Daemon:
    def __init__(self, payload, executable):
        if os.geteuid() != 0:
            raise RuntimeError("Network management requires sudo.")
        self.config = validate(payload["config"])
        self.uid = int(payload["uid"])
        if self.uid <= 0 or int(os.environ.get("SUDO_UID", "-1")) != self.uid:
            raise ValueError("A non-root invoking user is required.")
        self.directory = runtime_dir(self.uid)
        self.directory.mkdir(mode=0o711, exist_ok=True)
        if self.directory.is_symlink() or self.directory.stat().st_uid != 0:
            raise RuntimeError("Runtime directory must be owned by root.")
        os.chmod(self.directory, 0o711)
        self.lock = (self.directory / "lock").open("a")
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stop_orphans(self.directory)
        journal = self.directory / "network.json"
        self.network = Network(self.directory, self.uid)
        if journal.exists():
            self.network.entries = json.loads(journal.read_text())
            if self.network.cleanup():
                raise RuntimeError("Stale network state requires recovery with dvr down.")
        self.socket_path = self.directory / "control.sock"
        self.socket_path.unlink(missing_ok=True)
        self.server = socket.socket(socket.AF_UNIX)
        self.server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self.server.listen(16)
        self.executable = executable
        self.binary = payload["binary"]
        self.sessions = payload["sessions"]
        self.previous_services = payload.get("previous_services", [])
        self.replaced_services = []
        self.children, self.retry = {}, {}
        self.states = {g["name"]: {"state": "starting"} for g in self.config["gateways"]}
        self.stop = False
        self.network_lock = threading.RLock()
        self.relay = Relay(
            self.config["gateways"],
            lambda name: dict(self.states[name]),
            on_response=self.dns_response,
        )
        self.started = time.time()

    def status(self, overall="running", error=None):
        data = {
            "state": overall,
            "pid": os.getpid(),
            "started": self.started,
            "gateways": self.states,
            "error": error,
        }
        atomic_json(self.directory / "status.json", data, self.uid)

    def start(self, name):
        session = self.sessions[name]
        script = shlex.join(
            [
                sys.executable,
                self.executable,
                "_hook",
                "--socket",
                str(self.socket_path),
                "--gateway",
                name,
            ]
        )
        args = [
            self.binary,
            "--protocol=anyconnect",
            "--no-proxy",
            "--non-inter",
            "--cookie-on-stdin",
            "--servercert=" + session["FINGERPRINT"],
            "--reconnect-timeout=300",
            "--script=" + script,
        ]
        if session.get("RESOLVE"):
            args.append("--resolve=" + session["RESOLVE"])
        args.append(session["CONNECT_URL"])
        process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            process.stdin.write(session["COOKIE"].encode() + b"\n")
            process.stdin.close()
        except BrokenPipeError:
            pass
        self.children[name] = process
        self.save_processes()
        self.states[name] = {
            "state": "connecting",
            "attempts": self.states[name].get("attempts", 0) + 1,
        }

    def save_processes(self):
        atomic_json(
            self.directory / "processes.json",
            [
                {"pid": process.pid, "signature": process_signature(process.pid)}
                for process in self.children.values()
                if process.poll() is None
            ],
        )

    def dns_response(self, name, interface, addresses):
        with self.network_lock:
            state = self.states[name]
            if state["state"] != "connected" or state["interface"] != interface:
                raise RuntimeError("Tunnel changed while DNS was resolving.")
            try:
                self.network.dns_routes(name, interface, addresses, self.config["gateways"])
            except RuntimeError as exc:
                state["dns_error"] = str(exc)
                self.status()
                raise

    def handle(self, data):
        with self.network_lock:
            return self._handle(data)

    def _handle(self, data):
        operation = data.get("op")
        if operation == "down":
            self.stop = True
        elif operation == "resume":
            for name, session in data["sessions"].items():
                if name not in self.states or self.states[name]["state"] == "connected":
                    continue
                if name in self.children:
                    raise RuntimeError(
                        "A connection is already recovering. Wait for status to settle."
                    )
                self.sessions[name] = session
                self.retry.pop(name, None)
                self.start(name)
        elif operation == "hook":
            name, env = data["gateway"], data["env"]
            gateway = next(g for g in self.config["gateways"] if g["name"] == name)
            reason = env.get("reason")
            if reason in ("connect", "reconnect"):
                try:
                    details = self.network.connect(gateway, env)
                    self.states[name].update(details, state="connected", error=None)
                    flush_dns()
                except Exception as exc:
                    self.states[name].update(state="configuration_error", error=str(exc))
                    if name in self.children:
                        self.children[name].terminate()
                    raise
            elif reason == "disconnect":
                self.network.cleanup(name, routes_only=True)
                if self.states[name]["state"] not in (
                    "configuration_error",
                    "authentication_required",
                ):
                    self.states[name]["state"] = "disconnected"
            elif reason == "attempt-reconnect":
                self.states[name]["state"] = "reconnecting"
            elif reason != "pre-init":
                raise ValueError("Unsupported network hook event.")
        else:
            raise ValueError("Unknown control operation.")
        self.status()
        return {"ok": True}

    def accept(self):
        conn, _ = self.server.accept()
        with conn:
            conn.settimeout(10)
            try:
                message = bytearray()
                while part := conn.recv(65536):
                    message.extend(part)
                    if len(message) > 2 * 1024 * 1024:
                        raise ValueError("Control message too large.")
                reply = self.handle(json.loads(message))
            except Exception as exc:
                reply = {"ok": False, "error": str(exc)}
            try:
                conn.sendall(json.dumps(reply).encode())
            except OSError:
                pass

    def monitor(self):
        with self.network_lock:
            self._monitor()

    def _monitor(self):
        for name, process in list(self.children.items()):
            code = process.poll()
            if code is None:
                continue
            del self.children[name]
            self.save_processes()
            self.network.cleanup(name, routes_only=True)
            state = self.states[name]
            if state["state"] == "configuration_error":
                continue
            if code == 2:
                state.update(
                    state="authentication_required",
                    exit_code=code,
                    error="Run dvr up in a terminal to authenticate this gateway again.",
                )
            else:
                state.update(state="retry_wait", exit_code=code)
                self.retry[name] = time.monotonic() + min(60, 2 ** min(state.get("attempts", 1), 6))
            self.status()
        for name, deadline in list(self.retry.items()):
            if time.monotonic() >= deadline:
                del self.retry[name]
                self.start(name)
                self.status()

    def run(self):
        def stop(*_):
            self.stop = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        error = None
        self.status("starting")
        try:
            self.relay.start()
            for service in self.previous_services:
                import re

                if not re.fullmatch(r"[A-F0-9-]{36}", service):
                    raise ValueError("Invalid original service identifier.")
                subprocess.run(
                    ["/usr/sbin/scutil", "--nc", "stop", service],
                    check=True,
                    capture_output=True,
                )
                self.replaced_services.append(service)
                atomic_json(self.directory / "original-services.json", self.replaced_services)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    observed = subprocess.run(
                        ["/usr/sbin/scutil", "--nc", "status", service],
                        capture_output=True,
                        text=True,
                    ).stdout
                    if observed.startswith("Disconnected"):
                        break
                    time.sleep(0.2)
                else:
                    raise RuntimeError(
                        "Original VPN did not disconnect; network changes were stopped."
                    )
            self.network.resolvers(self.config["gateways"], self.relay.port)
            for name in self.states:
                self.start(name)
            self.status()
            while not self.stop:
                if select.select([self.server], [], [], 0.5)[0]:
                    self.accept()
                self.monitor()
        except BaseException as exc:
            error = str(exc)
        finally:
            for process in self.children.values():
                if process.poll() is None:
                    process.terminate()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and any(
                p.poll() is None for p in self.children.values()
            ):
                if select.select([self.server], [], [], 0.1)[0]:
                    self.accept()
            for process in self.children.values():
                if process.poll() is None:
                    process.kill()
                process.wait()
            with self.network_lock:
                for state in self.states.values():
                    state["state"] = "stopped"
                errors = self.network.cleanup()
            self.relay.close()
            flush_dns()
            self.server.close()
            self.socket_path.unlink(missing_ok=True)
            self.save_processes()
            errors.extend(restore_services(self.directory))
            self.status(
                "error" if error or errors else "stopped",
                error or ("; ".join(errors) if errors else None),
            )
            fcntl.flock(self.lock, fcntl.LOCK_UN)
            self.lock.close()
        return 1 if error or errors else 0


def recover(uid):
    directory = runtime_dir(uid)
    journal = directory / "network.json"
    if not journal.exists():
        return
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stop_orphans(directory)
        network = Network(directory, uid)
        network.entries = json.loads(journal.read_text())
        errors = network.cleanup()
        errors.extend(restore_services(directory))
        if errors:
            raise RuntimeError("; ".join(errors))
        atomic_json(directory / "status.json", {"state": "stopped", "gateways": {}}, uid)
