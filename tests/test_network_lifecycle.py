import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dual_vpn_router.config import load
from dual_vpn_router.dns import Relay, answer_addresses, forward
from dual_vpn_router.network import Network
from dual_vpn_router.runtime import Daemon, request, stop_orphans

ROOT = Path(__file__).resolve().parents[1]


def dns_answer():
    name = b"\x03erp\x04corp\x07example\0"
    question = b"\x12\x34\x01\x00\x00\x01" + b"\0" * 6 + name + b"\0\x01\0\x01"
    response = question[:2] + b"\x81\x80\0\x01\0\x01\0\0\0\0" + question[12:]
    response += b"\xc0\x0c\0\x01\0\x01\0\0\0\x3c\0\x04" + socket.inet_aton("192.168.99.53")
    return question, response


class Recovery(unittest.TestCase):
    def test_replace_existing_resolver_restores_contents_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            resolver = Path(directory) / "resolver"
            resolver.mkdir()
            path = resolver / "erp.corp.example"
            path.write_text("nameserver 192.168.99.53\nport 5353\n")
            path.chmod(0o640)
            gateway = {"name": "b", "domains": ["erp.corp.example"], "replace_resolvers": True}
            network = Network(directory, os.getuid(), resolver_dir=resolver)
            network.resolvers([gateway], 1053)
            self.assertIn("127.0.0.1", path.read_text())
            restarted = Network(directory, os.getuid(), resolver_dir=resolver)
            restarted.entries = json.loads((Path(directory) / "network.json").read_text())
            self.assertEqual(restarted.cleanup(), [])
            self.assertEqual(path.read_text(), "nameserver 192.168.99.53\nport 5353\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_dns_resource_route_is_owned_by_correct_gateway(self):
        commands = []

        def command(args, check=True):
            commands.append(args)
            return SimpleNamespace(returncode=0, stdout="interface: utun80\n")

        gateways = load(ROOT / "examples/config.json")["gateways"]
        with tempfile.TemporaryDirectory() as directory:
            network = Network(directory, os.getuid(), command)
            network.dns_routes("b", "utun80", ["192.168.99.53"], gateways)
            network.dns_routes("b", "utun80", ["192.168.99.53"], gateways)
            self.assertEqual(len(network.entries), 1)
            self.assertEqual(network.entries[0]["prefix"], "192.168.99.53/32")
            with self.assertRaisesRegex(RuntimeError, "ownership"):
                network.dns_routes("a", "utun81", ["192.168.20.10"], gateways)
            network.cleanup("a")
            self.assertEqual(len(network.entries), 1)
            network.cleanup("b")
            self.assertFalse(network.entries)

    def test_dns_compressed_a_record_and_truncation(self):
        _, answer = dns_answer()
        self.assertEqual(answer_addresses(answer), ["192.168.99.53"])
        with self.assertRaises(ValueError):
            answer_addresses(answer[:-1])

    def test_reconnect_restores_dns_derived_routes(self):
        gateway = load(ROOT / "examples/config.json")["gateways"][1]
        gateways = [gateway]
        commands = []

        def command(args, check=True):
            commands.append(args)
            return SimpleNamespace(returncode=0, stdout="interface: utun80\n")

        with tempfile.TemporaryDirectory() as directory:
            network = Network(directory, os.getuid(), command)
            network.dns_routes("b", "utun80", ["192.168.99.53"], gateways)
            network.cleanup("b", routes_only=True)
            network.connect(
                gateway,
                {
                    "TUNDEV": "utun81",
                    "INTERNAL_IP4_ADDRESS": "172.16.0.3",
                    "INTERNAL_IP4_DNS": "192.168.1.53",
                },
            )
            host = [entry for entry in network.entries if entry.get("prefix") == "192.168.99.53/32"]
            self.assertEqual(len(host), 1)
            self.assertEqual(host[0]["interface"], "utun81")

    def test_stale_pid_reuse_is_not_signalled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "processes.json"
            path.write_text(json.dumps([{"pid": 1234, "signature": "old process"}]))
            with (
                patch(
                    "dual_vpn_router.runtime.process_signature", return_value="different process"
                ),
                patch("os.killpg") as kill,
            ):
                stop_orphans(directory)
            kill.assert_not_called()


@unittest.skipUnless(sys.platform == "darwin", "macOS hook integration")
class BackgroundIntegration(unittest.TestCase):
    def test_auth_cookie_hook_dns_routes_and_clean_shutdown(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            fake = directory / "openconnect"
            fake.write_text(
                "#!"
                + sys.executable
                + "\n"
                + """import os,subprocess,sys,time
assert sys.stdin.readline().strip() == "synthetic-cookie"
script = next(arg.split("=",1)[1] for arg in sys.argv if arg.startswith("--script="))
env = dict(os.environ, reason="connect", TUNDEV="utun80", INTERNAL_IP4_ADDRESS="172.16.0.2", INTERNAL_IP4_DNS="192.168.1.53")
assert subprocess.run(script, shell=True, env=env).returncode == 0
while True: time.sleep(1)
"""
            )
            fake.chmod(0o700)
            daemon = Daemon.__new__(Daemon)
            daemon.config = load(ROOT / "examples/config.json")
            daemon.config["gateways"] = [daemon.config["gateways"][1]]
            daemon.uid = os.getuid()
            daemon.directory = directory
            daemon.socket_path = directory / "control.sock"
            daemon.server = socket.socket(socket.AF_UNIX)
            daemon.server.bind(str(daemon.socket_path))
            daemon.server.listen()
            daemon.executable = str(ROOT / "dual_vpn_router/runner.py")
            daemon.binary = str(fake)
            daemon.sessions = {
                "b": {
                    "COOKIE": "synthetic-cookie",
                    "FINGERPRINT": "sha256:" + "a" * 64,
                    "CONNECT_URL": "https://vpn-b.example.invalid:4443",
                }
            }
            daemon.previous_services, daemon.replaced_services = [], []
            daemon.children, daemon.retry = {}, {}
            daemon.states = {"b": {"state": "starting"}}
            daemon.stop, daemon.started = False, time.time()
            daemon.network_lock = threading.RLock()
            commands = []

            def command(args, check=True):
                commands.append(args)
                return SimpleNamespace(returncode=0, stdout="interface: utun80\n")

            daemon.network = Network(directory, daemon.uid, command, directory / "resolver")
            question, answer = dns_answer()
            daemon.relay = Relay(
                daemon.config["gateways"],
                lambda name: dict(daemon.states[name]),
                upstream=lambda *a, **kw: answer,
                on_response=daemon.dns_response,
            )
            daemon.lock = (directory / "lock").open("a")
            outcomes = []
            with patch("signal.signal"):
                thread = threading.Thread(target=lambda: outcomes.append(daemon.run()), daemon=True)
                thread.start()
                try:
                    deadline = time.monotonic() + 8
                    while (
                        time.monotonic() < deadline and daemon.states["b"]["state"] != "connected"
                    ):
                        time.sleep(0.05)
                    self.assertEqual(daemon.states["b"]["state"], "connected")
                    response = forward(
                        question, "127.0.0.1", "", port=daemon.relay.port, bind=False
                    )
                    self.assertEqual(answer_addresses(response), ["192.168.99.53"])
                    self.assertTrue(
                        any("192.168.99.53" in cmd and "add" in cmd for cmd in commands)
                    )
                    request(daemon.socket_path, {"op": "down"})
                    thread.join(timeout=12)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(outcomes, [0])
                    self.assertFalse(daemon.network.entries)
                    self.assertFalse((directory / "resolver/erp.corp.example").exists())
                    self.assertFalse(daemon.socket_path.exists())
                    persisted = "".join(p.read_text() for p in directory.glob("*.json"))
                    self.assertNotIn("synthetic-cookie", persisted)
                finally:
                    daemon.stop = True
                    thread.join(timeout=12)
