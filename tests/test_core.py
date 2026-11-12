import json
import os
import pty
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from dual_vpn_router.auth import parse_auth
from dual_vpn_router.config import save, validate
from dual_vpn_router.dns import Relay, forward, receive_exact
from dual_vpn_router.network import Network
from dual_vpn_router.runtime import Daemon

ROOT = Path(__file__).resolve().parents[1]


def config():
    return json.loads((ROOT / "examples/config.json").read_text())


def query(name="erp.corp.example"):
    encoded = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    return b"\x12\x34\x01\x00\x00\x01" + b"\0" * 6 + encoded + b"\0\x01\0\x01"


class Configuration(unittest.TestCase):
    def test_overlap_and_unowned_domains_rejected(self):
        value = config()
        value["gateways"][1]["routes"] = ["192.168.10.128/25"]
        with self.assertRaisesRegex(ValueError, "Conflicting route"):
            validate(value)
        value = config()
        value["gateways"][1]["domains"] = value["gateways"][0]["domains"]
        with self.assertRaisesRegex(ValueError, "unique"):
            validate(value)

    def test_defaults_not_inferred_and_urls_no_credentials(self):
        for routes in (["0.0.0.0/0"], ["192.168.1.10/24"], ["::/0"]):
            value = config()
            value["gateways"][0]["routes"] = routes
            with self.assertRaises(ValueError):
                validate(value)
        value = config()
        value["gateways"][0]["url"] = "https://user:password@example.invalid"
        with self.assertRaises(ValueError):
            validate(value)

    def test_save_private_and_never_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            save(path, config())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                save(path, config())


class Authentication(unittest.TestCase):
    def auth_text(self):
        return (
            "COOKIE='synthetic-cookie'\nHOST='vpn-b.example.invalid'\nCONNECT_URL='https://vpn-b.example.invalid:4443/group'\nFINGERPRINT='sha256:"
            + "a" * 64
            + "'\nRESOLVE=''"
        )

    def test_output_never_evaluated_and_url_path_preserved(self):
        result = parse_auth(self.auth_text(), config()["gateways"][1])
        self.assertTrue(result["CONNECT_URL"].endswith("/group"))
        with self.assertRaises(ValueError):
            parse_auth(self.auth_text() + "\nEVIL='x'", config()["gateways"][1])
        with self.assertRaises(ValueError):
            parse_auth(
                self.auth_text().replace("vpn-b.example.invalid:4443", "other.invalid:4443"),
                config()["gateways"][1],
            )
        with self.assertRaises(ValueError):
            parse_auth(self.auth_text().replace("a" * 64, "abcd"), config()["gateways"][1])

    def test_keychain_password_then_interactive_otp_no_echo_or_cookie(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "openconnect"
            fake.write_text(
                "#!"
                + sys.executable
                + "\n"
                + """import sys
assert sys.stdin.readline().strip() == "synthetic-password"
print("OTP:", file=sys.stderr, flush=True)
assert sys.stdin.readline().strip() == "654321"
print("COOKIE='synthetic-cookie'")
print("CONNECT_URL='https://vpn-b.example.invalid:4443/group'")
print("FINGERPRINT='sha256:" + "a" * 64 + "'")
"""
            )
            fake.chmod(0o700)
            code = """from dual_vpn_router.auth import authenticate
from dual_vpn_router import keychain
keychain.read = lambda gateway: "synthetic-password"
keychain.write = lambda gateway, password: None
result = authenticate(FAKE, {"name":"b", "url":"https://vpn-b.example.invalid:4443", "username":"synthetic-user", "trust":"system"})
assert result["COOKIE"] == "synthetic-cookie"
print("AUTH_OK", flush=True)
""".replace("FAKE", repr(str(fake)))
            master, slave = pty.openpty()
            process = subprocess.Popen(
                [sys.executable, "-c", code],
                cwd=ROOT,
                stdin=slave,
                stdout=slave,
                stderr=slave,
            )
            os.close(slave)
            output, sent = bytearray(), False
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            part = os.read(master, 4096)
                        except OSError:
                            break
                        if not part:
                            break
                        output.extend(part)
                        if b"OTP:" in output and not sent:
                            os.write(master, b"654321\n")
                            sent = True
                    if process.poll() is not None:
                        break
                self.assertEqual(process.wait(timeout=2), 0, output.decode())
                self.assertIn(b"AUTH_OK", output)
                for secret in (b"synthetic-password", b"synthetic-cookie", b"654321"):
                    self.assertNotIn(secret, output)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(master)


class DNS(unittest.TestCase):
    def test_independent_failure_and_suffix_ownership(self):
        value = config()["gateways"]
        value[0]["domains"] = ["corp.example"]
        states = {
            "a": {
                "state": "connected",
                "interface": "utun80",
                "dns_servers": ["192.168.1.53"],
            },
            "b": {"state": "authentication_required"},
        }
        calls = []

        def upstream(packet, server, interface, **kwargs):
            calls.append((server, interface))
            return packet[:2] + b"\x81\x80" + packet[4:]

        relay = Relay(value, states.__getitem__, upstream)
        try:
            self.assertEqual(relay.answer(query())[3] & 15, 2)
            self.assertFalse(calls)
            self.assertEqual(relay.answer(query("a.corp.example"))[3] & 15, 0)
            self.assertEqual(calls, [("192.168.1.53", "utun80")])
            self.assertEqual(relay.answer(query("public.example"))[3] & 15, 5)
            self.assertEqual(len(calls), 1)
        finally:
            relay.udp.server_close()
            relay.tcp.server_close()

    def test_real_udp_truncation_retries_over_tcp(self):
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
            socket.socket() as tcp,
        ):
            udp.bind(("127.0.0.1", 0))
            port = udp.getsockname()[1]
            tcp.bind(("127.0.0.1", port))
            tcp.listen()
            packet = query()
            expected = packet[:2] + b"\x81\x80" + packet[4:]

            def server():
                part, peer = udp.recvfrom(4096)
                udp.sendto(part[:2] + b"\x83\x80" + part[4:], peer)
                conn, _ = tcp.accept()
                with conn:
                    length = struct.unpack("!H", receive_exact(conn, 2))[0]
                    self.assertEqual(receive_exact(conn, length), packet)
                    conn.sendall(struct.pack("!H", len(expected)) + expected)

            thread = threading.Thread(target=server, daemon=True)
            thread.start()
            self.assertEqual(forward(packet, "127.0.0.1", "", port=port, bind=False), expected)
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())

    def test_real_local_stub_serves_udp_and_tcp_and_fails_closed(self):
        relay = Relay(config()["gateways"], lambda _: {"state": "disconnected"})
        relay.start()
        try:
            for tcp in (False, True):
                response = forward(query(), "127.0.0.1", "", tcp=tcp, port=relay.port, bind=False)
                self.assertEqual(response[3] & 15, 2)
        finally:
            relay.close()


class NetworkOwnership(unittest.TestCase):
    def test_conflict_rolls_back_only_owned_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            installed, calls = set(), []

            def command(args, check=True):
                calls.append(args)
                if args[0].endswith("ifconfig"):
                    return SimpleNamespace(returncode=0, stdout="")
                if args[2] == "add":
                    if "-ifscope" in args:
                        return SimpleNamespace(returncode=1, stdout="")
                    installed.add(args[-3])
                if args[2] == "get":
                    return SimpleNamespace(returncode=0, stdout="interface: utun80\n")
                if args[2] == "delete":
                    installed.discard(args[-3])
                return SimpleNamespace(returncode=0, stdout="")

            network = Network(directory, os.getuid(), command, Path(directory) / "resolver")
            with self.assertRaisesRegex(RuntimeError, "Route conflict"):
                network.connect(
                    config()["gateways"][0],
                    {
                        "TUNDEV": "utun80",
                        "INTERNAL_IP4_ADDRESS": "172.16.0.2",
                        "INTERNAL_IP4_DNS": "192.168.1.53",
                    },
                )
            self.assertFalse(installed)
            self.assertFalse(network.entries)
            deletes = [c for c in calls if len(c) > 2 and c[2] == "delete"]
            self.assertEqual(len(deletes), 1)
            self.assertNotIn("-ifscope", deletes[0])

    def test_existing_resolver_and_user_changes_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            resolver = Path(directory) / "resolver"
            resolver.mkdir()
            network = Network(directory, os.getuid(), resolver_dir=resolver)
            path = resolver / "a.corp.example"
            path.write_text("existing resolver\n")
            with self.assertRaisesRegex(RuntimeError, "preserved"):
                network.resolvers(config()["gateways"], 1053)
            self.assertEqual(path.read_text(), "existing resolver\n")
            path.unlink()
            network.resolvers(config()["gateways"], 1053)
            path.write_text("user changed it\n")
            errors = network.cleanup()
            self.assertTrue(errors)
            self.assertEqual(path.read_text(), "user changed it\n")
            self.assertFalse((resolver / "erp.corp.example").exists())


class Lifecycle(unittest.TestCase):
    def daemon(self):
        daemon = Daemon.__new__(Daemon)
        daemon.network_lock = threading.RLock()
        daemon.config = config()
        daemon.states = {
            "a": {"state": "connected"},
            "b": {"state": "authentication_required"},
        }
        daemon.children, daemon.sessions, daemon.retry = {}, {}, {}
        daemon.network, daemon.start, daemon.status = Mock(), Mock(), Mock()
        daemon.save_processes = Mock()
        return daemon

    def test_resume_only_failed_gateway(self):
        daemon = self.daemon()
        daemon.handle(
            {
                "op": "resume",
                "sessions": {"a": {"COOKIE": "ignored"}, "b": {"COOKIE": "new"}},
            }
        )
        daemon.start.assert_called_once_with("b")
        self.assertNotIn("a", daemon.sessions)
        self.assertEqual(daemon.states["a"]["state"], "connected")

    def test_configuration_failure_preserves_other_gateway(self):
        daemon = self.daemon()
        daemon.network.connect.side_effect = RuntimeError("synthetic conflict")
        daemon.children["b"] = Mock()
        with self.assertRaises(RuntimeError):
            daemon.handle({"op": "hook", "gateway": "b", "env": {"reason": "connect"}})
        self.assertEqual(daemon.states["a"]["state"], "connected")
        self.assertEqual(daemon.states["b"]["state"], "configuration_error")
        daemon.children["b"].terminate.assert_called_once()

    def test_cookie_rejection_requests_interactive_reauth(self):
        daemon = self.daemon()
        daemon.children["b"] = Mock()
        daemon.children["b"].poll.return_value = 2
        daemon.monitor()
        self.assertEqual(daemon.states["b"]["state"], "authentication_required")
        self.assertEqual(daemon.states["a"]["state"], "connected")
        self.assertNotIn("b", daemon.retry)


if __name__ == "__main__":
    unittest.main()
