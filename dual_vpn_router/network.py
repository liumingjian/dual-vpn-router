import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

INTERFACE = re.compile(r"utun[0-9]+\Z")


def run(args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError(
            f"Network command failed: {args[0]} {args[1]} (exit {result.returncode})."
        )
    return result


def atomic_json(path, data, uid=None):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        if uid is not None:
            os.chown(temporary, uid, -1)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class Network:
    def __init__(self, runtime, uid, command=run, resolver_dir="/etc/resolver"):
        self.runtime, self.uid, self.command = Path(runtime), uid, command
        self.resolver_dir = Path(resolver_dir)
        self.entries = []
        self.dns_resources = {}

    def journal(self):
        atomic_json(self.runtime / "network.json", self.entries)

    def resolvers(self, gateways, port):
        self.resolver_dir.mkdir(mode=0o755, exist_ok=True)
        for g in gateways:
            for domain in g.get("domains", []):
                path = self.resolver_dir / domain
                content = f"# dual-vpn-router uid={self.uid}\nnameserver 127.0.0.1\nport {port}\n"
                original = None
                if path.is_symlink():
                    raise RuntimeError(f"A resolver symlink owns {domain}; it was preserved.")
                if path.exists():
                    if not g.get("replace_resolvers", False):
                        raise RuntimeError(f"An existing resolver owns {domain}; it was preserved.")
                    metadata = path.stat()
                    if metadata.st_size > 65536:
                        raise RuntimeError("Existing resolver is unexpectedly large; preserved.")
                    original = {
                        "content": path.read_text(),
                        "mode": stat.S_IMODE(metadata.st_mode),
                        "uid": metadata.st_uid,
                        "gid": metadata.st_gid,
                    }
                entry = {
                    "kind": "resolver",
                    "path": str(path),
                    "content": content,
                    "owner": g["name"],
                    "original": original,
                }
                self.entries.append(entry)
                self.journal()
                if original is None:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                    with os.fdopen(fd, "w") as stream:
                        stream.write(content)
                else:
                    self.write_resolver(
                        path,
                        content,
                        {"mode": 0o644, "uid": os.getuid(), "gid": os.getgid()},
                    )

    @staticmethod
    def write_resolver(path, content, metadata):
        fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, metadata["mode"])
            os.chown(temporary, metadata["uid"], metadata["gid"])
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def dns_routes(self, gateway, interface, addresses, gateways):
        for address in addresses:
            ip = ipaddress.IPv4Address(address)
            if not any(
                ip in ipaddress.IPv4Network(net)
                for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            ):
                continue
            covered = False
            for candidate in gateways:
                if any(ip in ipaddress.IPv4Network(prefix) for prefix in candidate["routes"]):
                    if candidate["name"] != gateway:
                        raise RuntimeError(
                            "Private DNS answer conflicts with another gateway's resource ownership."
                        )
                    covered = True
            if covered or any(
                e["kind"] == "route"
                and not e["scoped"]
                and e["prefix"] == str(ip) + "/32"
                and e["owner"] == gateway
                for e in self.entries
            ):
                continue
            self.route(str(ip) + "/32", interface, gateway)
            self.dns_resources.setdefault(gateway, set()).add(str(ip))

    def route(self, prefix, interface, gateway, scoped=False):
        prefix = str(ipaddress.IPv4Network(prefix))
        entry = {
            "kind": "route",
            "prefix": prefix,
            "interface": interface,
            "owner": gateway,
            "scoped": scoped,
        }
        self.entries.append(entry)
        self.journal()
        command = self.route_command(entry, "add")
        result = self.command(command, check=False)
        if result.returncode:
            self.entries.remove(entry)
            self.journal()
            raise RuntimeError(f"Route conflict for {prefix}; existing route was preserved.")

    @staticmethod
    def route_command(entry, action):
        net = ipaddress.IPv4Network(entry["prefix"])
        args = ["/sbin/route", "-n", action, "-host" if net.prefixlen == 32 else "-net"]
        if entry["scoped"]:
            args += ["-ifscope", entry["interface"]]
        return args + [
            str(net.network_address) if net.prefixlen == 32 else str(net),
            "-interface",
            entry["interface"],
        ]

    def connect(self, gateway, env):
        interface = env.get("TUNDEV", "")
        if not INTERFACE.fullmatch(interface):
            raise ValueError("OpenConnect did not supply a valid utun interface.")
        address = str(ipaddress.IPv4Address(env["INTERNAL_IP4_ADDRESS"]))
        mtu = max(576, min(9000, int(env.get("INTERNAL_IP4_MTU", "1406"))))
        if self.cleanup(gateway["name"], routes_only=True):
            raise RuntimeError("Previous route cleanup failed; reconnect was stopped.")
        self.command(
            [
                "/sbin/ifconfig",
                interface,
                "inet",
                address,
                address,
                "netmask",
                "255.255.255.255",
                "mtu",
                str(mtu),
                "up",
            ]
        )
        servers = gateway.get("dns_servers") or env.get("INTERNAL_IP4_DNS", "").split()
        servers = list(dict.fromkeys(str(ipaddress.IPv4Address(s)) for s in servers))
        if gateway.get("domains") and not servers:
            raise ValueError("No DNS servers provided for configured private domains.")
        try:
            for prefix in gateway["routes"]:
                self.route(prefix, interface, gateway["name"])
            for address in self.dns_resources.get(gateway["name"], set()):
                self.route(address + "/32", interface, gateway["name"])
            for server in servers:
                self.route(server + "/32", interface, gateway["name"], scoped=True)
        except BaseException:
            self.cleanup(gateway["name"], routes_only=True)
            raise
        advertised = []
        for n in range(min(int(env.get("CISCO_SPLIT_INC", "0")), 4096)):
            base = f"CISCO_SPLIT_INC_{n}_"
            if base + "ADDR" in env and base + "MASK" in env:
                advertised.append(
                    str(
                        ipaddress.IPv4Network(
                            env[base + "ADDR"] + "/" + env[base + "MASK"], strict=False
                        )
                    )
                )
        return {
            "interface": interface,
            "address": address,
            "dns_servers": servers,
            "advertised_routes": advertised,
            "configured_routes": gateway["routes"],
        }

    def cleanup(self, gateway=None, routes_only=False):
        errors = []
        for entry in list(reversed(self.entries)):
            if gateway is not None and entry["owner"] != gateway:
                continue
            if routes_only and entry["kind"] != "route":
                continue
            try:
                if entry["kind"] == "resolver":
                    path = Path(entry["path"])
                    if path.is_symlink():
                        raise RuntimeError(
                            "Resolver became a symlink; original backup was retained."
                        )
                    if not path.exists() and entry.get("original"):
                        raise RuntimeError("Resolver disappeared; original backup was retained.")
                    if path.exists():
                        current = path.read_text()
                        original = entry.get("original")
                        if original is not None and current == original["content"]:
                            pass
                        elif current != entry["content"]:
                            raise RuntimeError(
                                "Resolver content changed; preserved for manual inspection."
                            )
                        elif original is not None:
                            self.write_resolver(path, original["content"], original)
                        else:
                            path.unlink()
                else:
                    query = ["/sbin/route", "-n", "get"]
                    if entry["scoped"]:
                        query += ["-ifscope", entry["interface"]]
                    query.append(str(ipaddress.IPv4Network(entry["prefix"]).network_address))
                    result = self.command(query, check=False)
                    if re.search(
                        r"interface:\s*" + re.escape(entry["interface"]) + r"\b",
                        result.stdout,
                    ):
                        deleted = self.command(self.route_command(entry, "delete"), check=False)
                        if deleted.returncode:
                            raise RuntimeError("Could not remove owned route.")
                self.entries.remove(entry)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                errors.append(str(exc))
        self.journal()
        return errors
