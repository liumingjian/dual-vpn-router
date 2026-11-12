import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from .auth import authenticate, presented_key
from .config import DEFAULT_CONFIG, load, save
from .network import atomic_json
from .runtime import Daemon, hook, recover, request, runtime_dir
from .startup import detach_output, launch_worker, redact


def executable():
    # Module execution also supports installed console entry points and hook subprocesses.
    return str(Path(__file__).with_name("runner.py"))


def root_command(*args):
    return ["sudo", "-n", sys.executable, executable(), *args]


def sudo_validate():
    if subprocess.run(["sudo", "-v"]).returncode:
        raise RuntimeError("Administrator authorization was not granted.")


def status(uid=None):
    path = runtime_dir(os.getuid() if uid is None else uid) / "status.json"
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return {"state": "stopped", "gateways": {}}
    if data.get("state") not in ("stopped", "error"):
        try:
            os.kill(data["pid"], 0)
        except ProcessLookupError:
            data.update(
                state="interrupted",
                error="The controller stopped unexpectedly; run dvr down for recovery.",
            )
        except PermissionError:
            pass
    return data


def mapping(values):
    result = {}
    for value in values:
        name, sep, field = value.partition("=")
        if not sep or not field:
            raise ValueError("Use NAME=VALUE for gateway options.")
        result.setdefault(name, []).append(field)
    return result


def init(args):
    gateways = mapping(args.gateway)
    routes, domains, usernames = (
        mapping(args.route),
        mapping(args.domain),
        mapping(args.username),
    )
    tcp, http = mapping(args.tcp), mapping(args.http)
    if not gateways:
        if not sys.stdin.isatty():
            raise ValueError("Use --gateway, --route and --domain, or run init in a terminal.")
        for name in ("a", "b"):
            gateways[name] = [input(f"Gateway {name} HTTPS URL: ").strip()]
            routes[name] = (
                input(f"Gateway {name} resource CIDRs (comma separated): ").strip().split(",")
            )
            domains[name] = [
                d.strip().lower()
                for d in input(
                    f"Gateway {name} private DNS domains (comma separated, may be empty): "
                ).split(",")
                if d.strip()
            ]
            usernames[name] = [input(f"Gateway {name} username (may be empty): ").strip()]
    if any(
        name not in gateways
        for source in (routes, domains, usernames, tcp, http)
        for name in source
    ):
        raise ValueError("An option refers to an undefined gateway.")
    config = {"gateways": []}
    for name, urls in gateways.items():
        if len(urls) != 1 or len(usernames.get(name, [])) > 1:
            raise ValueError("Specify one URL and username per gateway.")
        probes = []
        for address in tcp.get(name, []):
            host, _, port = address.rpartition(":")
            probes.append({"kind": "tcp", "host": host, "port": int(port)})
        probes += [{"kind": "http", "url": url} for url in http.get(name, [])]
        config["gateways"].append(
            {
                "name": name,
                "url": urls[0],
                "routes": routes.get(name, []),
                "domains": domains.get(name, []),
                "username": usernames.get(name, [""])[0],
                "trust": "presented" if args.trust_presented else "system",
                "keychain": True,
                "probes": probes,
            }
        )
    save(args.config, config)
    print(f"Created {args.config}. No password was requested or stored.")


def snapshot(path):
    data = {
        "timestamp": time.time(),
        "services": subprocess.run(
            ["/usr/sbin/scutil", "--nc", "list"], capture_output=True, text=True
        ).stdout,
        "routes": subprocess.run(
            ["/usr/sbin/netstat", "-rn", "-f", "inet"], capture_output=True, text=True
        ).stdout,
        "dns": subprocess.run(["/usr/sbin/scutil", "--dns"], capture_output=True, text=True).stdout,
    }
    data["resolver_files"] = {
        str(resolver): {"content": resolver.read_text(), "mode": resolver.stat().st_mode & 0o777}
        for resolver in Path("/etc/resolver").glob("*")
        if resolver.is_file() and not resolver.is_symlink() and resolver.stat().st_size < 65536
    }
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    save_snapshot = path.with_name(path.stem + f"-{time.time_ns()}" + path.suffix)
    atomic_json(save_snapshot, data)
    return save_snapshot


def connected_anyconnect():
    import re

    output = subprocess.run(
        ["/usr/sbin/scutil", "--nc", "list"], capture_output=True, text=True
    ).stdout
    result = []
    for line in output.splitlines():
        match = re.search(r"\(Connected\)\s+([A-F0-9-]{36}).*com\.cisco\.anyconnect", line)
        if match:
            result.append(match[1])
    return result


def up(args, config):
    binary = shutil.which("openconnect")
    if not binary:
        raise RuntimeError("Install OpenConnect first: brew install openconnect")
    current = status()
    if current["state"] == "interrupted":
        raise RuntimeError(current["error"])
    active = current["state"] in ("running", "starting")
    if active:
        targets = [
            g
            for g in config["gateways"]
            if current["gateways"].get(g["name"], {}).get("state") == "authentication_required"
        ]
        if not targets:
            print(json.dumps(current, indent=2))
            return
    else:
        targets = config["gateways"]
    previous = connected_anyconnect() if not active else []
    if previous and not args.replace_anyconnect:
        raise RuntimeError(
            "AnyConnect is connected. Use up --replace-anyconnect to replace it during validation."
        )
    sudo_validate()
    baseline = snapshot(Path.home() / ".local/state/dual-vpn-router/baseline.json")
    print(f"Network snapshot: {baseline}")
    sessions = {g["name"]: authenticate(binary, g) for g in targets}
    sudo_validate()
    payload = {
        "uid": os.getuid(),
        "config": config,
        "sessions": sessions,
        "binary": binary,
        "previous_services": previous,
    }
    if active:
        result = subprocess.run(
            root_command("_resume", "--uid", str(os.getuid())),
            input=json.dumps(payload),
            text=True,
        )
        if result.returncode:
            raise RuntimeError("Could not resume authentication-required sessions.")
    else:
        process = subprocess.Popen(
            root_command("_launch"),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        process.stdin.write(json.dumps(payload).encode())
        process.stdin.close()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            observed = status()
            if observed.get("started", 0) > payload.get("requested", baseline.stat().st_mtime):
                if observed["state"] == "error":
                    raise RuntimeError(observed.get("error", "Startup failed."))
                if observed["state"] == "running":
                    break
            if process.poll() not in (None, 0):
                detail = process.stderr.read(8192).decode(errors="replace").strip()
                detail = redact(detail, sessions)
                process.stderr.close()
                raise RuntimeError(
                    "Controller could not start: "
                    + (detail or f"launcher exit {process.returncode}")
                )
            time.sleep(0.2)
        else:
            raise RuntimeError(
                "Controller startup timed out. Inspect dvr status, then use dvr down if needed."
            )
        code = process.wait(timeout=5)
        detail = process.stderr.read(8192).decode(errors="replace").strip()
        process.stderr.close()
        if code:
            raise RuntimeError("Controller launcher failed: " + redact(detail, sessions))
    print(
        "Controller started. Run dvr status to check each tunnel and dvr doctor --probe to verify resources."
    )


def down(args):
    sudo_validate()
    result = subprocess.run(root_command("_down", "--uid", str(os.getuid())))
    if result.returncode:
        raise RuntimeError("Shutdown or recovery failed; inspect dvr status.")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        current = status()
        if current["state"] in ("stopped", "error"):
            print(json.dumps(current, indent=2))
            if current.get("error"):
                raise RuntimeError("Shutdown needs attention; see the status error.")
            return
        time.sleep(0.2)
    raise RuntimeError("Shutdown is still pending; inspect dvr status.")


def probe_resource(probe):
    if probe["kind"] == "tcp":
        with socket.create_connection((probe["host"], int(probe["port"])), timeout=5):
            return {"ok": True, "kind": "tcp"}
    # Use the system resolver and bypass application/environment proxies.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(
            urllib.request.Request(probe["url"], method="HEAD"), timeout=8
        ) as response:
            return {
                "ok": 200 <= response.status < 400,
                "kind": "http",
                "http_status": response.status,
            }
    except urllib.error.HTTPError as exc:
        return {"ok": False, "kind": "http", "http_status": exc.code}


def doctor(args, config):
    checks = []
    controller = status()

    def add(name, ok, detail):
        checks.append({"check": name, "ok": ok, "detail": detail})

    add("platform", platform.system() == "Darwin", platform.system())
    binary = shutil.which("openconnect")
    add("openconnect", bool(binary), binary or "Install with brew install openconnect")
    authorized = controller["state"] in ("running", "starting")
    cached = subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0
    add(
        "administrator",
        authorized or cached,
        "The running controller already holds network-management privileges."
        if authorized
        else "Starting network management needs local sudo authorization; doctor does not request it.",
    )
    for gateway in config["gateways"]:
        name = gateway["name"]
        for domain in gateway.get("domains", []):
            path = Path("/etc/resolver") / domain
            existing = path.exists()
            owned = existing and path.read_text().startswith(
                f"# dual-vpn-router uid={os.getuid()}\n"
            )
            add(
                name + ":resolver:" + domain,
                not existing or owned or gateway.get("replace_resolvers", False),
                "owned"
                if owned
                else "will back up and restore existing resolver"
                if existing and gateway.get("replace_resolvers", False)
                else "existing conflict"
                if existing
                else "available",
            )
        if args.probe:
            try:
                if gateway.get("trust", "system") == "presented":
                    presented_key(gateway["url"])
                else:
                    import ssl
                    from urllib.parse import urlsplit

                    url = urlsplit(gateway["url"])
                    with socket.create_connection(
                        (url.hostname, url.port or 443), timeout=5
                    ) as sock:
                        with ssl.create_default_context().wrap_socket(
                            sock, server_hostname=url.hostname
                        ):
                            pass
                add(
                    name + ":gateway_tls",
                    True,
                    "Handshake succeeded using configured trust policy; not authenticated.",
                )
            except (OSError, subprocess.SubprocessError) as exc:
                add(name + ":gateway_tls", False, type(exc).__name__)
            for index, probe in enumerate(gateway.get("probes", [])):
                try:
                    result = probe_resource(probe)
                    add(f"{name}:resource:{index}", result["ok"], result)
                except (OSError, urllib.error.URLError) as exc:
                    add(f"{name}:resource:{index}", False, type(exc).__name__)
            if not gateway.get("probes"):
                add(
                    name + ":resources",
                    False,
                    "No representative service probe is configured; application access remains unverified.",
                )
    result = {"checks": checks, "controller": controller}
    if args.snapshot:
        result["snapshot"] = str(snapshot(args.snapshot))
    print(json.dumps(result, indent=2))
    return 0 if all(check["ok"] for check in checks) else 1


def parser():
    p = argparse.ArgumentParser(
        description="Coordinate macOS OpenConnect tunnels, routes and split DNS."
    )
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    sub = p.add_subparsers(dest="command", required=True, metavar="{init,up,down,status,doctor}")
    init_p = sub.add_parser("init", help="Create non-secret local configuration")
    for name in ("gateway", "route", "domain", "username", "tcp", "http"):
        init_p.add_argument("--" + name, action="append", default=[], metavar="NAME=VALUE")
    init_p.add_argument("--trust-presented", action="store_true")
    up_p = sub.add_parser("up", help="Authenticate locally and start background management")
    up_p.add_argument("--replace-anyconnect", action="store_true")
    sub.add_parser("down", help="Stop managed sessions and recover owned network state")
    sub.add_parser("status", help="Report controller and tunnel states")
    doctor_p = sub.add_parser(
        "doctor",
        help="Read-only diagnostics; never authenticates or changes network settings",
    )
    doctor_p.add_argument(
        "--probe", action="store_true", help="Test gateway TLS and configured resources"
    )
    doctor_p.add_argument("--snapshot", type=Path)
    sub.add_parser("_launch", help=argparse.SUPPRESS)
    sub.add_parser("_daemon", help=argparse.SUPPRESS)
    for name in ("_resume", "_down"):
        sub.add_parser(name, help=argparse.SUPPRESS).add_argument("--uid", type=int, required=True)
    hook_p = sub.add_parser("_hook", help=argparse.SUPPRESS)
    hook_p.add_argument("--socket", required=True)
    hook_p.add_argument("--gateway", required=True)
    sub._choices_actions = [
        action for action in sub._choices_actions if not action.dest.startswith("_")
    ]
    return p


def main():
    args = parser().parse_args()
    try:
        if args.command == "init":
            return init(args)
        if args.command == "status":
            print(json.dumps(status(), indent=2))
            return
        if platform.system() != "Darwin":
            raise RuntimeError("Network management currently supports macOS only.")
        if args.command == "_hook":
            return hook(args.socket, args.gateway)
        if args.command.startswith("_"):
            if os.geteuid() != 0:
                raise RuntimeError("This internal command requires sudo.")
            if args.command == "_launch":
                launch_worker(json.load(sys.stdin), executable())
                # The detached worker is deliberately reparented; do not wait for its lifetime.
                os._exit(0)
            if args.command == "_daemon":
                daemon = Daemon(json.load(sys.stdin), executable())
                print(json.dumps({"ready": True}), flush=True)
                detach_output()
                return sys.exit(daemon.run())
            if args.uid <= 0 or int(os.environ.get("SUDO_UID", "-1")) != args.uid:
                raise RuntimeError("Control UID must match the invoking sudo user.")
            path = runtime_dir(args.uid) / "control.sock"
            if args.command == "_resume":
                payload = json.load(sys.stdin)
                request(path, {"op": "resume", "sessions": payload["sessions"]})
            else:
                try:
                    request(path, {"op": "down"})
                except (FileNotFoundError, ConnectionRefusedError):
                    recover(args.uid)
            return
        if args.command == "down":
            return down(args)
        config = load(args.config)
        if args.command == "up":
            return up(args, config)
        return sys.exit(doctor(args, config))
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"dvr: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
