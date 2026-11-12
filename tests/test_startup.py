import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dual_vpn_router import cli
from dual_vpn_router.config import load
from dual_vpn_router.startup import launch_worker

ROOT = Path(__file__).resolve().parents[1]


class Startup(unittest.TestCase):
    def test_authenticated_controller_keeps_sudo_timestamp_context(self):
        """Model tty-scoped sudo credentials using actual process session IDs."""
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            timestamp = directory / "sudo-timestamp"
            state = directory / "status.json"
            sudo = directory / "sudo"
            sudo.write_text(
                "#!"
                + sys.executable
                + "\n"
                + """import os,sys
from pathlib import Path
timestamp=Path(TIMESTAMP)
if sys.argv[1] == '-v':
    timestamp.write_text(str(os.getsid(0)))
    sys.exit(0)
if timestamp.read_text() != str(os.getsid(0)):
    print('sudo: a password is required', file=sys.stderr)
    sys.exit(1)
os.execv(sys.argv[2],sys.argv[2:])
""".replace("TIMESTAMP", repr(str(timestamp)))
            )
            sudo.chmod(0o700)
            worker = directory / "worker.py"
            worker.write_text(
                """import json,os,sys,time
from pathlib import Path
payload=json.load(sys.stdin)
Path(STATE).write_text(json.dumps({'state':'running','started':time.time(),'gateways':{}}))
""".replace("STATE", repr(str(state)))
            )
            baseline = directory / "baseline.json"
            baseline.write_text("{}")

            def status():
                return (
                    json.loads(state.read_text())
                    if state.exists()
                    else {"state": "stopped", "gateways": {}}
                )

            with (
                patch.dict(os.environ, {"PATH": str(directory) + os.pathsep + os.environ["PATH"]}),
                patch.object(
                    cli, "root_command", return_value=[str(sudo), "-n", sys.executable, str(worker)]
                ),
                patch.object(cli, "status", side_effect=status),
                patch.object(cli, "snapshot", return_value=baseline),
                patch.object(cli, "authenticate", return_value={"COOKIE": "synthetic-cookie"}),
                patch.object(cli, "connected_anyconnect", return_value=[]),
                patch.object(cli.shutil, "which", return_value="/synthetic/openconnect"),
            ):
                cli.up(
                    SimpleNamespace(replace_anyconnect=False), load(ROOT / "examples/config.json")
                )
            self.assertEqual(status()["state"], "running")

    def test_worker_detaches_only_after_launcher_context(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = Path(directory) / "worker.py"
            worker.write_text("""import json,os,sys,time
payload=json.load(sys.stdin)
assert os.getsid(0) != payload['parent_sid']
assert payload['sessions']['b']['COOKIE'] == 'synthetic-cookie'
print(json.dumps({'ready':True}),flush=True)
time.sleep(0.3)
""")
            child = launch_worker(
                {"parent_sid": os.getsid(0), "sessions": {"b": {"COOKIE": "synthetic-cookie"}}},
                str(worker),
            )
            self.assertEqual(child.wait(timeout=3), 0)

    def test_worker_initialization_error_is_reported_without_cookie(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = Path(directory) / "worker.py"
            worker.write_text("""import json,sys
payload=json.load(sys.stdin)
print('initialization failed: ' + payload['sessions']['b']['COOKIE'],file=sys.stderr)
sys.exit(1)
""")
            with self.assertRaisesRegex(RuntimeError, "initialization failed: <REDACTED>") as error:
                launch_worker({"sessions": {"b": {"COOKIE": "synthetic-cookie"}}}, str(worker))
            self.assertNotIn("synthetic-cookie", str(error.exception))


if __name__ == "__main__":
    unittest.main()
