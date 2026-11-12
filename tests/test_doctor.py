import contextlib
import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from dual_vpn_router.cli import doctor


class Doctor(unittest.TestCase):
    def check(self, state):
        output = io.StringIO()
        with (
            patch("dual_vpn_router.cli.status", return_value={"state": state, "gateways": {}}),
            patch("dual_vpn_router.cli.platform.system", return_value="Darwin"),
            patch("dual_vpn_router.cli.shutil.which", return_value="/synthetic/openconnect"),
            patch("dual_vpn_router.cli.subprocess.run", return_value=SimpleNamespace(returncode=1)),
            contextlib.redirect_stdout(output),
        ):
            code = doctor(SimpleNamespace(probe=False, snapshot=None), {"gateways": []})
        return code, json.loads(output.getvalue())

    def test_running_controller_does_not_need_callers_sudo_timestamp(self):
        code, _ = self.check("running")
        self.assertEqual(code, 0)

    def test_stopped_controller_reports_missing_startup_authorization(self):
        code, _ = self.check("stopped")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
