"""Smoke tests for the installed package, without credentials or API calls."""

import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class InstallationTests(unittest.TestCase):
    def test_installed_distribution_exports_the_server_command(self):
        distribution = importlib.metadata.distribution("anchain-data-mcp")
        commands = {
            entry.name: entry.value
            for entry in distribution.entry_points
            if entry.group == "console_scripts"
        }
        self.assertEqual(commands.get("anchain_data"), "mcp_server:main")

    def test_installed_command_runs_outside_checkout_without_api_key(self):
        executable = "anchain_data.exe" if os.name == "nt" else "anchain_data"
        command = Path(sys.executable).parent / executable
        env = os.environ.copy()
        env.pop("ANCHAIN_APIKEY", None)
        env.pop("PYTHONPATH", None)
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [str(command), "--help"], cwd=directory, env=env,
                capture_output=True, text=True, timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--ANCHAIN_APIKEY", result.stdout)
        self.assertIn("--remote", result.stdout)


if __name__ == "__main__":
    unittest.main()
