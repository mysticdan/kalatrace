"""CLI regression tests: run with `make test` at the repository root."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


CLI = Path(os.environ.get(
    "KALATRACE_CLI",
    Path(__file__).resolve().parents[1] / "userspace/build/debug/kalatracectl",
)).resolve()


class CliRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cwd = Path(self.tmp.name)

    def event(self, **overrides):
        data = {
            "timestamp_ns": "18446744073709551615",
            "event_type": "exec",
            "pid": 123,
            "ppid": 10,
            "uid": 1000,
            "gid": 1000,
            "mode": 0,
            "flags": 0,
            "comm": "bash",
            "parent_comm": "nginx",
            "exe_path": "/bin/bash",
            "path": "/tmp/file",
        }
        data.update(overrides)
        return data

    def invoke(self, content, command="test-event"):
        input_path = self.cwd / "event.json"
        input_path.write_bytes(content)
        return subprocess.run(
            [str(CLI), command, str(input_path)], cwd=self.cwd,
            capture_output=True, text=True, check=False,
        )

    def test_output_escapes_strings_and_preserves_u64(self):
        tricky_path = '/tmp/"quote"\\backslash\nnewline\t\x01control'
        event = self.event(path=tricky_path, exe_path='/bin/"bash"\\x')
        result = self.invoke(json.dumps(event).encode())
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = (self.cwd / "alerts.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 1)
        alert = json.loads(lines[0])
        self.assertEqual(alert["path"], tricky_path)
        self.assertEqual(alert["exe_path"], event["exe_path"])
        self.assertEqual(alert["timestamp_ns"], 18446744073709551615)
        self.assertIn('\\u0001', lines[0])

    @unittest.skipUnless(Path('/dev/full').exists(), 'Linux /dev/full required')
    def test_write_failure_is_not_reported_as_success(self):
        (self.cwd / 'alerts.jsonl').symlink_to('/dev/full')
        result = self.invoke(json.dumps(self.event()).encode())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Failed to write alert', result.stderr)
        self.assertNotIn('Alert generated and written', result.stdout)

    def test_trailing_garbage_is_rejected(self):
        content = json.dumps(self.event()).encode() + b'\nTHIS_IS_NOT_JSON'
        result = self.invoke(content)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.cwd / 'alerts.jsonl').exists())

    def test_trailing_whitespace_is_allowed(self):
        content = b' \n' + json.dumps(self.event()).encode() + b'\n \t'
        result = self.invoke(content)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_embedded_nul_is_rejected(self):
        content = json.dumps(self.event()).encode() + b'\x00GARBAGE'
        result = self.invoke(content)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.cwd / 'alerts.jsonl').exists())

    def test_oversize_input_is_rejected(self):
        content = json.dumps(self.event()).encode() + b' ' * 1024 + b'GARBAGE'
        result = self.invoke(content)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.cwd / 'alerts.jsonl').exists())

    def test_unknown_command_is_rejected(self):
        result = self.invoke(json.dumps(self.event()).encode(), 'unrecognized-command')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unknown command', result.stderr)
        self.assertFalse((self.cwd / 'alerts.jsonl').exists())


if __name__ == '__main__':
    unittest.main()
