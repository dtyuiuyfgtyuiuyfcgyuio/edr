"""Exercise the real read-only triage CLI with isolated synthetic files."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


AGENT = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else None


class TriageCliTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(AGENT, "pass the built edr executable")
        self.fixture = tempfile.TemporaryDirectory(prefix="edr_triage_cli_")
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name).resolve()
        self.config_path = self.root / "config.json"
        self.pack = self.root / "pack"
        self.rules = self.root / "rules.json"
        self.rules.write_text('{"rules":[{"id":"fixture"}]}', encoding="utf-8")
        for name in ("alerts", "incidents", "audit"):
            (self.root / (name + ".jsonl")).write_text(
                '{"id":"fixture","value":1}\n', encoding="utf-8")
        config = {
            "rules_path": str(self.rules),
            "alerts_path": str(self.root / "alerts.jsonl"),
            "correlation": {"enable": False, "incident_path": str(self.root / "incidents.jsonl")},
            "response_channel": {"enable": False, "audit_path": str(self.root / "audit.jsonl")},
            "reporter": {"enable": False, "api_key": "cli-fixture-secret"},
            "auto_response": {"enable": False},
            "future_option": ["future-fixture-secret"],
        }
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        self.source_bytes = {p.name: p.read_bytes() for p in self.root.iterdir()}

    def run_cli(self, *extra, with_out=True):
        args = [str(AGENT), "--config", str(self.config_path), "--triage"]
        if with_out:
            args += ["--out", str(self.pack)]
        return subprocess.run(args + list(extra), cwd=self.root, capture_output=True,
                              encoding="utf-8", errors="replace", timeout=30)

    def test_configured_ledgers_redaction_and_export_hashes(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((self.pack / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], 2)
        self.assertTrue(manifest["config_redacted"])
        self.assertEqual(len(manifest["files"]), 5)
        self.assertTrue(all(not entry["missing"] for entry in manifest["files"]))
        redacted = (self.pack / "config.json").read_text(encoding="utf-8")
        self.assertNotIn("cli-fixture-secret", redacted)
        self.assertNotIn("future-fixture-secret", redacted)
        for entry in manifest["files"]:
            data = (self.pack / entry["name"]).read_bytes()
            self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(entry["bytes"], len(data))
            if entry["name"].endswith(".jsonl"):
                self.assertEqual(json.loads(data), {"id": "fixture", "value": 1})
        for name, data in self.source_bytes.items():
            self.assertEqual((self.root / name).read_bytes(), data)

    def test_rules_cli_override(self):
        override = self.root / "override.json"
        data = b'{"rules":[]}'
        override.write_bytes(data)
        result = self.run_cli("--rules", str(override))
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads((self.pack / "rules_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["count"], 0)
        self.assertEqual(summary["sha256"], hashlib.sha256(data).hexdigest())

    def test_existing_pack_is_preserved(self):
        self.assertEqual(self.run_cli().returncode, 0)
        before = {p.name: p.read_bytes() for p in self.pack.iterdir()}
        self.assertNotEqual(self.run_cli().returncode, 0)
        self.assertEqual({p.name: p.read_bytes() for p in self.pack.iterdir()}, before)

    def test_invalid_or_missing_config_does_not_export(self):
        self.config_path.write_text('{"reporter":{"api_key":"secret-invalid"', encoding="utf-8")
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("secret-invalid", result.stdout + result.stderr)
        self.assertFalse(self.pack.exists())
        self.config_path.unlink()
        self.assertNotEqual(self.run_cli().returncode, 0)
        self.assertFalse(self.pack.exists())

    def test_missing_output_and_conflicting_actions_rejected(self):
        self.assertNotEqual(self.run_cli(with_out=False).returncode, 0)
        self.assertNotEqual(self.run_cli("--sysinfo").returncode, 0)
        self.assertFalse(self.pack.exists())


if __name__ == "__main__":
    unittest.main()
