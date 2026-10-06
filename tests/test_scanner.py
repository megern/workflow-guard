from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from workflow_guard.scanner import WorkflowLoader, scan_paths, scan_text

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples" / "workflows"
SHA = "a" * 40


class ScannerTests(unittest.TestCase):
    def test_risky_fixture_rules_have_precise_source_locations(self):
        report = scan_paths([FIXTURES / "risky.yml"])
        self.assertEqual(report.errors, [])
        self.assertEqual([(f.rule_id, f.line, f.column, f.job) for f in report.findings], [
            ("WG001", 3, 14, None),
            ("WG005", 8, 15, "build"),
            ("WG003", 10, 16, "build"),
            ("WG004", 13, 17, "build"),
            ("WG006", 15, 20, "build"),
        ])
        self.assertEqual(report.to_dict()["summary"], {
            "findings": 5, "by_severity": {"low": 0, "medium": 1, "high": 4}, "errors": 0,
        })

    def test_safe_fixture_does_not_flag_env_local_actions_or_sha(self):
        report = scan_paths([FIXTURES / "safe.yml"])
        self.assertEqual(report.findings, [])
        self.assertEqual(report.errors, [])

    def test_effective_permissions_respect_root_and_job_scopes(self):
        report = scan_paths([FIXTURES / "defaults.yml"])
        self.assertEqual([(f.rule_id, f.job, f.line) for f in report.findings],
                         [("WG002", "inherited", 4)])
        source = (FIXTURES / "defaults.yml").read_text()
        self.assertEqual(scan_text(source.replace("on: push", "on: push\npermissions: read-all")).findings, [])
        job_write = source.replace("permissions: {}", "permissions: write-all")
        self.assertEqual([(f.rule_id, f.job) for f in scan_text(job_write).findings],
                         [("WG002", "inherited"), ("WG001", "explicit")])

    def test_on_stays_string_and_safe_loader_is_not_globally_mutated(self):
        parsed = yaml.load("on: pull_request_target\nflag: true\nword: yes", Loader=WorkflowLoader)
        self.assertEqual(parsed["on"], "pull_request_target")
        self.assertIs(parsed["flag"], True)
        self.assertEqual(parsed["word"], "yes")
        self.assertIn(True, yaml.safe_load("on: push"))

    def test_all_trigger_forms_are_recognized(self):
        source = (FIXTURES / "risky.yml").read_text()
        for trigger in ("pull_request_target", "[push, pull_request_target]",
                        "{pull_request_target: {types: [opened]}}"):
            with self.subTest(trigger=trigger):
                report = scan_text(source.replace("on: pull_request_target", f"on: {trigger}"))
                self.assertIn("WG003", {f.rule_id for f in report.findings})
        unprivileged = scan_text(source.replace("on: pull_request_target", "on: pull_request"))
        self.assertNotIn("WG003", {f.rule_id for f in unprivileged.findings})

    def test_remote_reusable_workflows_and_container_pins(self):
        source = f"""on: push
permissions: {{}}
jobs:
  reusable:
    uses: owner/repo/.github/workflows/build.yml@v1
  local:
    uses: ./.github/workflows/build.yml
  containers:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:latest
      - uses: docker://alpine@sha256:{'b' * 64}
      - uses: owner/repo@{SHA}
      - uses: owner/repo@abc123
"""
        self.assertEqual([(f.rule_id, f.job, f.line) for f in scan_text(source).findings], [
            ("WG005", "reusable", 5), ("WG005", "containers", 11),
            ("WG005", "containers", 14),
        ])

    def test_folded_multiline_expression_cites_original_yaml_line(self):
        source = """on: pull_request
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: >-
          echo '${{
            github.event.issue.title
          }}'
"""
        finding, = scan_text(source).findings
        self.assertEqual((finding.rule_id, finding.line, finding.column), ("WG004", 8, 17))

    def test_secret_echo_is_a_direct_reference_check(self):
        source = """on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.TOKEN }}
        run: |
          echo "$TOKEN"
          # echo '${{ secrets.COMMENT }}'
          printf '%s' '${{ secrets.OTHER }}'
          echo '${{ toJSON(secrets) }}'
"""
        findings = scan_text(source).findings
        self.assertEqual([(f.rule_id, f.line) for f in findings], [("WG006", 13)])

    def test_repeated_expressions_each_retain_their_own_source_line(self):
        source = """on: push
permissions: {}
jobs:
  test:
    steps:
      - run: |
          echo '${{ github.event.issue.title }}'
          echo '${{ github.event.issue.title }}'
          echo '${{ secrets.TOKEN }}'
          echo '${{ secrets.TOKEN }}'
"""
        self.assertEqual([(f.rule_id, f.line) for f in scan_text(source).findings], [
            ("WG004", 7), ("WG004", 8), ("WG006", 9), ("WG006", 10),
        ])

    def test_malformed_duplicate_merge_and_scalar_documents_are_errors(self):
        sources = ["jobs: [", "on: push\non: pull_request\njobs: {}",
                   "jobs: {x: {<<: {permissions: {}}}}", "hello"]
        for source in sources:
            with self.subTest(source=source):
                report = scan_text(source)
                self.assertTrue(report.errors)
                self.assertEqual(report.findings, [])

    def test_tagged_yaml_is_never_constructed_or_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "must-not-exist"
            source = f"""on: push
permissions: {{}}
jobs:
  test:
    steps:
      - run: !!python/object/apply:os.system ['touch {marker}']
"""
            report = scan_text(source)
            self.assertFalse(marker.exists())
            self.assertEqual(report.findings, [])
            self.assertTrue(report.errors)

    def test_directory_scan_is_deterministic_and_deduplicates_identical_paths(self):
        report = scan_paths([FIXTURES, FIXTURES / "safe.yml"])
        self.assertEqual(report.files_scanned, 3)
        self.assertEqual(len(report.findings), 6)
        self.assertEqual(report.errors, [])

    def test_missing_empty_and_oversized_inputs_are_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = scan_paths([root])
            self.assertTrue(report.errors)
            missing = scan_paths([root / "missing.yml"])
            self.assertTrue(missing.errors)
            oversized = root / "huge.yml"
            oversized.write_text("#" * 1_048_577)
            self.assertTrue(scan_paths([oversized]).errors)


class CliTests(unittest.TestCase):
    def invoke(self, *arguments):
        environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        return subprocess.run([sys.executable, "-m", "workflow_guard", *map(str, arguments)],
                              capture_output=True, text=True, env=environment, check=False)

    def test_json_report_and_exit_threshold(self):
        risky = self.invoke(FIXTURES / "risky.yml", "--format", "json")
        self.assertEqual(risky.returncode, 1)
        self.assertEqual(json.loads(risky.stdout)["summary"]["findings"], 5)
        report_only = self.invoke(FIXTURES / "risky.yml", "--fail-on", "none")
        self.assertEqual(report_only.returncode, 0)
        self.assertIn("WG003", report_only.stdout)
        safe = self.invoke(FIXTURES / "safe.yml")
        self.assertEqual(safe.returncode, 0)
        medium = self.invoke(FIXTURES / "defaults.yml", "--fail-on", "medium")
        self.assertEqual(medium.returncode, 1)

    def test_json_output_file_and_errors_cannot_be_suppressed(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_file = Path(temporary) / "reports" / "scan.json"
            command = self.invoke(FIXTURES / "safe.yml", "--json-output", report_file)
            self.assertEqual(command.returncode, 0)
            self.assertEqual(json.loads(report_file.read_text())["files_scanned"], 1)
            bad = self.invoke(Path(temporary) / "missing.yml", "--fail-on", "none", "--format", "json")
            self.assertEqual(bad.returncode, 2)
            self.assertEqual(json.loads(bad.stdout)["summary"]["errors"], 1)

    def test_json_output_cannot_overwrite_workflow_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            input_file = Path(temporary) / "workflow.yml"
            source = (FIXTURES / "safe.yml").read_text()
            input_file.write_text(source)
            command = self.invoke(input_file, "--json-output", input_file)
            self.assertEqual(command.returncode, 2)
            self.assertEqual(input_file.read_text(), source)


if __name__ == "__main__":
    unittest.main()
